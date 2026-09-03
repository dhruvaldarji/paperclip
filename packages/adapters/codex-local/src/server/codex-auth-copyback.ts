import { constants as fsConstants } from "node:fs";
import { lstat, mkdir, open, rename, rm } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import {
  assertNoSymlinkInManagedCredentialPath,
  ManagedCredentialHomeRejectedError,
  resolveManagedCredentialHomeBoundary,
} from "@paperclipai/adapter-utils";
import { withDirectoryMergeLock } from "@paperclipai/adapter-utils/workspace-restore-merge";
import {
  isCodexAuthCacheEnabled,
  readSubscriptionAccountId,
  writeCodexAuthCacheEntry,
} from "./codex-auth-cache.js";
import { USE_SOURCE_EXIT, decideCodexAuthMerge } from "./codex-auth-merge-decision.js";

// The outbound copy-back reuses the exact same direction-agnostic decision
// predicate the inbound restore runs, through the shared `decideCodexAuthMerge`
// entry point. The predicate answers one question — "should the caller replace
// `destination` with `source`?" — purely by argument order (first = source,
// second = destination). For the copy-back the sandbox credential is the
// `source` and the shared host credential is the `destination`, so exit 10 (use
// source) means "install the sandbox copy onto the host" and exit 20 (keep
// destination) means "leave the host copy untouched". The predicate only ever
// reads the two files and exits with a code; it never prints token bytes.

/** Outcome of a copy-back attempt. No token material is ever surfaced. */
export type CopyBackCodexAuthOutcome = "copied" | "kept-host";

export interface CopyBackCodexAuthInput {
  /**
   * Reads the sandbox `auth.json` bytes back from the (about-to-be-destroyed)
   * sandbox. In production this is bound to the managed-runtime restore
   * context's `readFile` for `${assetDir}/auth.json`.
   */
  readSandboxAuth: () => Promise<Buffer>;
  /**
   * Absolute path of the shared host credential to (maybe) overwrite — the
   * symlink *source* the managed Codex homes point their `auth.json` at, never
   * an in-sandbox or per-agent symlink. This path was validated once by a
   * caller before this function ran; that earlier check is not proof enough
   * on its own — see the re-verification note on {@link copyBackCodexAuth}.
   */
  hostAuthPath: string;
  /**
   * The company that owns `hostAuthPath`. When present, this function
   * independently re-resolves the company's containment boundary right
   * before the write, so it does not trust `hostAuthPath` on the strength of
   * an earlier caller's check alone. Omit only for a target this function's
   * caller already guards through a different, unmanaged boundary (for
   * example a run-scoped proof home): the re-verification is skipped, not
   * defaulted to a guess.
   */
  companyId?: string;
  /** Non-leaking progress sink: receives decision/outcome lines only. */
  log: (line: string) => void | Promise<void>;
  /**
   * Resolves and ensures the per-identity cache slot path for a sandbox
   * `account_id`. When this is provided AND the cache off-switch is on, the
   * copy-back also writes the fresher, usable subscription credential into its
   * per-identity cache slot as a second, additive write, keyed by the real
   * `account_id`. This is independent of the host default overwrite: it can
   * write a cache slot for a different identity than the host holds (matrix rows
   * 1b, 3), and it never touches the host default store. When absent, no cache
   * write happens.
   */
  resolveCacheEntryPath?: (accountId: string) => Promise<string>;
  /** Environment for the cache off-switch read. Defaults to `process.env`. */
  env?: NodeJS.ProcessEnv;
}

/**
 * Thrown only when the pinned host directory's identity (its device and
 * inode) no longer matches a fresh, no-follow read of the same path taken
 * immediately before a write. This means something removed and recreated
 * the directory since it was pinned — a directory-replacement race, not a
 * benign "target is outside the managed tree" outcome. A caller must not
 * catch this as benign; it must stay fail-loud like every other unexpected
 * write error.
 */
export class CopyBackDirectoryReplacedError extends Error {
  constructor() {
    super(
      "Codex auth copy-back: the host directory changed identity between the last check and the write.",
    );
    this.name = "CopyBackDirectoryReplacedError";
  }
}

/**
 * Compares the pinned directory descriptor's identity to a fresh, no-follow
 * read of the plain directory path. A Linux write addresses the pinned
 * descriptor itself (through its `/proc/self/fd` alias), so a later swap of
 * the plain path text cannot redirect it; a non-Linux write still addresses
 * that plain path text directly, so it needs this last check. A directory
 * removed and recreated under the same name carries a new device/inode pair
 * even though it is a plain directory, not a symbolic link — a check for
 * "not a symbolic link" alone cannot see that swap, so this call compares
 * identity instead. Call this immediately before each write that follows,
 * with no other `await` in between.
 */
async function assertPinnedDirectoryStillLive(pinnedDir: FileHandle, plainDirPath: string): Promise<void> {
  const [pinnedStat, liveStat] = await Promise.all([pinnedDir.stat(), lstat(plainDirPath)]);
  if (pinnedStat.dev !== liveStat.dev || pinnedStat.ino !== liveStat.ino) {
    throw new CopyBackDirectoryReplacedError();
  }
}

/**
 * Guards, locks, and atomically installs a strictly-newer sandbox Codex
 * `auth.json` onto the shared host credential at teardown.
 *
 * Sequence, all under `withDirectoryMergeLock` on the host target's directory
 * so a concurrent inbound restore or another copy-back can't interleave:
 *   1. Read the sandbox credential bytes. A genuinely absent sandbox
 *      `auth.json` (ENOENT) means there is simply nothing to copy back, so it
 *      resolves to `kept-host` (benign no-op, host untouched); every other read
 *      error stays fail-loud.
 *   2. When the caller passes `companyId`, re-verify `hostAuthPath`'s
 *      directory right before the write. A caller validates `hostAuthPath`
 *      before it calls this function, but time passes between that check
 *      and this write — the sandbox read above and the directory-lock wait
 *      both await. A mutable ancestor directory can be rebound to a symbolic
 *      link in that window, so this function re-resolves the company
 *      boundary and re-walks every existing path segment with a no-follow
 *      `lstat` immediately before it creates anything. A caller that omits
 *      `companyId` guards its target through a different, unmanaged
 *      boundary, so this step is skipped.
 *   3. Inside the lock, re-verify a THIRD time against the real path
 *      `withDirectoryMergeLock` itself just resolved (`fs.realpath` on
 *      `hostDir`, taken at lock-acquisition time). Immediately after — with
 *      no further `await` in between — open that real directory with
 *      `O_DIRECTORY | O_NOFOLLOW` and pin it behind the returned file
 *      descriptor, on every platform. This single open call is itself a
 *      fourth, atomic re-check: it fails outright instead of opening a
 *      symbolic link, so a swap in the gap the third check cannot see
 *      (between that check returning and this open running) is still
 *      caught. On Linux, every write below then resolves through this
 *      descriptor's `/proc/self/fd/<fd>` alias, never through the plain
 *      directory path string again, so a LATER swap of that string cannot
 *      redirect a write the way it could when a write only ever re-used a
 *      path already re-walked from the root. `/proc` does not exist on a
 *      non-Linux platform, so there the writes below instead address the
 *      plain `hostDir` text — but immediately before each of those writes,
 *      with no other `await` in between, the pinned descriptor's identity
 *      (device and inode) is compared against a fresh, no-follow read of
 *      that same plain text. A directory removed and recreated under the
 *      same name is still caught this way even though it is a plain
 *      directory, not a symbolic link, and so cannot be caught by a
 *      symbolic-link-only check. Node.js exposes no `openat` or `renameat`,
 *      so this identity check — immediately before the write it guards —
 *      is the strongest containment the standard library supports without
 *      a Linux-only descriptor pin.
 *   4. Stage the bytes to a `0600` temp file inside the pinned directory
 *      (same filesystem as the host target, which doubles as the predicate
 *      `source`). The open uses `O_EXCL` so it fails instead of following or
 *      overwriting an existing entry, and `O_NOFOLLOW` so it refuses outright
 *      if the temp name is (or became) a symbolic link.
 *   5. Run the newer-wins decision predicate (`source` = sandbox temp,
 *      `destination` = host). Exit 10 → adopt the sandbox copy; exit 20 →
 *      keep the host copy.
 *   6. On exit 10, `rename` the staged temp over the host target, both
 *      addressed through the pinned directory's descriptor alias. `rename`
 *      never follows a destination symbolic link — it replaces the link
 *      entry itself — so even a `hostAuthPath` swapped to a symbolic link in
 *      this window is overwritten in place, never written through. This is
 *      an atomic same-directory swap that preserves mode `0600`. On exit 20,
 *      discard the temp file.
 * The staged temp is always removed (rename consumes it on the copy path; the
 * finally cleans it up otherwise), so a failure never leaves a partial file.
 * Never logs token bytes — only the decision outcome.
 *
 * The decision predicate (step 5) still reads its two files by plain path,
 * not through the pinned descriptor: it runs in a separate `node` child
 * process, and a file descriptor pinned in this process is not addressable
 * from that child's own `/proc/self/fd`. That read is comparison-only — it
 * can at most skew which side the predicate picks, never place attacker
 * bytes anywhere — so the descriptor pin is reserved for the two operations
 * that actually write: the temp-file create in step 4 and the `rename` in
 * step 6.
 */
export async function copyBackCodexAuth(input: CopyBackCodexAuthInput): Promise<CopyBackCodexAuthOutcome> {
  const { readSandboxAuth, hostAuthPath, companyId, log, resolveCacheEntryPath, env } = input;

  // Read first (outside the lock) — a read never mutates the host, so there is
  // nothing to serialize yet. A genuinely absent sandbox `auth.json` (ENOENT —
  // e.g. Codex removed it mid-run, or a non-provisioned edge) is a "nothing to
  // copy back" no-op, not a teardown failure: return `kept-host` and log the
  // benign outcome. Every other read error stays fail-loud so a real read fault
  // is never silently mistaken for "nothing to copy back".
  let sandboxAuthBytes: Buffer;
  try {
    sandboxAuthBytes = await readSandboxAuth();
  } catch (error) {
    if ((error as NodeJS.ErrnoException | null)?.code === "ENOENT") {
      await log(
        "[paperclip] Codex auth copy-back: no sandbox credential to copy back (absent auth.json); host credential kept.",
      );
      return "kept-host";
    }
    throw error;
  }

  const hostDir = path.dirname(hostAuthPath);
  const hostAuthFileName = path.basename(hostAuthPath);

  const skippedOutsideTreeLog =
    "[paperclip] Codex auth copy-back: skipped (the configured Codex home is outside the managed directory tree).";

  // Re-verify right before the write. Do not trust `hostAuthPath` on the
  // strength of a caller's earlier check alone — re-resolve the boundary and
  // re-walk the path with a no-follow `lstat` here, as close to the `mkdir`
  // below as possible. Only a containment rejection is a benign "outside the
  // managed tree" outcome; every other error stays fail-loud, matching the
  // sandbox-read handling above. A caller that omits `companyId` guards its
  // target through a different, unmanaged boundary, so there is no company
  // containment to re-check here.
  let boundary: string | undefined;
  if (companyId) {
    try {
      boundary = await resolveManagedCredentialHomeBoundary({ env, companyId });
      await assertNoSymlinkInManagedCredentialPath(boundary, hostDir);
    } catch (error) {
      if (!(error instanceof ManagedCredentialHomeRejectedError)) {
        throw error;
      }
      await log(skippedOutsideTreeLog);
      return "kept-host";
    }
  }

  await mkdir(hostDir, { recursive: true });
  const hostOutcome = await withDirectoryMergeLock(
    hostDir,
    async (canonicalHostDir) => {
      // `withDirectoryMergeLock` resolved `hostDir`'s real path to compute
      // the lock key, at the instant the lock was acquired. Re-verify
      // against that fresh resolution — not the literal `hostDir` above —
      // with no `await` in between, and use it for every write below. This
      // catches a symbolic-link swap that happened during the `mkdir` call
      // or the lock-acquisition wait, the gap the check above cannot see.
      if (boundary) {
        try {
          await assertNoSymlinkInManagedCredentialPath(boundary, canonicalHostDir);
        } catch (error) {
          if (!(error instanceof ManagedCredentialHomeRejectedError)) {
            throw error;
          }
          await log(skippedOutsideTreeLog);
          return "kept-host";
        }
      }

      // Pin `canonicalHostDir` behind a file descriptor on every platform,
      // immediately, with no further `await` before it is used. `O_DIRECTORY
      // | O_NOFOLLOW` makes this open call a fourth, atomic re-check: it
      // fails with `ELOOP` or `ENOTDIR` instead of opening a symbolic link or
      // a non-directory, so a swap that lands in the gap the check above
      // cannot see is still caught here.
      let pinnedDir: FileHandle;
      try {
        pinnedDir = await open(
          canonicalHostDir,
          fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW,
        );
      } catch (error) {
        const code = (error as NodeJS.ErrnoException | null)?.code;
        if (code !== "ELOOP" && code !== "ENOTDIR") {
          throw error;
        }
        await log(skippedOutsideTreeLog);
        return "kept-host";
      }
      // On Linux, every write below resolves through this descriptor's
      // `/proc/self/fd/<fd>` alias, not the plain `canonicalHostDir` text
      // used until now, so a swap of that text AFTER this point can no
      // longer redirect a write. `/proc` does not exist on a non-Linux
      // platform, so there `writeDirPath` stays the plain `canonicalHostDir`
      // text, and each write below calls {@link assertPinnedDirectoryStillLive}
      // immediately beforehand to re-verify that text still names the
      // SAME directory `pinnedDir` was opened against.
      const writeDirPath =
        process.platform === "linux" ? `/proc/self/fd/${pinnedDir.fd}` : canonicalHostDir;

      try {
        const canonicalHostAuthPath = path.join(canonicalHostDir, hostAuthFileName);

        // Stage on the same filesystem as the host target so both the predicate read
        // and the final rename stay device-local (rename across devices is not
        // atomic and would fail with EXDEV). Both the create below and the rename
        // that follows address the file through `writeDirPath` — the pinned
        // directory descriptor on Linux, the plain re-verified directory text
        // everywhere else — never through the original `canonicalHostDir` text
        // again on Linux.
        const tempFileName = `.auth.json.copyback-${process.pid}-${randomUUID()}.tmp`;
        const stagedTempPath = path.join(canonicalHostDir, tempFileName);
        const writeStagedTempPath = path.join(writeDirPath, tempFileName);
        const writeHostAuthPath = path.join(writeDirPath, hostAuthFileName);

        // A non-Linux write addresses `canonicalHostDir` by plain text, not
        // through `pinnedDir` itself, so re-verify the text still names the
        // directory `pinnedDir` was opened against, immediately before the
        // first write that uses it. Linux writes through `pinnedDir`'s own
        // `/proc/self/fd` alias, so this check is unnecessary there.
        if (process.platform !== "linux") {
          await assertPinnedDirectoryStillLive(pinnedDir, canonicalHostDir);
        }

        // `O_CREAT | O_EXCL` creates the temp private and fails instead of
        // following or overwriting an existing entry; `O_NOFOLLOW` additionally
        // refuses outright if that entry is a symbolic link.
        const handle = await open(
          writeStagedTempPath,
          fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
          0o600,
        );
        try {
          await handle.writeFile(sandboxAuthBytes);
          await handle.close();

          // The decision predicate runs in a separate `node` child process, so
          // it cannot address a descriptor pinned in this process — it reads
          // both files by plain path. That read only feeds a comparison; it
          // can skew which side the predicate picks but never places
          // attacker-controlled bytes anywhere, so the descriptor pin (on
          // Linux) is reserved for the create and the rename below, the two
          // operations that actually write.
          const decision = await decideCodexAuthMerge(stagedTempPath, canonicalHostAuthPath, {
            errorLabel: "codex auth copy-back",
          });
          if (decision === USE_SOURCE_EXIT) {
            // The decision predicate above awaited a separate child process —
            // real time enough for a non-Linux directory swap the earlier
            // check could not see. Re-verify immediately before this write,
            // the same way as before the create above.
            if (process.platform !== "linux") {
              await assertPinnedDirectoryStillLive(pinnedDir, canonicalHostDir);
            }
            // Atomic same-directory swap through `writeDirPath`; rename
            // preserves the temp's 0600 mode.
            await rename(writeStagedTempPath, writeHostAuthPath);
            await log(
              "[paperclip] Codex auth copy-back: sandbox credential is strictly newer for the same subscription identity; installed to the host at mode 0600.",
            );
            return "copied";
          }

          await log(
            "[paperclip] Codex auth copy-back: host credential kept (sandbox copy is not a strictly-newer same-identity subscription credential).",
          );
          return "kept-host";
        } finally {
          // Close is idempotent-safe to skip after an explicit close; the temp is the
          // thing that must never linger. On the copy path rename already consumed it
          // (force makes the removal a no-op); on every other path this deletes the
          // staged credential bytes.
          await handle.close().catch(() => undefined);
          await rm(writeStagedTempPath, { force: true }).catch(() => undefined);
        }
      } finally {
        await pinnedDir?.close().catch(() => undefined);
      }
    },
    env,
  );

  // Additive cache write. Independent of the host default overwrite above: it
  // runs on its own directory lock, keys the slot by the real sandbox
  // `account_id`, and can write a slot for a different identity than the host
  // holds. It never touches the host default store. The off-switch (default on)
  // makes this a no-op when disabled. Only a usable subscription credential has
  // an identity to key; an api-key or unusable sandbox credential is skipped.
  //
  // The cache write is best-effort. The host copy-back above already finished
  // and set `hostOutcome`, so a failure of this additive write must not replace
  // that successful result. Catch the error, log it, and return `hostOutcome`.
  // The cache stays a hint: the next teardown re-attempts the write.
  if (resolveCacheEntryPath && isCodexAuthCacheEnabled(env)) {
    try {
      const sandboxAccountId = readSubscriptionAccountId(sandboxAuthBytes);
      if (sandboxAccountId) {
        const cacheEntryPath = await resolveCacheEntryPath(sandboxAccountId);
        await writeCodexAuthCacheEntry({ sandboxAuthBytes, cacheEntryPath, log, env });
      }
    } catch (error) {
      // Log only the errno code, never the error message. The message embeds the
      // cache slot path, and the slot path embeds the raw `account_id`; the code
      // (for example EACCES or ENOSPC) makes the failure diagnosable without a
      // leak. Token bytes never reach the log.
      const code = (error as NodeJS.ErrnoException | null)?.code ?? "unknown";
      // The host copy-back above already finished and set `hostOutcome`. This
      // diagnostic log is the last step, so a rejecting logger must not throw
      // and turn that successful result into a failed copy-back. Guard the log:
      // a rejection here is swallowed, and the function still returns
      // `hostOutcome` below.
      await Promise.resolve(
        log(
          `[paperclip] Codex auth cache: additive cache write failed (${code}); host copy-back result kept.`,
        ),
      ).catch(() => undefined);
    }
  }

  return hostOutcome;
}
