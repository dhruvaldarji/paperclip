import { chmod, lstat, mkdir, mkdtemp, readdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { copyBackCodexAuth } from "./codex-auth-copyback.js";
import {
  ensureCodexAuthCacheEntryDir,
  resolveCodexAuthCacheDir,
  resolveCodexAuthCacheEntryPath,
} from "./codex-auth-cache.js";
import { resolveSharedCodexHomeDir } from "./codex-home.js";

// One-shot hook run from inside the mocked `open` below, right before the
// real `open` call it wraps. It receives the exact arguments the copy-back
// passed to `open`, so a test can act only once a specific call (for example
// the one that creates the staging temp file) is about to run, and re-arm
// itself for a later call otherwise. A test arms this to swap a directory
// for a symbolic link, or replace it outright, at the exact instant the
// copy-back's own next `open` call runs — the narrowest point a directory
// race could land. `null` by default, so every other test in this file runs
// against the real `open` unchanged.
let onFirstOpenCall: ((args: unknown[]) => Promise<void>) | null = null;

// One-shot hook run right AFTER a real `open` call resolves (as opposed to
// `onFirstOpenCall`, which runs right before). A test uses this to land a
// directory swap the instant after the copy-back pins the directory
// descriptor — the earliest point a swap could still be caught by a later
// identity re-check, since the swap must follow the pin to be a genuine
// "already pinned, now replaced" race rather than a swap the pin's own
// `O_NOFOLLOW` open would already refuse.
let onAfterOpenCall: ((args: unknown[]) => Promise<void>) | null = null;

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    open: async (...args: Parameters<typeof actual.open>) => {
      if (onFirstOpenCall) {
        const hook = onFirstOpenCall;
        onFirstOpenCall = null;
        await hook(args);
      }
      const handle = await actual.open(...args);
      if (onAfterOpenCall) {
        const hook = onAfterOpenCall;
        onAfterOpenCall = null;
        await hook(args);
      }
      return handle;
    },
  };
});

// One-shot hook run right after the real merge-decision predicate resolves.
// The predicate runs in a separate `node` child process, so it is real
// elapsed time a mocked `open`/`rename` hook cannot reach. A test uses this
// to land a directory swap between the decision and the rename that follows
// it.
let onAfterDecideCodexAuthMerge: (() => Promise<void>) | null = null;

vi.mock("./codex-auth-merge-decision.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./codex-auth-merge-decision.js")>();
  return {
    ...actual,
    decideCodexAuthMerge: async (...args: Parameters<typeof actual.decideCodexAuthMerge>) => {
      const result = await actual.decideCodexAuthMerge(...args);
      if (onAfterDecideCodexAuthMerge) {
        const hook = onAfterDecideCodexAuthMerge;
        onAfterDecideCodexAuthMerge = null;
        await hook();
      }
      return result;
    },
  };
});

// The copy-back module reuses the exact same direction-agnostic decision
// predicate (`codex-auth-merge-decision.cjs`) that the inbound extract path
// runs, only with the arguments flipped: for an outbound copy-back the sandbox
// copy is the `source` and the host copy is the `destination`, so exit 10
// (use source) means "install the sandbox credential onto the host" and exit 20
// (keep destination) means "leave the host credential untouched". This suite
// drives the REAL `.cjs` through the module (no stub predicate) against a real
// host tmp filesystem, injecting only the sandbox read.
describe("copyBackCodexAuth", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    while (cleanupDirs.length > 0) {
      const dir = cleanupDirs.pop();
      if (!dir) continue;
      // Re-open perms in case a test tightened them, so cleanup always succeeds.
      await chmod(dir, 0o700).catch(() => undefined);
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  function subscriptionAuth(input: {
    accountId: string;
    lastRefresh?: string;
    marker: string;
  }): string {
    return JSON.stringify(
      {
        tokens: {
          id_token: `id-token-${input.marker}`,
          access_token: `access-token-${input.marker}`,
          refresh_token: `refresh-token-${input.marker}`,
          account_id: input.accountId,
        },
        ...(input.lastRefresh ? { last_refresh: input.lastRefresh } : {}),
      },
      null,
      2,
    );
  }

  function apiKeyAuth(marker: string): string {
    return JSON.stringify({ OPENAI_API_KEY: `sk-${marker}` }, null, 2);
  }

  async function makeHostDir(): Promise<string> {
    const dir = await mkdtemp(path.join(os.tmpdir(), "paperclip-codex-copyback-"));
    cleanupDirs.push(dir);
    return dir;
  }

  const NEWER = "2026-07-09T02:00:00Z";
  const OLDER = "2026-07-09T01:00:00Z";

  async function runCopyBack(input: {
    sandboxAuth: string | (() => Promise<Buffer>);
    hostAuth: string;
    hostDir?: string;
  }): Promise<{
    outcome: Awaited<ReturnType<typeof copyBackCodexAuth>>;
    finalHostAuth: string;
    finalHostMode: number;
    logs: string[];
    leftoverEntries: string[];
  }> {
    const hostDir = input.hostDir ?? (await makeHostDir());
    const hostAuthPath = path.join(hostDir, "auth.json");
    await writeFile(hostAuthPath, input.hostAuth, { mode: 0o600 });

    const readSandboxAuth =
      typeof input.sandboxAuth === "function"
        ? input.sandboxAuth
        : async () => Buffer.from(input.sandboxAuth as string, "utf8");

    const logs: string[] = [];
    const outcome = await copyBackCodexAuth({
      readSandboxAuth,
      hostAuthPath,
      log: (line) => {
        logs.push(line);
      },
    });

    const finalHostAuth = await readFile(hostAuthPath, "utf8");
    const finalHostMode = (await lstat(hostAuthPath)).mode & 0o777;
    const leftoverEntries = (await readdir(hostDir)).filter((name) => name !== "auth.json");
    return { outcome, finalHostAuth, finalHostMode, logs, leftoverEntries };
  }

  it("installs a strictly-newer same-account sandbox auth onto the host at 0600", async () => {
    const sandboxAuth = subscriptionAuth({
      accountId: "acct-same",
      lastRefresh: NEWER,
      marker: "sandbox-newer-SENTINEL",
    });
    const hostAuth = subscriptionAuth({
      accountId: "acct-same",
      lastRefresh: OLDER,
      marker: "host-older-SENTINEL",
    });

    const result = await runCopyBack({ sandboxAuth, hostAuth });

    expect(result.outcome).toBe("copied");
    expect(result.finalHostAuth).toBe(sandboxAuth);
    expect(result.finalHostMode).toBe(0o600);
    // Temp staging file must be gone once the swap completes.
    expect(result.leftoverEntries).toEqual([]);
    // Never leak token bytes in log output.
    expect(result.logs.join("\n")).not.toContain("SENTINEL");
  });

  it("keeps the host auth when the sandbox copy is not strictly newer", async () => {
    const cases: { name: string; sandboxAuth: string; hostAuth: string }[] = [
      {
        name: "tie",
        sandboxAuth: subscriptionAuth({ accountId: "acct-same", lastRefresh: NEWER, marker: "sandbox-tie" }),
        hostAuth: subscriptionAuth({ accountId: "acct-same", lastRefresh: NEWER, marker: "host-tie" }),
      },
      {
        name: "sandbox older",
        sandboxAuth: subscriptionAuth({ accountId: "acct-same", lastRefresh: OLDER, marker: "sandbox-older" }),
        hostAuth: subscriptionAuth({ accountId: "acct-same", lastRefresh: NEWER, marker: "host-newer" }),
      },
      {
        name: "missing sandbox last_refresh",
        sandboxAuth: subscriptionAuth({ accountId: "acct-same", marker: "sandbox-no-refresh" }),
        hostAuth: subscriptionAuth({ accountId: "acct-same", lastRefresh: NEWER, marker: "host-refresh" }),
      },
      {
        name: "unparseable sandbox last_refresh",
        sandboxAuth: subscriptionAuth({ accountId: "acct-same", lastRefresh: "not-a-date", marker: "sandbox-bad" }),
        hostAuth: subscriptionAuth({ accountId: "acct-same", lastRefresh: NEWER, marker: "host-refresh" }),
      },
    ];

    for (const entry of cases) {
      const result = await runCopyBack({ sandboxAuth: entry.sandboxAuth, hostAuth: entry.hostAuth });
      expect(result.outcome, entry.name).toBe("kept-host");
      expect(result.finalHostAuth, entry.name).toBe(entry.hostAuth);
      expect(result.finalHostMode, entry.name).toBe(0o600);
      expect(result.leftoverEntries, entry.name).toEqual([]);
    }
  });

  it("keeps the host auth on identity mismatch, kind mismatch, apikey, and unusable sandbox auth", async () => {
    const hostAuth = subscriptionAuth({ accountId: "acct-host", lastRefresh: OLDER, marker: "host-keep" });
    const cases: { name: string; sandboxAuth: string; hostAuth: string }[] = [
      {
        name: "identity mismatch (sandbox newer, different account)",
        sandboxAuth: subscriptionAuth({ accountId: "acct-other", lastRefresh: NEWER, marker: "sandbox-other" }),
        hostAuth,
      },
      {
        name: "kind mismatch (sandbox subscription, host apikey)",
        sandboxAuth: subscriptionAuth({ accountId: "acct-host", lastRefresh: NEWER, marker: "sandbox-sub" }),
        hostAuth: apiKeyAuth("host-api-key"),
      },
      {
        name: "sandbox apikey",
        sandboxAuth: apiKeyAuth("sandbox-api-key"),
        hostAuth,
      },
      {
        name: "sandbox unusable JSON",
        sandboxAuth: "{not valid json",
        hostAuth,
      },
      {
        name: "sandbox account id missing",
        sandboxAuth: JSON.stringify({
          tokens: { id_token: "id", access_token: "acc", refresh_token: "ref" },
          last_refresh: NEWER,
        }),
        hostAuth,
      },
      {
        name: "host unusable JSON (never create host auth from sandbox)",
        sandboxAuth: subscriptionAuth({ accountId: "acct-host", lastRefresh: NEWER, marker: "sandbox-valid" }),
        hostAuth: "{not valid json",
      },
    ];

    for (const entry of cases) {
      const result = await runCopyBack({ sandboxAuth: entry.sandboxAuth, hostAuth: entry.hostAuth });
      expect(result.outcome, entry.name).toBe("kept-host");
      expect(result.finalHostAuth, entry.name).toBe(entry.hostAuth);
      expect(result.finalHostMode, entry.name).toBe(0o600);
      expect(result.leftoverEntries, entry.name).toEqual([]);
    }
  });

  it("creates a missing shared Codex home before staging copy-back", async () => {
    const rootDir = await makeHostDir();
    const hostDir = path.join(rootDir, "missing-codex-home");
    const hostAuthPath = path.join(hostDir, "auth.json");
    const logs: string[] = [];

    const outcome = await copyBackCodexAuth({
      readSandboxAuth: async () => Buffer.from(apiKeyAuth("sandbox-only"), "utf8"),
      hostAuthPath,
      log: (line) => {
        logs.push(line);
      },
    });

    expect(outcome).toBe("kept-host");
    expect(await readdir(hostDir)).toEqual([]);
    expect(logs.join("\n")).not.toContain("sandbox-only");
  });

  it("preserves the host file atomically when the install cannot be staged (no partial write, no leaked temp)", async () => {
    // Make the host directory read-only so staging the same-filesystem temp fails
    // with EACCES. The host credential must be left byte-for-byte intact and no
    // partial/temp file may remain — the outbound write is all-or-nothing.
    const hostDir = await makeHostDir();
    const hostAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: OLDER, marker: "host-intact" });
    const hostAuthPath = path.join(hostDir, "auth.json");
    await writeFile(hostAuthPath, hostAuth, { mode: 0o600 });
    const before = await stat(hostAuthPath);

    await chmod(hostDir, 0o500); // r-x: readable/traversable, not writable
    try {
      const sandboxAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: NEWER, marker: "sandbox-newer" });
      await expect(
        copyBackCodexAuth({
          readSandboxAuth: async () => Buffer.from(sandboxAuth, "utf8"),
          hostAuthPath,
          log: () => {},
        }),
      ).rejects.toThrow();
    } finally {
      await chmod(hostDir, 0o700);
    }

    const after = await stat(hostAuthPath);
    expect(await readFile(hostAuthPath, "utf8")).toBe(hostAuth);
    expect(after.mode & 0o777).toBe(0o600);
    expect(after.mtimeMs).toBe(before.mtimeMs);
    expect((await readdir(hostDir)).filter((name) => name !== "auth.json")).toEqual([]);
  });

  it("treats an absent sandbox auth.json (ENOENT) as a keep-host no-op, host untouched, no throw", async () => {
    const hostAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: OLDER, marker: "host-intact" });

    // The real production `readSandboxAuth` is `readFile("${assetDir}/auth.json")`;
    // a genuinely absent file surfaces a node ENOENT error. That must be a benign
    // "nothing to copy back" outcome, not a fail-loud teardown error.
    const enoent = Object.assign(new Error("ENOENT: no such file or directory, open 'auth.json'"), {
      code: "ENOENT",
    });

    const result = await runCopyBack({
      sandboxAuth: async () => {
        throw enoent;
      },
      hostAuth,
    });

    expect(result.outcome).toBe("kept-host");
    expect(result.finalHostAuth).toBe(hostAuth);
    expect(result.finalHostMode).toBe(0o600);
    // No staging temp is ever created on the ENOENT path.
    expect(result.leftoverEntries).toEqual([]);
    expect(result.logs.join("\n")).toContain("no sandbox credential to copy back");
  });

  it("fails loud when the sandbox read errors and leaves the host untouched", async () => {
    const hostDir = await makeHostDir();
    const hostAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: OLDER, marker: "host-intact" });
    const hostAuthPath = path.join(hostDir, "auth.json");
    await writeFile(hostAuthPath, hostAuth, { mode: 0o600 });

    await expect(
      copyBackCodexAuth({
        readSandboxAuth: async () => {
          throw new Error("sandbox read boom");
        },
        hostAuthPath,
        log: () => {},
      }),
    ).rejects.toThrow(/sandbox read boom/);

    expect(await readFile(hostAuthPath, "utf8")).toBe(hostAuth);
    expect((await readdir(hostDir)).filter((name) => name !== "auth.json")).toEqual([]);
  });

  it("does not emit token substrings on any code path", async () => {
    const sandboxAuth = subscriptionAuth({
      accountId: "acct-same",
      lastRefresh: NEWER,
      marker: "TOKEN-SENTINEL",
    });
    const hostAuth = subscriptionAuth({
      accountId: "acct-same",
      lastRefresh: OLDER,
      marker: "HOST-SENTINEL",
    });

    const result = await runCopyBack({ sandboxAuth, hostAuth });
    expect(result.outcome).toBe("copied");
    const combined = result.logs.join("\n");
    expect(combined).not.toContain("SENTINEL");
    expect(combined).not.toContain("id-token");
    expect(combined).not.toContain("access-token");
    expect(combined).not.toContain("refresh-token");
  });
});

// The teardown copy-back also writes the fresher, usable subscription credential
// into its per-identity cache slot, keyed by the real `account_id`. The cache is
// a SEPARATE store; the host default overwrite and the cache slot are asserted
// independently. This suite drives the real `.cjs` predicate (default mode for
// the host store, seed mode for the cache slot) against a real host tmp
// filesystem.
describe("copyBackCodexAuth identity-keyed cache write", () => {
  const cleanupDirs: string[] = [];
  const COMPANY_ID = "company-a";

  afterEach(async () => {
    while (cleanupDirs.length > 0) {
      const dir = cleanupDirs.pop();
      if (!dir) continue;
      await chmod(dir, 0o700).catch(() => undefined);
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  function subscriptionAuth(input: { accountId: string; lastRefresh?: string; marker: string }): string {
    return JSON.stringify({
      tokens: {
        id_token: `id-token-${input.marker}`,
        access_token: `access-token-${input.marker}`,
        refresh_token: `refresh-token-${input.marker}`,
        account_id: input.accountId,
      },
      ...(input.lastRefresh ? { last_refresh: input.lastRefresh } : {}),
    });
  }

  function apiKeyAuth(marker: string): string {
    return JSON.stringify({ OPENAI_API_KEY: `sk-${marker}` });
  }

  const NEWER = "2026-07-09T02:00:00Z";
  const OLDER = "2026-07-09T01:00:00Z";

  async function makeEnv(extra: Record<string, string> = {}): Promise<{
    env: NodeJS.ProcessEnv;
    sharedHomeAuthPath: string;
    sharedHome: string;
  }> {
    const home = await mkdtemp(path.join(os.tmpdir(), "paperclip-codex-copyback-cache-"));
    cleanupDirs.push(home);
    const env: NodeJS.ProcessEnv = {
      PAPERCLIP_HOME: home,
      PAPERCLIP_INSTANCE_ID: "default",
      CODEX_HOME: path.join(home, "shared-codex"),
      ...extra,
    };
    const sharedHome = resolveSharedCodexHomeDir(env);
    await mkdir(sharedHome, { recursive: true });
    return { env, sharedHomeAuthPath: path.join(sharedHome, "auth.json"), sharedHome };
  }

  async function runWithCache(input: {
    sandboxAuth: string;
    hostAuth?: string;
    env: NodeJS.ProcessEnv;
    sharedHomeAuthPath: string;
    cacheEnabledEnv?: NodeJS.ProcessEnv;
  }): Promise<{
    outcome: Awaited<ReturnType<typeof copyBackCodexAuth>>;
    finalHostAuth: string | null;
    logs: string[];
  }> {
    if (input.hostAuth !== undefined) {
      await writeFile(input.sharedHomeAuthPath, input.hostAuth, { mode: 0o600 });
    }
    const logs: string[] = [];
    const outcome = await copyBackCodexAuth({
      readSandboxAuth: async () => Buffer.from(input.sandboxAuth, "utf8"),
      hostAuthPath: input.sharedHomeAuthPath,
      log: (line) => {
        logs.push(line);
      },
      resolveCacheEntryPath: (accountId) =>
        ensureCodexAuthCacheEntryDir(input.env, accountId, COMPANY_ID),
      env: input.cacheEnabledEnv ?? input.env,
    });
    const finalHostAuth = await readFile(input.sharedHomeAuthPath, "utf8").catch(
      (error: NodeJS.ErrnoException) => (error.code === "ENOENT" ? null : Promise.reject(error)),
    );
    return { outcome, finalHostAuth, logs };
  }

  async function readCacheSlot(env: NodeJS.ProcessEnv, accountId: string): Promise<string | null> {
    const entryPath = resolveCodexAuthCacheEntryPath(env, accountId, COMPANY_ID);
    return readFile(entryPath, "utf8").catch((error: NodeJS.ErrnoException) =>
      error.code === "ENOENT" ? null : Promise.reject(error),
    );
  }

  it("host absent (matrix row 3): host default store stays empty, cache slot holds the credential keyed by account_id", async () => {
    const { env, sharedHomeAuthPath } = await makeEnv();
    const sandboxAuth = subscriptionAuth({ accountId: "acct-y", lastRefresh: NEWER, marker: "row3" });

    const result = await runWithCache({ sandboxAuth, env, sharedHomeAuthPath });

    expect(result.outcome).toBe("kept-host");
    expect(result.finalHostAuth).toBeNull(); // host never seeded
    expect(await readCacheSlot(env, "acct-y")).toBe(sandboxAuth);
  });

  it("host present, same identity, sandbox newer (matrix row 1a): host default overwritten AND cache slot updated", async () => {
    const { env, sharedHomeAuthPath } = await makeEnv();
    const sandboxAuth = subscriptionAuth({ accountId: "acct-x", lastRefresh: NEWER, marker: "sandbox" });
    const hostAuth = subscriptionAuth({ accountId: "acct-x", lastRefresh: OLDER, marker: "host" });

    const result = await runWithCache({ sandboxAuth, hostAuth, env, sharedHomeAuthPath });

    expect(result.outcome).toBe("copied");
    expect(result.finalHostAuth).toBe(sandboxAuth);
    expect(await readCacheSlot(env, "acct-x")).toBe(sandboxAuth);
  });

  it("host present, different identity (matrix row 1b): host default untouched, cache slot holds the new identity only", async () => {
    const { env, sharedHomeAuthPath } = await makeEnv();
    const sandboxAuth = subscriptionAuth({ accountId: "acct-y", lastRefresh: NEWER, marker: "sandbox" });
    const hostAuth = subscriptionAuth({ accountId: "acct-x", lastRefresh: OLDER, marker: "host" });

    const result = await runWithCache({ sandboxAuth, hostAuth, env, sharedHomeAuthPath });

    expect(result.outcome).toBe("kept-host");
    expect(result.finalHostAuth).toBe(hostAuth); // host keeps its own identity X
    expect(await readCacheSlot(env, "acct-y")).toBe(sandboxAuth); // slot Y written
    expect(await readCacheSlot(env, "acct-x")).toBeNull(); // no slot for host identity
  });

  it("sandbox apikey or unusable: neither the host default nor the cache changes", async () => {
    for (const sandboxAuth of [apiKeyAuth("sbx"), "{not valid json"]) {
      const { env, sharedHomeAuthPath } = await makeEnv();
      const hostAuth = subscriptionAuth({ accountId: "acct-x", lastRefresh: OLDER, marker: "host" });
      const result = await runWithCache({ sandboxAuth, hostAuth, env, sharedHomeAuthPath });
      expect(result.outcome).toBe("kept-host");
      expect(result.finalHostAuth).toBe(hostAuth);
      const cacheDir = resolveCodexAuthCacheDir(env, COMPANY_ID);
      // No cache slot directory is created at all for a credential with no identity.
      await expect(readdir(cacheDir)).rejects.toThrow();
    }
  });

  it("off-switch off (matrix row 1a inputs): teardown cache write is a no-op and the host default overwrite still runs", async () => {
    const { env, sharedHomeAuthPath } = await makeEnv();
    const sandboxAuth = subscriptionAuth({ accountId: "acct-x", lastRefresh: NEWER, marker: "sandbox" });
    const hostAuth = subscriptionAuth({ accountId: "acct-x", lastRefresh: OLDER, marker: "host" });

    const result = await runWithCache({
      sandboxAuth,
      hostAuth,
      env,
      sharedHomeAuthPath,
      cacheEnabledEnv: { ...env, PAPERCLIP_CODEX_AUTH_CACHE: "0" },
    });

    // Host overwrite still runs with the off-switch off.
    expect(result.outcome).toBe("copied");
    expect(result.finalHostAuth).toBe(sandboxAuth);
    // No cache slot is written.
    const cacheDir = resolveCodexAuthCacheDir(env, COMPANY_ID);
    await expect(readdir(cacheDir)).rejects.toThrow();
  });

  it("two concurrent teardown writes for the same identity leave one valid cache slot (no partial file)", async () => {
    const { env, sharedHomeAuthPath } = await makeEnv();
    await writeFile(
      sharedHomeAuthPath,
      subscriptionAuth({ accountId: "acct-x", lastRefresh: OLDER, marker: "host" }),
      { mode: 0o600 },
    );
    const run = (marker: string) =>
      copyBackCodexAuth({
        readSandboxAuth: async () =>
          Buffer.from(subscriptionAuth({ accountId: "acct-x", lastRefresh: NEWER, marker }), "utf8"),
        hostAuthPath: sharedHomeAuthPath,
        log: () => {},
        resolveCacheEntryPath: (accountId) => ensureCodexAuthCacheEntryDir(env, accountId, COMPANY_ID),
        env,
      });
    await Promise.all([run("a"), run("b")]);

    const entryPath = resolveCodexAuthCacheEntryPath(env, "acct-x", COMPANY_ID);
    const slotDir = path.dirname(entryPath);
    // Exactly one valid slot file, no leftover staging temp.
    expect(await readdir(slotDir)).toEqual(["auth.json"]);
    const finalSlot = await readFile(entryPath, "utf8");
    expect(JSON.parse(finalSlot).tokens.account_id).toBe("acct-x");
  });

  it("the cache write never emits source token bytes or a raw account_id to the log", async () => {
    const { env, sharedHomeAuthPath } = await makeEnv();
    const sandboxAuth = subscriptionAuth({
      accountId: "SECRET-ACCT",
      lastRefresh: NEWER,
      marker: "TOKEN-SENTINEL",
    });
    const result = await runWithCache({ sandboxAuth, env, sharedHomeAuthPath });
    expect(await readCacheSlot(env, "SECRET-ACCT")).toBe(sandboxAuth);
    const combined = result.logs.join("\n");
    expect(combined).not.toContain("SENTINEL");
    expect(combined).not.toContain("SECRET-ACCT");
    expect(combined).not.toContain("id-token");
  });

  it("a read-only cache directory does not fail the copy-back: the successful host result is kept and no partial slot remains", async () => {
    const { env, sharedHomeAuthPath } = await makeEnv();
    const sandboxAuth = subscriptionAuth({ accountId: "acct-x", lastRefresh: NEWER, marker: "sandbox" });
    const hostAuth = subscriptionAuth({ accountId: "acct-x", lastRefresh: OLDER, marker: "host" });
    await writeFile(sharedHomeAuthPath, hostAuth, { mode: 0o600 });

    // Pre-create the entry directory, then make it read-only so the cache-slot
    // temp create fails. The host overwrite runs first and must stay intact. The
    // additive cache write is best-effort, so its failure must not throw.
    const entryPath = await ensureCodexAuthCacheEntryDir(env, "acct-x", COMPANY_ID);
    const slotDir = path.dirname(entryPath);
    const logs: string[] = [];
    await chmod(slotDir, 0o500);
    let outcome: string;
    try {
      outcome = await copyBackCodexAuth({
        readSandboxAuth: async () => Buffer.from(sandboxAuth, "utf8"),
        hostAuthPath: sharedHomeAuthPath,
        log: (line) => {
          logs.push(line);
        },
        resolveCacheEntryPath: (accountId) => ensureCodexAuthCacheEntryDir(env, accountId, COMPANY_ID),
        env,
      });
    } finally {
      await chmod(slotDir, 0o700);
    }

    // The host copy-back succeeded and its result is returned unchanged.
    expect(outcome).toBe("copied");
    // Host default overwrite ran before the cache write and stays applied.
    expect(await readFile(sharedHomeAuthPath, "utf8")).toBe(sandboxAuth);
    // No partial slot file; only the (empty) slot directory remains.
    expect(await readdir(slotDir)).toEqual([]);
    // The failure is visible in the log with only the errno code. The raw
    // account_id (which the failing slot path embeds) never reaches the log.
    const combined = logs.join("\n");
    expect(combined).toContain("additive cache write failed (EACCES)");
    expect(combined).not.toContain("acct-x");
  });

  it("a rejecting cache-failure log does not override the successful host copy-back result", async () => {
    const { env, sharedHomeAuthPath } = await makeEnv();
    const sandboxAuth = subscriptionAuth({ accountId: "acct-x", lastRefresh: NEWER, marker: "sandbox" });
    const hostAuth = subscriptionAuth({ accountId: "acct-x", lastRefresh: OLDER, marker: "host" });
    await writeFile(sharedHomeAuthPath, hostAuth, { mode: 0o600 });

    // Force the additive cache write to fail: pre-create the slot directory,
    // then make it read-only so the slot temp create fails with EACCES.
    const entryPath = await ensureCodexAuthCacheEntryDir(env, "acct-x", COMPANY_ID);
    const slotDir = path.dirname(entryPath);
    await chmod(slotDir, 0o500);

    // The logger rejects for the cache-failure diagnostic line only. The host
    // copy-back already installed the sandbox credential on disk, so this
    // rejection must not propagate and must not override the "copied" result.
    const logs: string[] = [];
    let outcome: Awaited<ReturnType<typeof copyBackCodexAuth>> | undefined;
    let thrown: unknown;
    try {
      outcome = await copyBackCodexAuth({
        readSandboxAuth: async () => Buffer.from(sandboxAuth, "utf8"),
        hostAuthPath: sharedHomeAuthPath,
        log: (line) => {
          logs.push(line);
          if (line.includes("additive cache write failed")) {
            return Promise.reject(new Error("log sink boom"));
          }
        },
        resolveCacheEntryPath: (accountId) => ensureCodexAuthCacheEntryDir(env, accountId, COMPANY_ID),
        env,
      }).catch((error: unknown) => {
        thrown = error;
        return undefined;
      });
    } finally {
      await chmod(slotDir, 0o700);
    }

    // The rejecting cache-failure log never surfaces as a thrown error.
    expect(thrown).toBeUndefined();
    // The host copy-back result is kept intact.
    expect(outcome).toBe("copied");
    expect(await readFile(sharedHomeAuthPath, "utf8")).toBe(sandboxAuth);
    // No partial slot file remains after the failed cache write.
    expect(await readdir(slotDir)).toEqual([]);
    // The cache-failure diagnostic was attempted even though the sink rejected.
    expect(logs.some((line) => line.includes("additive cache write failed (EACCES)"))).toBe(true);
  });
});

// When a caller passes `companyId`, the copy-back re-verifies the host target's
// containment inside the company's own directory tree immediately before the
// write. This suite drives that re-check against a real host tmp filesystem
// laid out to match the company tree the check expects.
describe("copyBackCodexAuth companyId containment re-check", () => {
  const cleanupDirs: string[] = [];
  const COMPANY_ID = "company-a";

  afterEach(async () => {
    while (cleanupDirs.length > 0) {
      const dir = cleanupDirs.pop();
      if (!dir) continue;
      await chmod(dir, 0o700).catch(() => undefined);
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  function subscriptionAuth(input: { accountId: string; lastRefresh?: string; marker: string }): string {
    return JSON.stringify({
      tokens: {
        id_token: `id-token-${input.marker}`,
        access_token: `access-token-${input.marker}`,
        refresh_token: `refresh-token-${input.marker}`,
        account_id: input.accountId,
      },
      ...(input.lastRefresh ? { last_refresh: input.lastRefresh } : {}),
    });
  }

  const NEWER = "2026-07-09T02:00:00Z";
  const OLDER = "2026-07-09T01:00:00Z";

  async function setUpInstance(): Promise<{ env: NodeJS.ProcessEnv; companyRoot: string }> {
    const homeDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-codex-copyback-containment-"));
    cleanupDirs.push(homeDir);
    const env: NodeJS.ProcessEnv = { PAPERCLIP_HOME: homeDir, PAPERCLIP_INSTANCE_ID: "default" };
    const companyRoot = path.join(homeDir, "instances", "default", "companies", COMPANY_ID);
    await mkdir(companyRoot, { recursive: true });
    return { env, companyRoot };
  }

  it("installs on the host when the host path sits inside the company's own tree, exactly as without companyId", async () => {
    const { env, companyRoot } = await setUpInstance();
    const hostDir = path.join(companyRoot, "codex-home");
    const hostAuthPath = path.join(hostDir, "auth.json");
    await mkdir(hostDir, { recursive: true });
    const hostAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: OLDER, marker: "host-in-tree" });
    await writeFile(hostAuthPath, hostAuth, { mode: 0o600 });
    const sandboxAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: NEWER, marker: "sandbox-in-tree" });

    const logs: string[] = [];
    const outcome = await copyBackCodexAuth({
      readSandboxAuth: async () => Buffer.from(sandboxAuth, "utf8"),
      hostAuthPath,
      companyId: COMPANY_ID,
      log: (line) => {
        logs.push(line);
      },
      env,
    });

    expect(outcome).toBe("copied");
    expect(await readFile(hostAuthPath, "utf8")).toBe(sandboxAuth);
  });

  it("keeps the host, writes nothing, and logs the fixed warning when the host path sits outside the company's tree", async () => {
    const { env } = await setUpInstance();
    const outsideDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-codex-copyback-outside-"));
    cleanupDirs.push(outsideDir);
    const hostAuthPath = path.join(outsideDir, "auth.json");
    const sandboxAuth = subscriptionAuth({ accountId: "acct-x", lastRefresh: NEWER, marker: "sandbox-outside" });

    const logs: string[] = [];
    const outcome = await copyBackCodexAuth({
      readSandboxAuth: async () => Buffer.from(sandboxAuth, "utf8"),
      hostAuthPath,
      companyId: COMPANY_ID,
      log: (line) => {
        logs.push(line);
      },
      env,
    });

    expect(outcome).toBe("kept-host");
    expect(await readdir(outsideDir)).toEqual([]);
    expect(logs).toEqual([
      "[paperclip] Codex auth copy-back: skipped (the configured Codex home is outside the managed directory tree).",
    ]);
  });

  it("stays fail-loud and does not return kept-host when the re-check fails with an error that is not a containment rejection", async () => {
    const hostDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-codex-copyback-broken-env-"));
    cleanupDirs.push(hostDir);
    const hostAuthPath = path.join(hostDir, "auth.json");
    const hostAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: OLDER, marker: "host-broken-env" });
    await writeFile(hostAuthPath, hostAuth, { mode: 0o600 });

    // An invalid PAPERCLIP_INSTANCE_ID makes the boundary resolver throw a
    // plain configuration error before it ever reaches a containment check.
    const brokenEnv: NodeJS.ProcessEnv = { PAPERCLIP_HOME: hostDir, PAPERCLIP_INSTANCE_ID: "not a valid id" };
    const sandboxAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: NEWER, marker: "sandbox-broken-env" });

    await expect(
      copyBackCodexAuth({
        readSandboxAuth: async () => Buffer.from(sandboxAuth, "utf8"),
        hostAuthPath,
        companyId: COMPANY_ID,
        log: () => {},
        env: brokenEnv,
      }),
    ).rejects.toThrow(/Invalid PAPERCLIP_INSTANCE_ID/);

    expect(await readFile(hostAuthPath, "utf8")).toBe(hostAuth);
  });
});

// Between the lock-time re-check and the write, a local attacker who can
// rename entries under the target's own parent could swap the target
// directory for a symbolic link. This suite proves the copy-back closes that
// window: it swaps the directory for a link to an OUTSIDE, attacker-chosen
// directory at the earliest point the copy-back's own next filesystem call
// runs, then asserts nothing ever lands in that outside directory.
describe("copyBackCodexAuth directory-swap-to-symlink protection", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    onFirstOpenCall = null;
    while (cleanupDirs.length > 0) {
      const dir = cleanupDirs.pop();
      if (!dir) continue;
      await chmod(dir, 0o700).catch(() => undefined);
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  function subscriptionAuth(input: { accountId: string; lastRefresh?: string; marker: string }): string {
    return JSON.stringify({
      tokens: {
        id_token: `id-token-${input.marker}`,
        access_token: `access-token-${input.marker}`,
        refresh_token: `refresh-token-${input.marker}`,
        account_id: input.accountId,
      },
      ...(input.lastRefresh ? { last_refresh: input.lastRefresh } : {}),
    });
  }

  const NEWER = "2026-07-09T02:00:00Z";
  const OLDER = "2026-07-09T01:00:00Z";

  it("does not write into a directory swapped to a symbolic link right after the lock-time re-check", async () => {
    const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-codex-copyback-swap-"));
    cleanupDirs.push(rootDir);
    const hostDir = path.join(rootDir, "codex-home");
    const hostAuthPath = path.join(hostDir, "auth.json");
    await mkdir(hostDir, { recursive: true });
    const hostAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: OLDER, marker: "host-intact" });
    await writeFile(hostAuthPath, hostAuth, { mode: 0o600 });

    const outsideDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-codex-copyback-outside-"));
    cleanupDirs.push(outsideDir);
    // A usable, OLDER same-account decoy at the attacker's target: with a
    // real destination in place the decision predicate would pick "use
    // source" (the sandbox copy below is newer), so an unpinned write would
    // overwrite this decoy with the sandbox credential — the clearest,
    // byte-level proof of a leaked write, not just an early return.
    const outsideAuthPath = path.join(outsideDir, "auth.json");
    const decoyAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: OLDER, marker: "outside-decoy" });
    await writeFile(outsideAuthPath, decoyAuth, { mode: 0o600 });

    // Fires right before the copy-back's own first `open` call, which is the
    // directory-pin open: swap the real `hostDir` for a symbolic link to
    // `outsideDir` at that exact instant.
    onFirstOpenCall = async () => {
      await rm(hostDir, { recursive: true, force: true });
      await symlink(outsideDir, hostDir);
    };

    const sandboxAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: NEWER, marker: "sandbox-newer" });
    const logs: string[] = [];
    const outcome = await copyBackCodexAuth({
      readSandboxAuth: async () => Buffer.from(sandboxAuth, "utf8"),
      hostAuthPath,
      log: (line) => {
        logs.push(line);
      },
    });

    expect(outcome).toBe("kept-host");
    // The decoy at the attacker's target is untouched — the copy-back never
    // wrote through the swapped symbolic link.
    expect(await readFile(outsideAuthPath, "utf8")).toBe(decoyAuth);
    expect(await readdir(outsideDir)).toEqual(["auth.json"]);
    expect(logs).toEqual([
      "[paperclip] Codex auth copy-back: skipped (the configured Codex home is outside the managed directory tree).",
    ]);
  });
});

// A non-Linux host cannot pin the copy-back directory behind a `/proc/self/fd`
// descriptor (`/proc` does not exist there), but it must still install a
// refreshed credential: the managed-home safety checks (containment, symlink
// rejection) do not depend on that descriptor pin. This suite forces
// `process.platform` to a non-Linux value and proves the write still happens,
// and that the containment re-check still blocks a target outside the tree.
describe("copyBackCodexAuth on a non-Linux host", () => {
  const cleanupDirs: string[] = [];
  const originalPlatform = process.platform;
  const COMPANY_ID = "company-a";

  afterEach(async () => {
    Object.defineProperty(process, "platform", { value: originalPlatform });
    while (cleanupDirs.length > 0) {
      const dir = cleanupDirs.pop();
      if (!dir) continue;
      await chmod(dir, 0o700).catch(() => undefined);
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  function subscriptionAuth(input: { accountId: string; lastRefresh?: string; marker: string }): string {
    return JSON.stringify({
      tokens: {
        id_token: `id-token-${input.marker}`,
        access_token: `access-token-${input.marker}`,
        refresh_token: `refresh-token-${input.marker}`,
        account_id: input.accountId,
      },
      ...(input.lastRefresh ? { last_refresh: input.lastRefresh } : {}),
    });
  }

  const NEWER = "2026-07-09T02:00:00Z";
  const OLDER = "2026-07-09T01:00:00Z";

  it.each(["darwin", "win32"])(
    "installs a strictly-newer sandbox credential onto the host on %s",
    async (platform) => {
      Object.defineProperty(process, "platform", { value: platform });
      const hostDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-codex-copyback-nonlinux-"));
      cleanupDirs.push(hostDir);
      const hostAuthPath = path.join(hostDir, "auth.json");
      const hostAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: OLDER, marker: "host-older" });
      await writeFile(hostAuthPath, hostAuth, { mode: 0o600 });
      const sandboxAuth = subscriptionAuth({
        accountId: "acct-same",
        lastRefresh: NEWER,
        marker: "sandbox-newer",
      });

      const logs: string[] = [];
      const outcome = await copyBackCodexAuth({
        readSandboxAuth: async () => Buffer.from(sandboxAuth, "utf8"),
        hostAuthPath,
        log: (line) => {
          logs.push(line);
        },
      });

      expect(outcome).toBe("copied");
      expect(await readFile(hostAuthPath, "utf8")).toBe(sandboxAuth);
      expect((await lstat(hostAuthPath)).mode & 0o777).toBe(0o600);
      // No staging temp is left behind on the write path.
      expect((await readdir(hostDir)).filter((name) => name !== "auth.json")).toEqual([]);
      expect(logs.join("\n")).not.toContain("outside the managed directory tree");
    },
  );

  it("still keeps the host, writes nothing, when the target sits outside the company's own tree", async () => {
    Object.defineProperty(process, "platform", { value: "darwin" });
    const homeDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-codex-copyback-nonlinux-containment-"));
    cleanupDirs.push(homeDir);
    const env: NodeJS.ProcessEnv = { PAPERCLIP_HOME: homeDir, PAPERCLIP_INSTANCE_ID: "default" };
    await mkdir(path.join(homeDir, "instances", "default", "companies", COMPANY_ID), { recursive: true });
    const outsideDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-codex-copyback-nonlinux-outside-"));
    cleanupDirs.push(outsideDir);
    const hostAuthPath = path.join(outsideDir, "auth.json");
    const sandboxAuth = subscriptionAuth({ accountId: "acct-x", lastRefresh: NEWER, marker: "sandbox-outside" });

    const logs: string[] = [];
    const outcome = await copyBackCodexAuth({
      readSandboxAuth: async () => Buffer.from(sandboxAuth, "utf8"),
      hostAuthPath,
      companyId: COMPANY_ID,
      log: (line) => {
        logs.push(line);
      },
      env,
    });

    expect(outcome).toBe("kept-host");
    expect(await readdir(outsideDir)).toEqual([]);
    expect(logs).toEqual([
      "[paperclip] Codex auth copy-back: skipped (the configured Codex home is outside the managed directory tree).",
    ]);
  });
});

// A symbolic-link check alone cannot see a directory that a local attacker
// removed and recreated as a fresh, PLAIN directory under the same name — the
// replacement is still a real directory, not a link. On Linux, every write
// addresses the directory descriptor pinned before this replacement could
// land, so the replacement never redirects a write; on a non-Linux platform
// the write still addresses the directory by its plain path text, so this
// suite proves the copy-back re-checks the pinned descriptor's identity
// (device and inode) immediately before that write and rejects instead of
// installing into the replacement.
describe("copyBackCodexAuth directory-replacement race protection on a non-Linux host", () => {
  const cleanupDirs: string[] = [];
  const originalPlatform = process.platform;

  afterEach(async () => {
    onFirstOpenCall = null;
    onAfterOpenCall = null;
    onAfterDecideCodexAuthMerge = null;
    Object.defineProperty(process, "platform", { value: originalPlatform });
    while (cleanupDirs.length > 0) {
      const dir = cleanupDirs.pop();
      if (!dir) continue;
      await chmod(dir, 0o700).catch(() => undefined);
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  function subscriptionAuth(input: { accountId: string; lastRefresh?: string; marker: string }): string {
    return JSON.stringify({
      tokens: {
        id_token: `id-token-${input.marker}`,
        access_token: `access-token-${input.marker}`,
        refresh_token: `refresh-token-${input.marker}`,
        account_id: input.accountId,
      },
      ...(input.lastRefresh ? { last_refresh: input.lastRefresh } : {}),
    });
  }

  const NEWER = "2026-07-09T02:00:00Z";
  const OLDER = "2026-07-09T01:00:00Z";

  it("rejects the write instead of installing into a directory removed and recreated right after the descriptor was pinned", async () => {
    Object.defineProperty(process, "platform", { value: "darwin" });

    const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-codex-copyback-replace-"));
    cleanupDirs.push(rootDir);
    const hostDir = path.join(rootDir, "codex-home");
    const hostAuthPath = path.join(hostDir, "auth.json");
    await mkdir(hostDir, { recursive: true });
    const hostAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: OLDER, marker: "host-intact" });
    await writeFile(hostAuthPath, hostAuth, { mode: 0o600 });

    // A decoy planted in the REPLACEMENT directory: if the copy-back wrote
    // through the plain path text without re-checking identity, this decoy
    // would end up overwritten by the sandbox credential instead of the
    // write being rejected. Fires right after the copy-back's directory-pin
    // `open` call resolves — the earliest point a genuine "already pinned,
    // now replaced" race can land.
    const decoyAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: OLDER, marker: "decoy-after-swap" });
    onAfterOpenCall = async () => {
      await rm(hostDir, { recursive: true, force: true });
      await mkdir(hostDir, { recursive: true });
      await writeFile(path.join(hostDir, "auth.json"), decoyAuth, { mode: 0o600 });
    };

    const sandboxAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: NEWER, marker: "sandbox-newer" });
    await expect(
      copyBackCodexAuth({
        readSandboxAuth: async () => Buffer.from(sandboxAuth, "utf8"),
        hostAuthPath,
        log: () => {},
      }),
    ).rejects.toThrow(/changed identity/);

    // The replacement directory's own decoy is untouched — the copy-back
    // never wrote through the replaced directory.
    expect(await readFile(path.join(hostDir, "auth.json"), "utf8")).toBe(decoyAuth);
    expect(await readdir(hostDir)).toEqual(["auth.json"]);
  });

  it("rejects the write when the replacement lands between the merge decision and the rename", async () => {
    Object.defineProperty(process, "platform", { value: "darwin" });

    const rootDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-codex-copyback-replace-late-"));
    cleanupDirs.push(rootDir);
    const hostDir = path.join(rootDir, "codex-home");
    const hostAuthPath = path.join(hostDir, "auth.json");
    await mkdir(hostDir, { recursive: true });
    const hostAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: OLDER, marker: "host-intact" });
    await writeFile(hostAuthPath, hostAuth, { mode: 0o600 });

    // The merge-decision predicate runs as a separate `node` child process —
    // real elapsed time the create-time re-check cannot reach. Fires right
    // after that predicate resolves with "use source" for the strictly-newer
    // same-identity sandbox credential below, and replaces the directory
    // with a fresh, plain one under the same name before the rename runs.
    onAfterDecideCodexAuthMerge = async () => {
      await rm(hostDir, { recursive: true, force: true });
      await mkdir(hostDir, { recursive: true });
    };

    const sandboxAuth = subscriptionAuth({ accountId: "acct-same", lastRefresh: NEWER, marker: "sandbox-newer" });
    await expect(
      copyBackCodexAuth({
        readSandboxAuth: async () => Buffer.from(sandboxAuth, "utf8"),
        hostAuthPath,
        log: () => {},
      }),
    ).rejects.toThrow(/changed identity/);

    // The replacement directory is empty — the rename never landed there.
    expect(await readdir(hostDir)).toEqual([]);
  });
});
