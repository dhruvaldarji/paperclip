import { randomBytes } from "node:crypto";
import {
  constants,
  fstatSync,
  lstatSync,
  realpathSync,
  type BigIntStats,
  type Stats,
} from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
} from "node:path";

import { createSanitizedAcpxSpawnInput } from "./environment.js";
import type { QualifiedAcpxAgent } from "./qualified-profiles.js";
import {
  resolveAcpxRuntimeRoot,
  type AcpxRecoveryBinding,
} from "./recovery-identity.js";

const PRIVATE_DIRECTORY_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;
const MAX_SANDBOX_ENVIRONMENT_BYTES = 512 * 1024;
const MAX_WORKSPACE_RECORD_BYTES = 64 * 1024;

interface AcpxRuntimeSandboxRootOwner {
  readonly root: string;
  readonly markerPath: string;
  readonly identifier: string;
  readonly dev: bigint;
  readonly ino: bigint;
}

// The runtime root path is deterministic per normalized session id, and
// `ensurePrivateDirectory` reuses an existing directory, so a path-only
// delete cannot prove a root still belongs to the admission that created it.
// An in-process registry cannot prove this either: a second Runner process
// starts with an empty registry, so its first claim always looks unowned.
// Only the filesystem is shared between Runner processes, so ownership is
// proved by a marker file placed beside the root (never inside it, because
// the recursive delete would destroy an inside marker before cleanup could
// read it). A claim opens the marker with O_CREAT|O_EXCL and writes a
// per-claim random identifier; that open is the cross-process exclusivity
// primitive. A later admission for the same deterministic root sees EEXIST
// and continues without delete authority — it never overwrites the marker,
// never deletes the root, and never fails the admission, because two
// admissions may legitimately share one session root. This in-process map
// is a same-process convenience mirror of a successful claim; the marker
// file is the sole source of truth for delete authority.
const acpxRuntimeSandboxRootOwners = new Map<
  string,
  AcpxRuntimeSandboxRootOwner
>();

// Every admission that claims or is declined a root — in any Runner process
// — keeps a durable lease file beside the root for as long as it uses that
// root. A lease file is not proof of delete authority (the marker alone is
// that); it is proof of occupancy. Because it lives on disk, any process
// that later gains the marker can see it, unlike a process-local registry,
// which starts empty in a new process and would report a live root as
// unowned. The marker owner must read the lease files before it deletes the
// root or releases the marker, so a still-live admission in another process
// is never deleted out from under, and the marker is never freed for reclaim
// while that admission still holds a lease. Each admission removes only its
// own lease file, when its own use of the root ends. Reading the lease files
// and acting on what they show are two separate filesystem calls; a
// same-root gate (defined further down, beside the lease helpers) makes a
// claim's own lease registration and a teardown's read-then-act run one at a
// time, so a new lease can never land in the gap between them.

// Associates each returned sandbox object with the exact owner it was built
// under, without exposing the ownership identifier on the public sandbox
// shape.
const acpxRuntimeSandboxRootOwnerByResult = new WeakMap<
  AcpxRuntimeSandbox,
  AcpxRuntimeSandboxRootOwner
>();

const ACPX_SANDBOX_ROOT_MARKER_SUFFIX = ".owner";
const ACPX_SANDBOX_ROOT_MARKER_MAX_BYTES = 128;
const ACPX_SANDBOX_ROOT_LEASE_INFIX = ".lease-";
const ACPX_SANDBOX_ROOT_LEASE_IDENTIFIER_PATTERN = /^[0-9a-f]{32}$/;

// A claim (marker write plus lease registration) and a teardown (marker
// read, lease count, then root delete or marker release) each read state and
// then act on it. Reading and acting are two separate filesystem calls, so
// without more, a claim can land in the gap between a teardown's read and
// its act: the teardown reads zero other leases, a new admission then
// registers a lease and starts using the root, and the teardown deletes that
// root anyway. This gate makes every claim and every teardown, for the same
// root, run one at a time, so a teardown's read and act always observe the
// same lease set and no claim can land inside that gap. It guards only this
// short read-then-act critical section, never the slower directory build
// that follows a claim.
const ACPX_SANDBOX_ROOT_GATE_SUFFIX = ".gate";
const ACPX_SANDBOX_ROOT_GATE_ACQUIRE_TIMEOUT_MS = 20_000;
const ACPX_SANDBOX_ROOT_GATE_RETRY_DELAY_MS = 15;
// Infix for the private path stale-gate recovery renames a gate to while it
// checks the gate's identity. See `breakStaleAcpxRuntimeSandboxRootGate`.
const ACPX_SANDBOX_ROOT_GATE_REAP_INFIX = ".reap-";
// Infix for the private path a holder stages its own gate content on before
// it publishes that content to the shared path. See
// `acquireAcpxRuntimeSandboxRootGate`.
const ACPX_SANDBOX_ROOT_GATE_STAGE_INFIX = ".stage-";
// A gate never appears at the shared path until its holder has already
// written its full pid and token to it — see
// `acquireAcpxRuntimeSandboxRootGate`. So a gate that carries no readable
// pid did not lose a race with a slow write, no matter how long that write
// took: its content was lost or damaged after publication. This grace
// period guards only that damage case, and must stay well under
// `ACPX_SANDBOX_ROOT_GATE_ACQUIRE_TIMEOUT_MS`, so a waiting admission gets
// more than one chance to recover the gate before it gives up.
const ACPX_SANDBOX_ROOT_GATE_INIT_GRACE_MS = 1_000;
// A single well-known path (not a random one) for the lock that serializes
// stale-gate recovery attempts for one gate across every Runner process. See
// `withAcpxRuntimeSandboxRootGateRecoveryLock`.
const ACPX_SANDBOX_ROOT_GATE_RECOVERY_LOCK_SUFFIX = ".recovering";
// One recovery attempt only runs local filesystem calls, never blocking I/O
// on another process, so it always finishes well inside this bound. A lock
// still held past it can only mean its own holder crashed mid-recovery; a
// later attempt then clears it, instead of leaving every admission for this
// root to wait out the full gate acquire timeout.
const ACPX_SANDBOX_ROOT_GATE_RECOVERY_LOCK_STALE_MS = 5_000;
// Infix for the private path a recovery lock holder pins its own lock
// instance under for as long as it holds the lock. Distinct from
// `ACPX_SANDBOX_ROOT_GATE_REAP_INFIX`, whose files are always short-lived
// (created and removed within a single function call): this pin instead
// lives for a holder's entire recovery pass, so a test or a directory scan
// that expects only transient reap files to ever appear must not mistake it
// for one. See `withAcpxRuntimeSandboxRootGateRecoveryLock`.
const ACPX_SANDBOX_ROOT_GATE_RECOVERY_LOCK_PIN_INFIX = ".holder-";

export interface AcpxRuntimeSandbox {
  root: string;
  stateDirectory: string;
  homeDirectory: string;
  configDirectory: string;
  dataDirectory: string;
  cacheDirectory: string;
  agentHomeDirectory: string;
  workspaceRecordPath: string;
  launchEnvironment: Readonly<NodeJS.ProcessEnv>;
  persistedEnvironment: Readonly<NodeJS.ProcessEnv>;
}

/** A recovered workspace pinned until the provider process is admitted. */
export interface AcpxRecoveryWorkspaceLease {
  readonly path: string;
  assertHeld(): void;
  close(): Promise<void>;
}

export interface AcpxRecoveryWorkspaceReadDependencies {
  /** Internal seam for racing a parent-directory replacement in tests. */
  afterRuntimeRootPinned?: () => Promise<void>;
}

/** Read the private workspace binding used to reopen one exact ACPX session. */
export async function readAcpxRecoveryWorkspace(
  input: {
    runtimeDirectory: string;
    normalizedSessionId: string;
  },
  dependencies: AcpxRecoveryWorkspaceReadDependencies = {},
): Promise<AcpxRecoveryWorkspaceLease> {
  const runtimeRoot = await resolveAcpxRuntimeRoot(
    input.runtimeDirectory,
    input.normalizedSessionId,
  );
  const namespace = dirname(runtimeRoot);
  let physicalNamespace: string;
  let physicalRuntimeRoot: string;
  try {
    const [namespaceMetadata, rootMetadata] = await Promise.all([
      lstat(namespace),
      lstat(runtimeRoot),
    ]);
    if (
      namespaceMetadata.isSymbolicLink() ||
      !namespaceMetadata.isDirectory() ||
      rootMetadata.isSymbolicLink() ||
      !rootMetadata.isDirectory()
    ) {
      throw new Error("invalid recovery directory");
    }
    [physicalNamespace, physicalRuntimeRoot] = await Promise.all([
      realpath(namespace),
      realpath(runtimeRoot),
    ]);
  } catch {
    throw new Error("ACPX recovery runtime directory is unavailable");
  }
  if (!isInside(physicalNamespace, physicalRuntimeRoot)) {
    throw new Error("ACPX recovery runtime directory escaped its namespace");
  }

  let namespaceHandle: FileHandle | null = null;
  let rootHandle: FileHandle | null = null;
  let workspaceHandle: FileHandle | null = null;
  try {
    namespaceHandle = await openPinnedDirectory(physicalNamespace);
    rootHandle = await openPinnedDirectory(physicalRuntimeRoot);
    assertPinnedDirectory(
      physicalNamespace,
      physicalNamespace,
      namespaceHandle,
      "ACPX recovery namespace changed during admission",
    );
    assertPinnedDirectory(
      physicalRuntimeRoot,
      physicalRuntimeRoot,
      rootHandle,
      "ACPX recovery runtime directory changed during admission",
    );
    await dependencies.afterRuntimeRootPinned?.();

    const recordPath = join(physicalRuntimeRoot, "workspace");
    let recordHandle: FileHandle;
    try {
      assertPinnedDirectory(
        physicalRuntimeRoot,
        physicalRuntimeRoot,
        rootHandle,
        "ACPX recovery runtime directory changed before record open",
      );
      recordHandle = await open(
        recordPath,
        constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
      );
    } catch {
      throw new Error("ACPX recovery workspace record is unavailable");
    }
    try {
      assertPinnedDirectory(
        physicalRuntimeRoot,
        physicalRuntimeRoot,
        rootHandle,
        "ACPX recovery runtime directory changed during record open",
      );
      const before = await recordHandle.stat({ bigint: true });
      if (
        !before.isFile() ||
        before.nlink !== 1n ||
        before.size < 2n ||
        before.size > BigInt(MAX_WORKSPACE_RECORD_BYTES)
      ) {
        throw new Error("ACPX recovery workspace record is invalid");
      }
      assertPinnedFile(recordPath, before);
      const bytes = await readFile(recordHandle);
      const after = await recordHandle.stat({ bigint: true });
      if (
        bytes.length !== Number(before.size) ||
        before.dev !== after.dev ||
        before.ino !== after.ino ||
        before.size !== after.size ||
        before.mtimeNs !== after.mtimeNs ||
        before.ctimeNs !== after.ctimeNs
      ) {
        throw new Error("ACPX recovery workspace record changed while read");
      }
      assertPinnedFile(recordPath, after);
      assertPinnedDirectory(
        physicalRuntimeRoot,
        physicalRuntimeRoot,
        rootHandle,
        "ACPX recovery runtime directory changed while record was read",
      );

      const workspace = bytes.toString("utf8").replace(/\n$/, "");
      if (!workspace || /[\u0000\r\n]/.test(workspace)) {
        throw new Error("ACPX recovery workspace record is invalid");
      }
      let physicalWorkspace: string;
      try {
        physicalWorkspace = await realpath(workspace);
        workspaceHandle = await openPinnedDirectory(physicalWorkspace);
      } catch {
        throw new Error("ACPX recovery workspace is unavailable");
      }
      if (physicalWorkspace === dirname(physicalWorkspace)) {
        throw new Error("ACPX recovery workspace is not a non-root directory");
      }
      if (!namespaceHandle || !rootHandle || !workspaceHandle) {
        throw new Error("ACPX recovery workspace handles are unavailable");
      }
      const pinnedNamespace = namespaceHandle;
      const pinnedRoot = rootHandle;
      const pinnedWorkspace = workspaceHandle;
      let closed = false;
      const lease: AcpxRecoveryWorkspaceLease = {
        path: physicalWorkspace,
        assertHeld() {
          if (closed)
            throw new Error("ACPX recovery workspace lease is closed");
          assertPinnedDirectory(
            physicalNamespace,
            physicalNamespace,
            pinnedNamespace,
            "ACPX recovery namespace changed before provider admission",
          );
          assertPinnedDirectory(
            physicalRuntimeRoot,
            physicalRuntimeRoot,
            pinnedRoot,
            "ACPX recovery runtime directory changed before provider admission",
          );
          assertPinnedDirectory(
            physicalWorkspace,
            physicalWorkspace,
            pinnedWorkspace,
            "ACPX recovery workspace changed before provider admission",
          );
        },
        async close() {
          if (closed) return;
          closed = true;
          await closeRecoveryHandles([
            pinnedWorkspace,
            pinnedRoot,
            pinnedNamespace,
          ]);
        },
      };
      lease.assertHeld();
      namespaceHandle = null;
      rootHandle = null;
      workspaceHandle = null;
      return lease;
    } finally {
      await recordHandle.close();
    }
  } finally {
    await closeRecoveryHandles([workspaceHandle, rootHandle, namespaceHandle]);
  }
}

async function openPinnedDirectory(path: string): Promise<FileHandle> {
  return await open(
    path,
    constants.O_RDONLY |
      (constants.O_DIRECTORY ?? 0) |
      (constants.O_NOFOLLOW ?? 0),
  );
}

function assertPinnedDirectory(
  path: string,
  expectedPhysicalPath: string,
  handle: FileHandle,
  message: string,
): void {
  try {
    const descriptor = fstatSync(handle.fd, { bigint: true });
    const entry = lstatSync(path, { bigint: true });
    if (
      !descriptor.isDirectory() ||
      entry.isSymbolicLink() ||
      !entry.isDirectory() ||
      !sameBigIntFile(descriptor, entry) ||
      realpathSync(path) !== expectedPhysicalPath
    ) {
      throw new Error(message);
    }
  } catch (error) {
    if (error instanceof Error && error.message === message) throw error;
    throw new Error(message);
  }
}

function assertPinnedFile(path: string, descriptor: BigIntStats): void {
  let entry: BigIntStats;
  try {
    entry = lstatSync(path, { bigint: true });
  } catch {
    throw new Error("ACPX recovery workspace record changed while read");
  }
  if (
    entry.isSymbolicLink() ||
    !entry.isFile() ||
    !sameBigIntFile(descriptor, entry)
  ) {
    throw new Error("ACPX recovery workspace record changed while read");
  }
}

function sameBigIntFile(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

async function closeRecoveryHandles(
  handles: readonly (FileHandle | null)[],
): Promise<void> {
  const results = await Promise.allSettled(
    handles
      .filter((handle): handle is FileHandle => handle !== null)
      .map((handle) => handle.close()),
  );
  const errors = results
    .filter(
      (result): result is PromiseRejectedResult => result.status === "rejected",
    )
    .map((result) => result.reason);
  if (errors.length > 0) {
    throw new AggregateError(errors, "Failed to close ACPX recovery handles");
  }
}

export interface AcpxRuntimeSandboxPrepareDependencies {
  /**
   * Internal test seam. Runs once the runtime root is claimed and owned,
   * before the rest of the sandbox is built.
   */
  afterRootOwned?: () => Promise<void>;
  /**
   * Internal test seam. Runs once a gate acquisition has written its own
   * pid and token to a private staging path in full, immediately before it
   * publishes that content to the shared path. Lets a test hold a
   * still-forming gate here, to prove no other process can ever observe it
   * at the shared path before its content is complete — however long the
   * write itself takes.
   */
  afterGateContentStaged?: () => Promise<void>;
  /**
   * Internal test seam. Runs once stale-gate recovery has pinned the gate
   * currently at the shared path with an extra link and proved its holder
   * is dead, immediately before recovery checks whether the shared path
   * still names that exact pinned gate and removes it. Lets a test replace
   * the gate at the shared path in that gap, to prove recovery only ever
   * removes the exact gate instance it pinned — never a replacement, and
   * never by disturbing the shared path first.
   */
  beforeStaleGateRemoval?: () => Promise<void>;
  /**
   * Internal test seam. Runs once stale-gate recovery has atomically
   * captured a live replacement gate in place of the dead one it proved
   * stale, immediately before recovery restores that capture to the shared
   * path. Lets a test claim the now-momentarily-empty shared path first, to
   * prove recovery's restore never clobbers that claim.
   */
  afterStaleGateCapture?: () => Promise<void>;
  /**
   * Internal test seam. Runs once this admission's own critical section has
   * ended, immediately before it releases its gate. Lets a test hold a
   * still-live gate open at the shared path, to prove a concurrent
   * stale-gate recovery pass can displace it without this admission's own
   * later release ever touching whatever a fresh claimant has since put in
   * its place.
   */
  beforeGateRelease?: () => Promise<void>;
  /**
   * Internal test seam. Runs once this admission has won the stale-gate
   * recovery lock, immediately before it inspects the gate. Lets a test hold
   * the lock open and prove a second, concurrent recovery attempt backs off
   * instead of racing its own capture of the same gate.
   */
  afterRecoveryLockAcquired?: () => Promise<void>;
  /**
   * Internal test seam. Runs once this admission has pinned the recovery
   * lock it found at the shared path and proved it stale, immediately
   * before it checks whether the shared path still names that exact pinned
   * lock and removes it. Lets a test replace the lock at the shared path in
   * that gap, to prove stale-lock recovery only ever removes the exact lock
   * instance it pinned — never a replacement a later admission has since
   * acquired.
   */
  afterRecoveryLockStaleCapture?: () => Promise<void>;
}

/** Prepare the private filesystem and environment visible to an ACPX agent. */
export async function prepareAcpxRuntimeSandbox(
  input: {
    binding: AcpxRecoveryBinding;
    agent: QualifiedAcpxAgent;
    environment?: NodeJS.ProcessEnv;
  },
  dependencies: AcpxRuntimeSandboxPrepareDependencies = {},
): Promise<AcpxRuntimeSandbox> {
  const expectedRoot = input.binding.runtimeRoot;
  if (resolve(expectedRoot) !== expectedRoot) {
    throw new Error("ACPX runtime root must be an absolute normalized path");
  }
  const acpxDirectory = dirname(expectedRoot);
  const runtimeDirectory = dirname(acpxDirectory);
  if (basename(acpxDirectory) !== "acpx") {
    throw new Error("ACPX runtime root is outside its expected namespace");
  }
  const physicalRuntimeDirectory = await realpath(runtimeDirectory);
  const physicalAcpxDirectory = await ensurePrivateDirectory(
    acpxDirectory,
    physicalRuntimeDirectory,
  );
  const root = await ensurePrivateDirectory(
    expectedRoot,
    physicalAcpxDirectory,
  );
  // Claim the marker as soon as the root exists, before any slower step (a
  // credential write, a later directory sync) can run. When another
  // admission already owns this deterministic root, the claim is declined:
  // this admission continues without delete authority, and its own cleanup
  // later finds the marker does not carry its identifier and leaves the
  // live root alone.
  const owner = await claimAcpxRuntimeSandboxRoot(root, dependencies);
  try {
    await dependencies.afterRootOwned?.();
    const stateDirectory = await ensurePrivateDirectory(
      join(root, "acpx-state"),
      root,
    );
    const homeDirectory = await ensurePrivateDirectory(
      join(root, "home"),
      root,
    );
    const configDirectory = await ensurePrivateDirectory(
      join(root, "config"),
      root,
    );
    const dataDirectory = await ensurePrivateDirectory(
      join(root, "data"),
      root,
    );
    const cacheDirectory = await ensurePrivateDirectory(
      join(root, "cache"),
      root,
    );
    const agentHomeDirectory = await ensurePrivateDirectory(
      join(root, `${input.agent}-home`),
      root,
    );
    const workspaceRecordPath = join(root, "workspace");
    await writePrivateFile(
      workspaceRecordPath,
      `${input.binding.workspacePath}\n`,
    );
    if (input.agent === "pi") {
      await writePrivateFile(
        join(agentHomeDirectory, "settings.json"),
        `${JSON.stringify({
          quietStartup: true,
          defaultProjectTrust: "never",
          enableInstallTelemetry: false,
        })}\n`,
      );
    }

    const sanitizedSpawnInput = createSanitizedAcpxSpawnInput(
      input.environment,
      input.agent,
    );
    // The sanitizer deliberately returns an opaque, frozen launch boundary.
    // Build the sandbox-owned mutable copy only from that projected
    // environment before adding paths that were created and validated above.
    const launchEnvironment: NodeJS.ProcessEnv = {
      ...sanitizedSpawnInput.env,
    };
    Object.assign(launchEnvironment, {
      HOME: homeDirectory,
      XDG_CONFIG_HOME: configDirectory,
      XDG_DATA_HOME: dataDirectory,
      XDG_CACHE_HOME: cacheDirectory,
      PAPERCLIP_ACPX_PROFILE: input.agent,
      PAPERCLIP_ACPX_ISOLATED_CONTEXT: "1",
      ...(input.agent === "pi"
        ? {
            PI_CODING_AGENT_DIR: agentHomeDirectory,
            PI_SKIP_VERSION_CHECK: "1",
            PI_TELEMETRY: "0",
          }
        : {}),
      ...(input.agent === "claude"
        ? { CLAUDE_CONFIG_DIR: agentHomeDirectory }
        : {}),
      ...(input.agent === "codex"
        ? {
            CODEX_HOME: agentHomeDirectory,
            NO_BROWSER: "1",
            ...(launchEnvironment.CODEX_API_KEY ||
            launchEnvironment.OPENAI_API_KEY
              ? {
                  DEFAULT_AUTH_REQUEST: JSON.stringify({
                    methodId: "api-key",
                  }),
                }
              : {}),
          }
        : {}),
    });
    validateEnvironmentSize(launchEnvironment);
    const persistedEnvironment = Object.fromEntries(
      Object.entries(launchEnvironment).filter(
        ([name, value]) =>
          typeof value === "string" && isPersistableEnvironmentName(name),
      ),
    );
    const sandbox: AcpxRuntimeSandbox = {
      root,
      stateDirectory,
      homeDirectory,
      configDirectory,
      dataDirectory,
      cacheDirectory,
      agentHomeDirectory,
      workspaceRecordPath,
      launchEnvironment: Object.freeze({ ...launchEnvironment }),
      persistedEnvironment: Object.freeze(persistedEnvironment),
    };
    acpxRuntimeSandboxRootOwnerByResult.set(sandbox, owner);
    return sandbox;
  } catch (error) {
    let cleanupError: unknown = null;
    try {
      await revalidateAndRemoveOwnedAcpxRuntimeSandboxRoot(root, owner);
    } catch (thrown) {
      cleanupError = thrown;
    }
    if (cleanupError !== null) {
      throw new AggregateError(
        [error, cleanupError],
        "ACPX sandbox preparation failed and its partial root could not be removed",
      );
    }
    throw error;
  }
}

function acpxRuntimeSandboxRootMarkerPath(root: string): string {
  return join(
    dirname(root),
    `${basename(root)}${ACPX_SANDBOX_ROOT_MARKER_SUFFIX}`,
  );
}

/**
 * Open the marker file with O_CREAT|O_EXCL. Only one caller, in one process,
 * can ever win this open call for a given marker path — that is the
 * cross-process exclusivity primitive the claim relies on. Returns false on
 * EEXIST instead of throwing, since losing the race is an expected outcome.
 */
async function writeAcpxSandboxRootMarkerExclusive(
  markerPath: string,
  identifier: string,
): Promise<boolean> {
  let handle: FileHandle;
  try {
    handle = await open(
      markerPath,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      PRIVATE_FILE_MODE,
    );
  } catch (error) {
    if (errorCode(error) === "EEXIST") return false;
    throw error;
  }
  try {
    await handle.chmod(PRIVATE_FILE_MODE);
    await handle.writeFile(identifier, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await syncDirectory(dirname(markerPath));
  return true;
}

// Read a marker's identifier. Returns null for a missing or malformed
// marker, so the caller treats it as "not proven" instead of as an error.
async function readAcpxSandboxRootMarkerIdentifier(
  markerPath: string,
): Promise<string | null> {
  let handle: FileHandle;
  try {
    handle = await open(
      markerPath,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
  } catch (error) {
    if (errorCode(error) === "ENOENT" || errorCode(error) === "ELOOP") {
      return null;
    }
    throw error;
  }
  try {
    const metadata = await handle.stat();
    if (
      !metadata.isFile() ||
      metadata.size < 1 ||
      metadata.size > ACPX_SANDBOX_ROOT_MARKER_MAX_BYTES
    ) {
      return null;
    }
    const bytes = await readFile(handle);
    return bytes.toString("utf8");
  } finally {
    await handle.close();
  }
}

function acpxRuntimeSandboxRootLeasePath(
  root: string,
  identifier: string,
): string {
  return join(
    dirname(root),
    `${basename(root)}${ACPX_SANDBOX_ROOT_LEASE_INFIX}${identifier}`,
  );
}

// Records this admission's own use of the root in a durable, cross-process
// lease file, so any process — including one that never held this
// admission's in-memory state — can later see the root is still occupied.
// Call this for every admission that claims or is declined this root, right
// after the marker claim is settled, so the lease is visible before any
// slower step in that admission's own preparation can run.
async function registerAcpxRuntimeSandboxRootLease(
  root: string,
  identifier: string,
): Promise<void> {
  const leasePath = acpxRuntimeSandboxRootLeasePath(root, identifier);
  let handle: FileHandle;
  try {
    handle = await open(
      leasePath,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      PRIVATE_FILE_MODE,
    );
  } catch (error) {
    if (errorCode(error) === "EEXIST") return;
    throw error;
  }
  try {
    await handle.chmod(PRIVATE_FILE_MODE);
  } finally {
    await handle.close();
  }
  await syncDirectory(dirname(leasePath));
}

// Ends this admission's own lease on the root, if it holds one. Call this
// from every path where an admission's own use of a root ends, before that
// path decides whether the root or the marker may be freed.
async function releaseAcpxRuntimeSandboxRootLease(
  root: string,
  identifier: string,
): Promise<void> {
  await unlink(acpxRuntimeSandboxRootLeasePath(root, identifier)).catch(
    (error) => {
      if (errorCode(error) !== "ENOENT") throw error;
    },
  );
}

// Counts durable leases on the root held by admissions other than
// `ownIdentifier`. Reads the filesystem, not any in-process state, so a
// lease registered by a different Runner process is still counted here.
async function countOtherAcpxRuntimeSandboxRootLeases(
  root: string,
  ownIdentifier: string,
): Promise<number> {
  const prefix = `${basename(root)}${ACPX_SANDBOX_ROOT_LEASE_INFIX}`;
  let entries: string[];
  try {
    entries = await readdir(dirname(root));
  } catch (error) {
    if (errorCode(error) === "ENOENT") return 0;
    throw error;
  }
  return entries.filter((entry) => {
    if (!entry.startsWith(prefix)) return false;
    const identifier = entry.slice(prefix.length);
    if (identifier === ownIdentifier) return false;
    return ACPX_SANDBOX_ROOT_LEASE_IDENTIFIER_PATTERN.test(identifier);
  }).length;
}

function acpxRuntimeSandboxRootGatePath(root: string): string {
  return join(
    dirname(root),
    `${basename(root)}${ACPX_SANDBOX_ROOT_GATE_SUFFIX}`,
  );
}

interface AcpxRuntimeSandboxRootGateDependencies {
  /** Internal seam that runs once a gate acquisition has staged its own
   * content in full, immediately before it publishes that content to the
   * shared path. Exercised only in tests. */
  afterGateContentStaged?: () => Promise<void>;
  beforeStaleGateRemoval?: () => Promise<void>;
  /** Internal seam for racing a third claimant into the moment between the
   * atomic capture and the restore in `removeStaleAcpxRuntimeSandboxRootGate`,
   * exercised only in tests. */
  afterStaleGateCapture?: () => Promise<void>;
  /** Internal seam that runs once this holder's own critical section has
   * ended, immediately before it releases its gate. Lets a test hold a
   * still-live gate open at the shared path, to prove a concurrent stale-gate
   * recovery pass can displace it without this holder's own later release
   * ever touching whatever a fresh claimant has since put in its place.
   * Exercised only in tests. */
  beforeGateRelease?: () => Promise<void>;
  /** Internal seam that runs once this admission has won the stale-gate
   * recovery lock, immediately before it inspects the gate. Lets a test hold
   * the lock open and prove a second, concurrent recovery attempt backs off
   * instead of racing its own capture of the same gate. Exercised only in
   * tests. */
  afterRecoveryLockAcquired?: () => Promise<void>;
  /** Internal seam for racing a replacement lock into the moment between the
   * atomic capture and the removal in
   * `breakStaleAcpxRuntimeSandboxRootGateRecoveryLock`, exercised only in
   * tests. */
  afterRecoveryLockStaleCapture?: () => Promise<void>;
}

/**
 * Run `criticalSection` as the sole holder of the gate for `root`, across
 * every Runner process. The gate is a file created with O_CREAT|O_EXCL, the
 * same cross-process exclusivity primitive the marker claim uses. Call this
 * around a claim's marker write plus lease registration, and around a
 * teardown's lease read plus its resulting delete or marker release, so a
 * claim and a teardown for the same root can never interleave.
 */
async function withAcpxRuntimeSandboxRootGate<T>(
  root: string,
  criticalSection: () => Promise<T>,
  dependencies: AcpxRuntimeSandboxRootGateDependencies = {},
): Promise<T> {
  const gatePath = acpxRuntimeSandboxRootGatePath(root);
  const deadline = Date.now() + ACPX_SANDBOX_ROOT_GATE_ACQUIRE_TIMEOUT_MS;
  for (;;) {
    const ownContent = await acquireAcpxRuntimeSandboxRootGate(
      gatePath,
      dependencies,
    );
    if (ownContent !== null) {
      try {
        return await criticalSection();
      } finally {
        await dependencies.beforeGateRelease?.();
        await releaseAcpxRuntimeSandboxRootGate(gatePath, ownContent);
      }
    }
    // The gate is held by another admission. Break it only when that holder
    // is provably gone (a crashed process), never on a mere timeout, so a
    // slow-but-live holder is never pre-empted. Run the break itself under
    // the recovery lock, so at most one admission ever inspects and removes
    // a given dead gate at a time — see
    // `withAcpxRuntimeSandboxRootGateRecoveryLock`.
    await withAcpxRuntimeSandboxRootGateRecoveryLock(gatePath, dependencies, () =>
      breakStaleAcpxRuntimeSandboxRootGate(gatePath, dependencies),
    );
    if (Date.now() >= deadline) {
      throw new Error(
        "ACPX sandbox root ownership gate could not be acquired",
      );
    }
    await delay(ACPX_SANDBOX_ROOT_GATE_RETRY_DELAY_MS);
  }
}

// Returns this holder's own gate content on success, so its later release
// can identify its own gate by content rather than by trusting `gatePath`
// still names it (see `releaseAcpxRuntimeSandboxRootGate`).
//
// Writes the full gate content to a private staging path first, then
// publishes it to the shared path with one atomic `link`. Creating an empty
// file directly at the shared path, then writing its content there in a
// later, separate call, would leave the shared path naming an
// identity-less gate for as long as that second call took. On a loaded
// host, a live holder's own write can take longer than stale-gate
// recovery's fixed grace period (`ACPX_SANDBOX_ROOT_GATE_INIT_GRACE_MS`),
// so recovery could then remove a gate its holder still owns. Staging the
// content first closes this gap by construction: the shared path never
// names this holder's gate until its content already exists in full, no
// matter how long the write itself takes.
async function acquireAcpxRuntimeSandboxRootGate(
  gatePath: string,
  dependencies: AcpxRuntimeSandboxRootGateDependencies = {},
): Promise<string | null> {
  const stagingPath = `${gatePath}${ACPX_SANDBOX_ROOT_GATE_STAGE_INFIX}${process.pid}-${randomBytes(8).toString("hex")}`;
  // The holder pid, plus a random per-acquisition token so this exact gate
  // instance can be told apart from a same-pid replacement created at the
  // same path later. A device-and-inode check cannot do this: a delete
  // immediately followed by a create at the same path can reuse the
  // just-freed inode number on some filesystems (observed on ext4), so a
  // replacement gate can carry the very same identity the deleted one had.
  const content = `${process.pid}:${randomBytes(16).toString("hex")}`;
  const handle = await open(
    stagingPath,
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_EXCL |
      (constants.O_NOFOLLOW ?? 0),
    PRIVATE_FILE_MODE,
  );
  try {
    await handle.chmod(PRIVATE_FILE_MODE);
    await handle.writeFile(content, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await dependencies.afterGateContentStaged?.();
    // `link` never opens through `gatePath`, unlike `open` with
    // O_CREAT|O_EXCL: it either creates a new name for the staged content
    // there, in one call, or fails outright, so a symlink planted at
    // `gatePath` can never be followed either way.
    await link(stagingPath, gatePath);
  } catch (error) {
    // Another holder's gate already names the shared path: this call lost
    // the race to acquire it.
    if (errorCode(error) === "EEXIST") return null;
    throw error;
  } finally {
    await unlink(stagingPath).catch((error) => {
      if (errorCode(error) !== "ENOENT") throw error;
    });
  }
  return content;
}

// Releases this holder's own gate. This must remove only the exact gate
// instance this holder acquired, never a fresh gate a later claimant has
// since put at the shared path — so a plain, unconditional `unlink(gatePath)`
// is never safe here. A concurrent stale-gate recovery pass can displace
// this holder's own still-live gate before this call runs (see
// `removeStaleAcpxRuntimeSandboxRootGate`): it captures whatever names the
// shared path with an atomic `rename`, and when a fresh claimant grabs the
// now-momentarily-empty shared path before recovery's restore can land,
// recovery leaves the captured gate stranded under a private name and
// never touches the shared path again. From this holder's point of view,
// by the time its own critical section ends, `gatePath` can therefore name
// three different things: this holder's own gate (the common case, nothing
// displaced it), nothing at all (recovery captured it and is still
// deciding what to do), or a different claimant's gate entirely (recovery
// captured this holder's gate and a fresh claimant has since taken the
// shared path). An unconditional unlink cannot tell these apart, so it
// would delete a later claimant's live gate right along with its own,
// reopening the exact claim-versus-teardown race this gate exists to
// close.
//
// This call instead captures whatever currently names `gatePath` with the
// same atomic `rename` recovery uses, then only proceeds by content: a
// match proves it caught its own gate, safe to delete for good; a mismatch
// means some other claimant's gate was caught by mistake, so this call
// restores it immediately with `link` — never `rename` — so a third
// claimant that has since taken the now-momentarily-empty shared path is
// never clobbered by the restore. Either way, once the shared path is no
// longer this holder's own concern, this call finishes by searching for its
// own gate under a stray reap-named capture with
// `reclaimAcpxRuntimeSandboxRootGateCapture`, since stale-gate recovery may
// still be holding it there, or may have already restored it back to
// `gatePath` in between, in which case a second capture attempt finds and
// removes it directly.
async function releaseAcpxRuntimeSandboxRootGate(
  gatePath: string,
  ownContent: string,
): Promise<void> {
  if (
    (await captureAndReleaseAcpxRuntimeSandboxRootGate(
      gatePath,
      ownContent,
    )) === "released"
  ) {
    return;
  }
  await reclaimAcpxRuntimeSandboxRootGateCapture(gatePath, ownContent);
  await captureAndReleaseAcpxRuntimeSandboxRootGate(gatePath, ownContent);
}

type AcpxRuntimeSandboxRootGateCaptureOutcome =
  | "released"
  | "absent"
  | "displaced";

// Atomically captures whatever currently names `gatePath` and, only when its
// content proves it is this holder's own gate, deletes it for good.
// Whatever else this call finds at `gatePath` — a different claimant's live
// gate, or nothing at all — is left exactly as this holder found it: a
// mismatched capture is put straight back (or, if a fresh claimant has since
// taken the shared path, left under its own private name for that gate's
// real owner to find later by content), and a missing gate means there is
// nothing here for this holder to release directly.
async function captureAndReleaseAcpxRuntimeSandboxRootGate(
  gatePath: string,
  ownContent: string,
): Promise<AcpxRuntimeSandboxRootGateCaptureOutcome> {
  const capturePath = `${gatePath}${ACPX_SANDBOX_ROOT_GATE_REAP_INFIX}${process.pid}-${randomBytes(8).toString("hex")}`;
  try {
    await rename(gatePath, capturePath);
  } catch (error) {
    // Nothing at the shared path to release directly.
    if (errorCode(error) === "ENOENT") return "absent";
    throw error;
  }
  const contents = await readFile(capturePath, "utf8").catch((error) => {
    if (errorCode(error) === "ENOENT") return null;
    throw error;
  });
  if (contents === ownContent) {
    await unlink(capturePath).catch((error) => {
      if (errorCode(error) !== "ENOENT") throw error;
    });
    return "released";
  }
  // The rename caught a gate that is not this holder's own: a different
  // claimant's gate was at the shared path. Put it straight back, unless a
  // further claimant has since taken the now-momentarily-empty shared path.
  try {
    await link(capturePath, gatePath);
  } catch (error) {
    if (errorCode(error) !== "EEXIST") throw error;
    // A further claimant grabbed the shared path first: leave the captured
    // gate under its own private name rather than clobber that claim. Its
    // real owner's own release finds it later, by content, the same way
    // this call looks for its own gate below.
    return "displaced";
  }
  await unlink(capturePath).catch((error) => {
    if (errorCode(error) !== "ENOENT") throw error;
  });
  return "displaced";
}

// Finds and removes any reap-named capture of `gatePath` whose content
// matches `ownContent`, so a stale-gate recovery holding that exact capture
// cannot restore it after this holder has already moved on.
async function reclaimAcpxRuntimeSandboxRootGateCapture(
  gatePath: string,
  ownContent: string,
): Promise<void> {
  const directory = dirname(gatePath);
  const prefix = `${basename(gatePath)}${ACPX_SANDBOX_ROOT_GATE_REAP_INFIX}`;
  let entries: string[];
  try {
    entries = await readdir(directory);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return;
    throw error;
  }
  for (const entry of entries) {
    if (!entry.startsWith(prefix)) continue;
    const capturePath = join(directory, entry);
    const contents = await readFile(capturePath, "utf8").catch((error) => {
      if (errorCode(error) === "ENOENT") return null;
      throw error;
    });
    if (contents !== ownContent) continue;
    await unlink(capturePath).catch((error) => {
      if (errorCode(error) !== "ENOENT") throw error;
    });
  }
}

// Serializes stale-gate recovery attempts for one gate across every Runner
// process, using a single well-known lock path (not a random one, unlike
// every other private path this file creates), so at most one admission
// ever runs `breakStaleAcpxRuntimeSandboxRootGate` for a given gate at a
// time.
//
// Without this lock, two admissions can independently pin the same dead
// gate, both prove its holder dead, and both proceed to remove it. The
// first admission's removal atomically vacates the shared path and deletes
// the dead gate for good. In the instant the shared path is vacant, a fresh
// claimant can win it with its own live gate — before the SECOND admission
// even runs its own removal. That second admission's removal then captures
// the fresh claimant's live gate instead of the dead one it pinned, so it
// must vacate the shared path again to inspect what it caught, and restore
// it once it proves the capture is not its own. That second vacate-then
// -restore step is itself a fresh window: a further claimant can win the
// shared path inside it and start running its own critical section fully
// concurrently with the live holder recovery just displaced, defeating the
// exclusivity this whole gate exists to give.
//
// Serializing recovery closes this at the source: only one admission is
// ever mid-recovery for a given gate, so its own removal step is always
// the very first thing to touch the shared path since it proved that gate
// stale. Nothing else can have replaced the gate in between, so its removal
// always captures the exact dead gate it pinned, and the vacate-then-restore
// case this lock protects against becomes unreachable in production — kept
// here only as a defensive fallback. This guarantee depends on the lock
// itself never being broken out from under a still-recovering holder; see
// `breakStaleAcpxRuntimeSandboxRootGateRecoveryLock` for how the lock's own
// stale-break stays safe under a second, concurrent admission.
//
// The lock itself only guards a short run of local filesystem calls, never
// blocking I/O on another process, so a live lock holder always finishes
// well inside `ACPX_SANDBOX_ROOT_GATE_RECOVERY_LOCK_STALE_MS`. A lock still
// held past that age can only mean its own holder crashed mid-recovery;
// this call then breaks it so a later attempt is not blocked forever by a
// lock its own holder can never release — see
// `breakStaleAcpxRuntimeSandboxRootGateRecoveryLock` for why that break must
// remove only the exact lock instance this call observed, never a
// replacement a later admission has since acquired.
async function withAcpxRuntimeSandboxRootGateRecoveryLock(
  gatePath: string,
  dependencies: AcpxRuntimeSandboxRootGateDependencies,
  recovery: () => Promise<void>,
): Promise<void> {
  const lockPath = `${gatePath}${ACPX_SANDBOX_ROOT_GATE_RECOVERY_LOCK_SUFFIX}`;
  let handle: FileHandle;
  try {
    handle = await open(
      lockPath,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      PRIVATE_FILE_MODE,
    );
  } catch (error) {
    if (errorCode(error) !== "EEXIST") throw error;
    // Another admission is already recovering this gate. Break the lock
    // only once it is provably stale, and either way, back off for this
    // call: attempting the gate's own recovery here too is exactly the race
    // this lock exists to prevent. A lock broken here lets the NEXT retry in
    // `withAcpxRuntimeSandboxRootGate`'s loop acquire it cleanly, instead of
    // this call racing a second recovery attempt into the same gate.
    await breakStaleAcpxRuntimeSandboxRootGateRecoveryLock(
      lockPath,
      dependencies,
    );
    return;
  }
  // Pin this exact lock instance under a private path this holder alone
  // controls, for as long as it holds the lock. A plain device-and-inode
  // check taken now and compared again at release time would not be safe on
  // its own: if a stale-lock break removes the shared name out from under
  // this holder in between, the filesystem can reuse the just-freed inode
  // number for an unrelated replacement lock (observed on this file's own
  // tmp filesystem, the same hazard the gate's own identity checks already
  // guard against), so a replacement could carry the very same identity the
  // removed lock had. This extra link keeps that exact inode allocated for
  // as long as the pin survives, so its device and inode can never be
  // confused with a later, unrelated file's — the pin is this holder's own
  // private name, so no break or release anywhere else in this file ever
  // touches it, and only this holder's own release removes it.
  const ownPinPath = `${lockPath}${ACPX_SANDBOX_ROOT_GATE_RECOVERY_LOCK_PIN_INFIX}${process.pid}-${randomBytes(8).toString("hex")}`;
  let ownEntry: BigIntStats;
  try {
    await handle.chmod(PRIVATE_FILE_MODE);
    await link(lockPath, ownPinPath);
    ownEntry = await lstat(ownPinPath, { bigint: true });
  } finally {
    await handle.close();
  }
  try {
    await dependencies.afterRecoveryLockAcquired?.();
    await recovery();
  } finally {
    await releaseAcpxRuntimeSandboxRootGateRecoveryLock(
      lockPath,
      ownPinPath,
      ownEntry,
    );
  }
}

// Releases this holder's own recovery lock. This must remove only the exact
// lock instance this holder acquired, never a replacement a later admission
// has since acquired at the same path — so a plain, unconditional
// `unlink(lockPath)` is never safe here. `breakStaleAcpxRuntimeSandboxRootGateRecoveryLock`
// can judge this holder's own still-live lock stale (its own stale threshold
// is a heuristic, not a proof of death) and remove it while this holder is
// still genuinely mid-recovery; a later admission can then win a fresh lock
// of its own at the now-vacant path before this holder's recovery finishes.
// From this holder's point of view, by the time it releases, `lockPath` can
// therefore name either its own lock (the common case) or a different
// admission's live replacement — an unconditional unlink cannot tell these
// apart, and would delete that replacement right along with its own,
// letting a third admission win a fresh lock and run its own recovery
// concurrently with whichever admission the replacement belongs to.
//
// This call instead captures whatever currently names `lockPath` with the
// same atomic `rename` stale-lock recovery uses, then proceeds only by the
// identity `ownPinPath` still pins: a match proves this call caught its own
// lock, safe to delete for good; a mismatch means a different admission's
// live lock was caught by mistake, so this call restores it immediately
// with `link`, not `rename`, so a further admission that has since taken
// the now-momentarily-empty shared path is never clobbered by the restore.
// Either way, this holder's own pin is no longer needed once the shared
// path is no longer its concern, so this call always releases it last.
async function releaseAcpxRuntimeSandboxRootGateRecoveryLock(
  lockPath: string,
  ownPinPath: string,
  ownEntry: BigIntStats,
): Promise<void> {
  try {
    const capturePath = `${lockPath}${ACPX_SANDBOX_ROOT_GATE_REAP_INFIX}${process.pid}-${randomBytes(8).toString("hex")}`;
    try {
      await rename(lockPath, capturePath);
    } catch (error) {
      // Nothing at the shared path to release directly.
      if (errorCode(error) === "ENOENT") return;
      throw error;
    }
    const capturedEntry = await lstat(capturePath, { bigint: true }).catch(
      (error) => {
        if (errorCode(error) === "ENOENT") return null;
        throw error;
      },
    );
    if (capturedEntry === null) {
      // The capture is gone already: `capturePath` is a private path only
      // this call knows, so nothing else should ever remove it, but this
      // is defensive against that regardless.
      return;
    }
    if (
      capturedEntry.dev === ownEntry.dev &&
      capturedEntry.ino === ownEntry.ino
    ) {
      await unlink(capturePath).catch((error) => {
        if (errorCode(error) !== "ENOENT") throw error;
      });
      return;
    }
    // The rename caught a lock that is not this holder's own: a different
    // admission's live lock was at the shared path. Put it straight back,
    // unless a further admission has since taken the now-momentarily-empty
    // shared path.
    try {
      await link(capturePath, lockPath);
    } catch (error) {
      if (errorCode(error) !== "EEXIST") throw error;
      // A further admission grabbed the shared path first: leave the
      // captured lock under its own private name rather than clobber that
      // claim. Its real owner's own release finds it later, the same way
      // this call would have found its own lock above.
      return;
    }
    await unlink(capturePath).catch((error) => {
      if (errorCode(error) !== "ENOENT") throw error;
    });
  } finally {
    await unlink(ownPinPath).catch((error) => {
      if (errorCode(error) !== "ENOENT") throw error;
    });
  }
}

// Removes a stale-gate recovery lock left behind by an attempt that crashed
// mid-recovery, so a lock its own holder can never release does not block
// every later admission for this root forever.
//
// A plain `stat`-then-`unlink` cannot break the lock safely: whatever this
// call reads to judge its age, a later, separate `unlink` call still removes
// whatever the path names at that later moment, not what this call read. If
// the observed holder finishes and releases its lock in that exact gap, and
// a fresh admission then wins the now-vacant path with its own new recovery
// attempt, the pathname `unlink` removes that fresh, live lock right along
// with the stale one — letting a second recovery run concurrently with the
// first and reopening the exact gate-displacement race this lock exists to
// close. See `breakStaleAcpxRuntimeSandboxRootGate` for the same class of
// bug already fixed once, on the gate file itself.
//
// This call instead pins whatever currently occupies `lockPath` with an
// extra `link` first, so the shared path is never vacated while it judges
// the pinned copy's age. Only once that pinned copy is old enough that its
// own holder must have crashed mid-recovery does this call remove the lock
// — and even then, only by capturing whatever the shared path names with one
// atomic `rename`, then comparing what it caught against the pinned
// identity: a match proves it caught the same lock it already judged stale,
// safe to delete for good. A mismatch means a fresh attempt already won the
// lock in the gap between the pin and this removal, so this call restores it
// immediately with `link`, not `rename` — `link` fails instead of silently
// overwriting a further attempt that has since taken the momentarily empty
// path first.
async function breakStaleAcpxRuntimeSandboxRootGateRecoveryLock(
  lockPath: string,
  dependencies: AcpxRuntimeSandboxRootGateDependencies,
): Promise<void> {
  const capturePath = `${lockPath}${ACPX_SANDBOX_ROOT_GATE_REAP_INFIX}${process.pid}-${randomBytes(8).toString("hex")}`;
  try {
    await link(lockPath, capturePath);
  } catch (error) {
    // Missing already: nothing to break.
    if (errorCode(error) === "ENOENT") return;
    throw error;
  }
  try {
    const pinnedEntry = await lstat(capturePath, { bigint: true });
    const ageMs = Date.now() - Number(pinnedEntry.mtimeMs);
    if (ageMs < ACPX_SANDBOX_ROOT_GATE_RECOVERY_LOCK_STALE_MS) {
      // Young enough that its own holder could still legitimately be
      // mid-recovery: leave it alone.
      return;
    }
    await dependencies.afterRecoveryLockStaleCapture?.();
    const removalPath = `${lockPath}${ACPX_SANDBOX_ROOT_GATE_REAP_INFIX}${process.pid}-${randomBytes(8).toString("hex")}`;
    try {
      await rename(lockPath, removalPath);
    } catch (error) {
      // Already gone: nothing to remove.
      if (errorCode(error) === "ENOENT") return;
      throw error;
    }
    const capturedEntry = await lstat(removalPath, { bigint: true });
    if (
      capturedEntry.dev === pinnedEntry.dev &&
      capturedEntry.ino === pinnedEntry.ino
    ) {
      // The rename caught the exact stale lock this call already judged
      // old: safe to delete for good.
      await unlink(removalPath).catch((error) => {
        if (errorCode(error) !== "ENOENT") throw error;
      });
      return;
    }
    // The rename caught a fresh lock a new recovery attempt has since put at
    // the shared path: put it straight back, unless a further attempt has
    // taken the now-momentarily-empty shared path first.
    try {
      await link(removalPath, lockPath);
    } catch (error) {
      if (errorCode(error) !== "EEXIST") throw error;
      return;
    }
    await unlink(removalPath).catch((error) => {
      if (errorCode(error) !== "ENOENT") throw error;
    });
  } finally {
    await unlink(capturePath).catch((error) => {
      if (errorCode(error) !== "ENOENT") throw error;
    });
  }
}

// Removes a gate file left behind by a holder process that no longer exists,
// so a hard process crash inside the critical section cannot block every
// later admission for this root forever. Never removes a gate whose holder
// is still alive, and never makes the shared path briefly name nothing — a
// live holder's gate must stay exclusive at the shared path for as long as
// that holder keeps it there.
//
// A gate can also carry no readable pid at all. Its holder always writes
// the pid and token to a private staging path in full, then publishes that
// content to the shared path with one atomic `link` — see
// `acquireAcpxRuntimeSandboxRootGate` — so a gate that names the shared
// path never starts out empty, no matter how long its holder's write took.
// An unreadable gate therefore means its content was lost or damaged after
// publication, not that its holder is still writing it. This call cannot
// check a dead-or-alive pid it cannot read, so it instead falls back to the
// gate's own age, purely as a safety net against that damage: a gate with
// no readable pid, still that way after `ACPX_SANDBOX_ROOT_GATE_INIT_GRACE_MS`
// has passed since its creation, is treated the same as a gate whose holder
// proved dead. A gate younger than that grace period is left alone, the
// same as a gate a live holder still owns.
//
// A plain read-then-unlink cannot inspect and remove safely: whatever this
// call reads to confirm identity, a later, separate unlink call still
// removes the file the path names at that later moment, not the file this
// call read. Two calls can never be made atomic by re-reading closer to the
// unlink; the gap only shrinks, it does not close. An earlier version of
// this function closed that gap by capturing the gate with `rename` before
// inspecting it — but `rename` vacates the shared path for the whole
// inspection, and a fresh claimant that creates a new gate in that gap is
// left believing it holds exclusivity while a delayed restore can still
// silently take its place, or a delayed restore can find the path already
// claimed and abandon the gate it captured, orphaning whichever holder
// created that original gate.
//
// This function instead pins whatever currently occupies the shared path
// with an extra `link` first. Unlike `rename`, `link` adds a second name for
// the same inode without ever removing the first, so the shared path is
// never vacated while this call decides whether the holder is dead: a
// genuinely live holder's gate stays exclusive there for the holder's entire
// critical section, no matter how this call's inspection of its own pinned
// copy turns out. The pin also keeps that exact inode alive for as long as
// this call holds it, so a later identity check against it can never be
// confused by a filesystem reusing a freed inode number for an unrelated new
// file at the same path — the well-known hazard a bare device-and-inode
// check runs into (observed on ext4).
//
// Once this call has proved, from its own pinned copy, that the holder is
// dead, it still must remove only that exact dead gate, never a fresh one
// that has since replaced it. A separate identity check followed by a
// separate pathname `unlink` cannot prove that: whatever the check reads,
// the `unlink` call still removes whatever the path names at its own later
// moment, not what the check read, so a fresh claimant's gate landing in
// that gap is removed right along with the dead one. This call closes that
// gap by combining the check and the removal into one `rename`, which
// atomically vacates the shared path and pulls in whatever it named at that
// exact instant. Only after the rename does this call compare what it
// caught against the pinned identity: a match proves it caught the same
// dead gate it already proved stale, safe to delete for good. A mismatch
// means a fresh claimant's gate was caught instead, so this call restores it
// immediately with `link`, not `rename` — `link` fails instead of silently
// overwriting a third claimant that grabbed the momentarily empty path
// first, so that third claimant's own gate is never clobbered by the
// restore, and the caught gate is kept under its own private name rather
// than lost.
async function breakStaleAcpxRuntimeSandboxRootGate(
  gatePath: string,
  dependencies: AcpxRuntimeSandboxRootGateDependencies = {},
): Promise<void> {
  const capturePath = `${gatePath}${ACPX_SANDBOX_ROOT_GATE_REAP_INFIX}${process.pid}-${randomBytes(8).toString("hex")}`;
  try {
    await link(gatePath, capturePath);
  } catch (error) {
    // Missing already: nothing to break.
    if (errorCode(error) === "ENOENT") return;
    throw error;
  }
  try {
    const pinnedEntry = await lstat(capturePath, { bigint: true });
    let holderPid: number | null;
    try {
      const bytes = await readFile(capturePath);
      const contents = bytes.toString("utf8").trim();
      const parsed = Number.parseInt(contents, 10);
      holderPid = Number.isInteger(parsed) && parsed > 0 ? parsed : null;
    } catch {
      // Unreadable: nothing provable to break here.
      return;
    }
    if (holderPid !== null) {
      if (isAcpxSandboxRootGateHolderAlive(holderPid)) {
        return;
      }
    } else {
      // Empty or malformed: no pid to check. Wait out the grace period
      // instead, so a holder still writing its pid keeps its gate.
      const ageMs = Date.now() - Number(pinnedEntry.mtimeMs);
      if (ageMs < ACPX_SANDBOX_ROOT_GATE_INIT_GRACE_MS) {
        return;
      }
    }
    await dependencies.beforeStaleGateRemoval?.();
    await removeStaleAcpxRuntimeSandboxRootGate(
      gatePath,
      pinnedEntry,
      dependencies,
    );
  } finally {
    await unlink(capturePath).catch((error) => {
      if (errorCode(error) !== "ENOENT") throw error;
    });
  }
}

// Removes the shared gate at `gatePath`, but only the exact dead gate
// `pinnedEntry` already proved stale, never a fresh gate that has since
// replaced it. `rename` atomically vacates the shared path and captures
// whatever it named at that instant, in one call, so there is no separate
// moment between an identity check and a removal for a fresh claimant's
// gate to land in.
async function removeStaleAcpxRuntimeSandboxRootGate(
  gatePath: string,
  pinnedEntry: BigIntStats,
  dependencies: AcpxRuntimeSandboxRootGateDependencies,
): Promise<void> {
  const removalPath = `${gatePath}${ACPX_SANDBOX_ROOT_GATE_REAP_INFIX}${process.pid}-${randomBytes(8).toString("hex")}`;
  try {
    await rename(gatePath, removalPath);
  } catch (error) {
    // Already gone: nothing to remove.
    if (errorCode(error) === "ENOENT") return;
    throw error;
  }
  const capturedEntry = await lstat(removalPath, { bigint: true });
  if (
    capturedEntry.dev === pinnedEntry.dev &&
    capturedEntry.ino === pinnedEntry.ino
  ) {
    // The rename caught the exact dead gate this call already proved
    // stale: safe to delete for good.
    await unlink(removalPath).catch((error) => {
      if (errorCode(error) !== "ENOENT") throw error;
    });
    return;
  }
  // The rename caught a live replacement a fresh claimant put at the shared
  // path after this call proved the original dead: put it straight back,
  // unless that claimant's own critical section has since ended. Restoring
  // a gate after its holder is done would resurrect it: the holder's own
  // release finds nothing at `gatePath` to unlink (this rename already
  // moved it away), so it reclaims `removalPath` directly by content
  // instead (see `releaseAcpxRuntimeSandboxRootGate`). A `link` failing
  // with ENOENT here means that reclaim already won this race, so there is
  // nothing left to restore.
  await dependencies.afterStaleGateCapture?.();
  try {
    await link(removalPath, gatePath);
  } catch (error) {
    const code = errorCode(error);
    if (code === "ENOENT") {
      // The claimant already finished and reclaimed its own gate out from
      // under this capture: its critical section is over, so leaving the
      // shared path empty is correct, not a leak.
      return;
    }
    if (code !== "EEXIST") throw error;
    // A third claimant grabbed the shared path in the brief moment this
    // call's rename vacated it, before the restore could land. That
    // claimant's gate must not be clobbered, so the caught gate is left
    // behind under its own private name instead of being forced back or
    // deleted.
    return;
  }
  await unlink(removalPath).catch((error) => {
    if (errorCode(error) !== "ENOENT") throw error;
  });
}

function isAcpxSandboxRootGateHolderAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // ESRCH proves the process is gone. Any other outcome (for example
    // EPERM) cannot prove that, so treat the holder as still alive.
    return errorCode(error) !== "ESRCH";
  }
}

function delay(timeoutMs: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, timeoutMs));
}

function reportDeclinedAcpxSandboxRootClaim(root: string): void {
  process.emitWarning(
    JSON.stringify({
      schema: "paperclip.runner.acpx_sandbox_root_claim_declined.v1",
      root,
    }),
    {
      code: "PAPERCLIP_ACPX_SANDBOX_ROOT_CLAIM_DECLINED",
      type: "PaperclipRunnerSandboxWarning",
    },
  );
}

async function claimAcpxRuntimeSandboxRoot(
  root: string,
  dependencies: AcpxRuntimeSandboxRootGateDependencies = {},
): Promise<AcpxRuntimeSandboxRootOwner> {
  const entry = await lstat(root, { bigint: true });
  if (entry.isSymbolicLink() || !entry.isDirectory()) {
    throw new Error("ACPX sandbox root must be a real directory");
  }
  const markerPath = acpxRuntimeSandboxRootMarkerPath(root);
  const identifier = randomBytes(16).toString("hex");
  const owner: AcpxRuntimeSandboxRootOwner = {
    root,
    markerPath,
    identifier,
    dev: entry.dev,
    ino: entry.ino,
  };
  // The marker write and the lease registration run as one gated step, so a
  // concurrent teardown's lease count can never land between them and miss
  // this admission's occupancy.
  const claimed = await withAcpxRuntimeSandboxRootGate(
    root,
    async () => {
      const won = await writeAcpxSandboxRootMarkerExclusive(
        markerPath,
        identifier,
      );
      // Register this admission's own durable lease before returning,
      // whether or not it won the marker, so its occupancy is visible to
      // any process that later reads the root's leases — including this
      // one.
      await registerAcpxRuntimeSandboxRootLease(root, identifier);
      return won;
    },
    dependencies,
  );
  if (!claimed) {
    // Another admission already owns this deterministic root. Continue
    // without delete authority: never overwrite its marker, never touch the
    // in-process registry, never delete the root, and never fail this
    // admission — two admissions may legitimately share one session root.
    reportDeclinedAcpxSandboxRootClaim(root);
    return owner;
  }
  acpxRuntimeSandboxRootOwners.set(root, owner);
  return owner;
}

/**
 * Delete a sandbox root through the exact ownership capability that created
 * it. Proves ownership by reading the marker file back and comparing its
 * identifier, so the proof holds across two Runner processes, then
 * revalidates the root's directory identity. A missing marker, a mismatched
 * identifier, a changed identity, or another admission still sharing the
 * root — proved by a durable lease file, so a sharing admission in a
 * different process is seen too — means: delete nothing.
 *
 * The lease read, the identity revalidation, and the resulting delete or
 * retain all run as one gated step, so no claim can register a new lease in
 * the gap between this admission counting leases and acting on that count.
 */
async function revalidateAndRemoveOwnedAcpxRuntimeSandboxRoot(
  root: string,
  owner: AcpxRuntimeSandboxRootOwner,
  dependencies: AcpxRuntimeSandboxRootTeardownDependencies = {},
): Promise<void> {
  await withAcpxRuntimeSandboxRootGate(root, async () => {
    // This admission's own use of the root ends here, whether or not it goes
    // on to hold delete authority.
    await releaseAcpxRuntimeSandboxRootLease(root, owner.identifier);

    const storedIdentifier = await readAcpxSandboxRootMarkerIdentifier(
      owner.markerPath,
    );
    if (storedIdentifier !== owner.identifier) {
      // A missing marker or a different identifier means another admission
      // owns (or once owned) this root, or this admission's own claim was
      // declined. Either way, delete nothing.
      if (acpxRuntimeSandboxRootOwners.get(root) === owner) {
        acpxRuntimeSandboxRootOwners.delete(root);
      }
      return;
    }
    let entry: BigIntStats;
    try {
      entry = await lstat(root, { bigint: true });
    } catch (error) {
      if (errorCode(error) === "ENOENT") {
        acpxRuntimeSandboxRootOwners.delete(root);
        return;
      }
      throw error;
    }
    if (
      entry.isSymbolicLink() ||
      !entry.isDirectory() ||
      entry.dev !== owner.dev ||
      entry.ino !== owner.ino
    ) {
      throw new Error("ACPX sandbox root identity changed before cleanup");
    }
    if (
      (await countOtherAcpxRuntimeSandboxRootLeases(root, owner.identifier)) >
      0
    ) {
      // Another admission — possibly in a different Runner process — built a
      // live sandbox on this same root and has not yet released its lease.
      // Leave the root, the marker, and the registry entry alone: the
      // failure mode is a retained directory, never a deleted live one.
      return;
    }
    await dependencies.afterLeaseCountDecision?.();
    await rm(root, { recursive: true });
    await unlink(owner.markerPath).catch((error) => {
      if (errorCode(error) !== "ENOENT") throw error;
    });
    if (acpxRuntimeSandboxRootOwners.get(root) === owner) {
      acpxRuntimeSandboxRootOwners.delete(root);
    }
  });
}

export interface AcpxRuntimeSandboxRootTeardownDependencies {
  /**
   * Internal test seam. Runs inside the root's ownership gate, once this
   * admission has decided to act (delete the root, or free the marker) and
   * before it does so.
   */
  afterLeaseCountDecision?: () => Promise<void>;
}

/**
 * Remove a sandbox root through the exact ownership capability that created
 * it. Refuses the delete when this admission never proved ownership of the
 * marker, or a later admission has since claimed the same deterministic
 * path, or the identity no longer matches.
 */
export async function removeOwnedAcpxRuntimeSandboxRoot(
  sandbox: AcpxRuntimeSandbox,
  dependencies: AcpxRuntimeSandboxRootTeardownDependencies = {},
): Promise<void> {
  const owner = acpxRuntimeSandboxRootOwnerByResult.get(sandbox);
  if (!owner) {
    throw new Error("ACPX sandbox root ownership capability is unavailable");
  }
  await revalidateAndRemoveOwnedAcpxRuntimeSandboxRoot(
    owner.root,
    owner,
    dependencies,
  );
}

/**
 * Release this admission's own claim on a sandbox root without removing the
 * root itself. Call this when an admission's own use of the root ends,
 * whether it holds the marker or was declined, so a later admission for the
 * same deterministic session root can claim the marker and, if it later
 * aborts, clean up its own attempt.
 *
 * The marker is freed when this admission is the last one still using the
 * root: after this admission's own lease is released, no other admission's
 * durable lease remains on it. Freeing the marker only then means a
 * still-live admission — the marker owner, or a declined admission sharing
 * the root in a different Runner process — always keeps its claim
 * recognized until it too closes. Which admission is recorded as the
 * marker's owner does not decide who may free it: the owner may close
 * first and leave a declined admission as the last one still using the
 * root, and that declined admission must still be able to free the marker
 * when its own turn comes. When another lease remains, the marker stays in
 * place and the root stays reachable only to admissions that share it; the
 * marker then remains stale until an existing recovery process reclaims
 * it, the same accepted failure mode as a marker left by a hard process
 * crash.
 *
 * The lease read, the lease count, and the resulting marker release all run
 * as one gated step, so no claim can register a new lease in the gap
 * between this admission counting leases and freeing the marker.
 */
export async function releaseAcpxRuntimeSandboxRootClaim(
  sandbox: AcpxRuntimeSandbox,
  dependencies: AcpxRuntimeSandboxRootTeardownDependencies = {},
): Promise<void> {
  const owner = acpxRuntimeSandboxRootOwnerByResult.get(sandbox);
  if (!owner) {
    throw new Error("ACPX sandbox root ownership capability is unavailable");
  }
  await withAcpxRuntimeSandboxRootGate(owner.root, async () => {
    // This admission's own use of the root ends here.
    await releaseAcpxRuntimeSandboxRootLease(owner.root, owner.identifier);

    const storedIdentifier = await readAcpxSandboxRootMarkerIdentifier(
      owner.markerPath,
    );
    // Freeing the marker does not require this admission's own identifier to
    // match it: the marker owner may already have closed and left a
    // declined admission as the root's last occupant, and that declined
    // admission must still be able to free the marker on its own close.
    const freeable =
      storedIdentifier !== null &&
      (await countOtherAcpxRuntimeSandboxRootLeases(
        owner.root,
        owner.identifier,
      )) === 0;
    if (freeable) {
      await dependencies.afterLeaseCountDecision?.();
      await unlink(owner.markerPath).catch((error) => {
        if (errorCode(error) !== "ENOENT") throw error;
      });
    }
    if (acpxRuntimeSandboxRootOwners.get(owner.root) === owner) {
      acpxRuntimeSandboxRootOwners.delete(owner.root);
    }
  });
}

async function ensurePrivateDirectory(
  directory: string,
  physicalParent: string,
): Promise<string> {
  try {
    await mkdir(directory, { mode: PRIVATE_DIRECTORY_MODE });
  } catch (error) {
    if (errorCode(error) !== "EEXIST") throw error;
  }
  let handle: FileHandle;
  try {
    handle = await open(
      directory,
      constants.O_RDONLY |
        (constants.O_DIRECTORY ?? 0) |
        (constants.O_NOFOLLOW ?? 0),
    );
  } catch {
    throw new Error("ACPX sandbox path must be a real directory");
  }
  let physical: string;
  try {
    const opened = await handle.stat();
    const entry = await lstat(directory);
    if (
      !opened.isDirectory() ||
      entry.isSymbolicLink() ||
      !entry.isDirectory() ||
      !sameFile(entry, opened)
    ) {
      throw new Error("ACPX sandbox path must be a real directory");
    }
    // Apply permissions to the inode that was opened without following links.
    // A directory-entry swap can therefore never redirect chmod to its target.
    await handle.chmod(PRIVATE_DIRECTORY_MODE);
    physical = await realpath(directory);
    const verifiedEntry = await lstat(directory);
    if (!sameFile(verifiedEntry, opened)) {
      throw new Error("ACPX sandbox directory changed during preparation");
    }
    if (!isInside(physicalParent, physical)) {
      throw new Error("ACPX sandbox directory escaped its private parent");
    }
    // Persist the child inode before the directory entry that names it.
    if (process.platform !== "win32") await handle.sync();
  } finally {
    await handle.close();
  }
  // Sync the parent even during recovery: an earlier process may have created
  // the entry and crashed before making that mkdir durable.
  await syncDirectory(physicalParent);
  return physical;
}

async function writePrivateFile(
  filePath: string,
  value: string,
): Promise<void> {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length < 1 || bytes.length > 64 * 1024) {
    throw new Error("ACPX sandbox file exceeds its bounded size");
  }
  const temporaryPath = `${filePath}.tmp-${randomBytes(12).toString("hex")}`;
  let handle: FileHandle;
  try {
    handle = await open(
      temporaryPath,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      PRIVATE_FILE_MODE,
    );
  } catch {
    throw new Error("ACPX sandbox file could not be opened without links");
  }
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile()) throw new Error("ACPX sandbox path is not a file");
    await handle.chmod(PRIVATE_FILE_MODE);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    await rename(temporaryPath, filePath);
    await syncDirectory(dirname(filePath));
    return;
  } finally {
    bytes.fill(0);
    await handle.close().catch(() => undefined);
    await unlink(temporaryPath).catch(() => undefined);
  }
}

async function syncDirectory(directory: string): Promise<void> {
  if (process.platform === "win32") return;
  const handle = await open(
    directory,
    constants.O_RDONLY | (constants.O_DIRECTORY ?? 0),
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function validateEnvironmentSize(environment: NodeJS.ProcessEnv): void {
  const bytes = Object.entries(environment).reduce(
    (total, [name, value]) =>
      total + Buffer.byteLength(name) + Buffer.byteLength(value ?? ""),
    0,
  );
  if (bytes > MAX_SANDBOX_ENVIRONMENT_BYTES) {
    throw new Error("ACPX launch environment exceeds its bounded size");
  }
}

function isPersistableEnvironmentName(name: string): boolean {
  return (
    /^(?:PATH|LANG|LANGUAGE|TZ|TMPDIR|TEMP|TMP|LC_[A-Z0-9_]{1,32})$/.test(
      name,
    ) ||
    /^(?:HOME|XDG_CONFIG_HOME|XDG_DATA_HOME|XDG_CACHE_HOME)$/.test(name) ||
    /^(?:PAPERCLIP_ACPX_PROFILE|PAPERCLIP_ACPX_ISOLATED_CONTEXT)$/.test(name) ||
    /^(?:PI_CODING_AGENT_DIR|PI_SKIP_VERSION_CHECK|PI_TELEMETRY)$/.test(name) ||
    /^(?:CLAUDE_CONFIG_DIR|CODEX_HOME|NO_BROWSER|DEFAULT_AUTH_REQUEST)$/.test(
      name,
    )
  );
}

function isInside(parent: string, child: string): boolean {
  const childPath = relative(parent, child);
  return (
    childPath.length > 0 &&
    childPath !== ".." &&
    !childPath.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) &&
    !isAbsolute(childPath)
  );
}

function sameFile(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function errorCode(error: unknown): string | null {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code?: unknown }).code)
    : null;
}
