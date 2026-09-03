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
  stat,
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
   * Internal test seam. Runs after stale-gate recovery has read a gate file
   * and proved its holder is dead, immediately before recovery renames the
   * gate to a private path to inspect and remove it. Lets a test replace
   * the gate at the shared path in that gap, to prove recovery only ever
   * removes the exact gate instance it inspected — never a replacement.
   */
  beforeStaleGateRemoval?: () => Promise<void>;
  /**
   * Internal test seam. Runs after stale-gate recovery has renamed a gate
   * to a private path and found its bytes do not match the dead gate it
   * inspected, immediately before recovery links that captured file back
   * onto the shared path. Lets a test create a fresh gate at the shared
   * path in that gap, to prove the restore never overwrites it.
   */
  beforeStaleGateRestore?: () => Promise<void>;
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
  beforeStaleGateRemoval?: () => Promise<void>;
  beforeStaleGateRestore?: () => Promise<void>;
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
    if (await acquireAcpxRuntimeSandboxRootGate(gatePath)) {
      try {
        return await criticalSection();
      } finally {
        await unlink(gatePath).catch((error) => {
          if (errorCode(error) !== "ENOENT") throw error;
        });
      }
    }
    // The gate is held by another admission. Break it only when that holder
    // is provably gone (a crashed process), never on a mere timeout, so a
    // slow-but-live holder is never pre-empted.
    await breakStaleAcpxRuntimeSandboxRootGate(gatePath, dependencies);
    if (Date.now() >= deadline) {
      throw new Error(
        "ACPX sandbox root ownership gate could not be acquired",
      );
    }
    await delay(ACPX_SANDBOX_ROOT_GATE_RETRY_DELAY_MS);
  }
}

async function acquireAcpxRuntimeSandboxRootGate(
  gatePath: string,
): Promise<boolean> {
  let handle: FileHandle;
  try {
    handle = await open(
      gatePath,
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
    // The holder pid, plus a random per-acquisition token so this exact
    // gate instance can be told apart from a same-pid replacement created
    // at the same path later. A device-and-inode check cannot do this: a
    // delete immediately followed by a create at the same path can reuse
    // the just-freed inode number on some filesystems (observed on ext4),
    // so a replacement gate can carry the very same identity the deleted
    // one had.
    await handle.writeFile(
      `${process.pid}:${randomBytes(16).toString("hex")}`,
      "utf8",
    );
    await handle.sync();
  } finally {
    await handle.close();
  }
  return true;
}

// Removes a gate file left behind by a holder process that no longer exists,
// so a hard process crash inside the critical section cannot block every
// later admission for this root forever. Never removes a gate whose holder
// is still alive, or one this process cannot prove is dead.
//
// Another admission can replace the gate at this same path — release the
// stale one and create a fresh, live one — at any point after this call
// proves the original holder dead. A plain read-then-unlink cannot guard
// against this: whatever this call reads to confirm identity, a later,
// separate unlink call still removes the file the path names at that later
// moment, not the file this call read. Two calls can never be made atomic
// by re-reading closer to the unlink; the gap only shrinks, it does not
// close.
//
// So this function never unlinks the shared path directly. It first
// `rename`s the gate to a private path only this call knows, one syscall
// that always moves whatever the shared path currently names — never stale
// information this call read earlier. That syscall is the one and only
// place this call touches the shared path, so there is no later, separate
// step left for a replacement to land in front of. It then inspects the
// private copy at leisure:
// - If the bytes match the dead gate this call proved stale, the private
//   copy is that same dead gate; deleting it is always safe, because no
//   other admission can name a private path only this call knows.
// - If the bytes differ, this call's `rename` caught a live replacement
//   instead. It puts that replacement back with `link`, which — unlike
//   `rename` — fails instead of overwriting when the shared path already
//   names something else again, so a second replacement can never be
//   clobbered by a restore that arrives late.
//
// A device-and-inode check cannot stand in for the byte comparison above:
// deleting a file and immediately creating a new one at the same path can
// reuse the just-freed inode number on some filesystems, so a replacement
// gate can carry the very identity the deleted one had. The byte comparison
// instead keys on the holder pid plus the random per-acquisition token
// `acquireAcpxRuntimeSandboxRootGate` writes; a collision between two
// gates' random tokens is not a practical concern.
async function breakStaleAcpxRuntimeSandboxRootGate(
  gatePath: string,
  dependencies: AcpxRuntimeSandboxRootGateDependencies = {},
): Promise<void> {
  let holderPid: number | null = null;
  let inspectedContents: string;
  try {
    const handle = await open(
      gatePath,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    try {
      const bytes = await readFile(handle);
      inspectedContents = bytes.toString("utf8").trim();
      const parsed = Number.parseInt(inspectedContents, 10);
      holderPid = Number.isInteger(parsed) && parsed > 0 ? parsed : null;
    } finally {
      await handle.close();
    }
  } catch {
    // Missing, unreadable, or malformed: nothing provable to break here.
    return;
  }
  if (holderPid !== null && isAcpxSandboxRootGateHolderAlive(holderPid)) {
    return;
  }
  await dependencies.beforeStaleGateRemoval?.();

  const capturePath = `${gatePath}${ACPX_SANDBOX_ROOT_GATE_REAP_INFIX}${process.pid}-${randomBytes(8).toString("hex")}`;
  try {
    await rename(gatePath, capturePath);
  } catch (error) {
    // Gone already, or another recovery call reaped it first: nothing left
    // to break.
    if (errorCode(error) === "ENOENT") return;
    throw error;
  }

  const capturedContents = (await readFile(capturePath))
    .toString("utf8")
    .trim();
  if (capturedContents !== inspectedContents) {
    // This call's rename caught a live replacement, not the dead gate it
    // inspected. Put it back — unless a newer replacement already claims
    // the path, in which case leave that one alone and drop the copy this
    // call is holding.
    await dependencies.beforeStaleGateRestore?.();
    try {
      await link(capturePath, gatePath);
    } catch (error) {
      if (errorCode(error) !== "EEXIST") throw error;
    }
  }
  await unlink(capturePath).catch((error) => {
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
 * Release the delete-authority claim on a sandbox root without removing the
 * root itself. Call this when an admission that reached a live host ends,
 * so a later admission for the same deterministic session root can claim
 * the marker and, if it later aborts, clean up its own attempt. Without
 * this release, the marker would keep the previous admission's identifier
 * for the process lifetime and every later admission's own abort cleanup
 * would find a marker it can never match.
 *
 * The marker is freed only when no other admission still holds a durable
 * lease on this root. A declined admission — possibly in a different Runner
 * process — may still be using the root when the owner closes; freeing the
 * marker in that case would let a third admission claim it and later delete
 * the still-live root out from under that declined admission. When a lease
 * remains, the marker stays in place, and the root becomes reachable only
 * to admissions that share it; the marker then remains stale until an
 * existing recovery process reclaims it, the same accepted failure mode as
 * a marker left by a hard process crash.
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
    const freeable =
      storedIdentifier === owner.identifier &&
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
