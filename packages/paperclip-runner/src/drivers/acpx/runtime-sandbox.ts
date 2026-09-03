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
  lstat,
  mkdir,
  open,
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
  readonly token: symbol;
  readonly dev: bigint;
  readonly ino: bigint;
}

// The runtime root path is deterministic per normalized session id, so a
// path-only delete cannot prove a root still belongs to the admission that
// created it. Each successful claim registers the current owner here,
// keyed by root path. A later claim for the same path (a legitimate
// re-opened session) replaces the entry. Cleanup for a stale owner checks
// this registry and the captured directory identity before it deletes
// anything, so a superseded owner's cleanup leaves a live root alone.
const acpxRuntimeSandboxRootOwners = new Map<
  string,
  AcpxRuntimeSandboxRootOwner
>();

// Associates each returned sandbox object with the exact owner it was built
// under, without exposing the ownership token on the public sandbox shape.
const acpxRuntimeSandboxRootOwnerByResult = new WeakMap<
  AcpxRuntimeSandbox,
  AcpxRuntimeSandboxRootOwner & { readonly root: string }
>();

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
  // Claim ownership as soon as the root exists, before any slower step (a
  // credential write, a later directory sync) can run. A later admission for
  // the same deterministic path claims this same record and supersedes it;
  // an aborted admission's own late cleanup then finds it is no longer the
  // registered owner and leaves the live root alone.
  const owner = await claimAcpxRuntimeSandboxRoot(root);
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
    acpxRuntimeSandboxRootOwnerByResult.set(sandbox, { ...owner, root });
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

async function claimAcpxRuntimeSandboxRoot(
  root: string,
): Promise<AcpxRuntimeSandboxRootOwner> {
  const entry = await lstat(root, { bigint: true });
  if (entry.isSymbolicLink() || !entry.isDirectory()) {
    throw new Error("ACPX sandbox root must be a real directory");
  }
  const owner: AcpxRuntimeSandboxRootOwner = {
    token: Symbol("acpx-sandbox-root-owner"),
    dev: entry.dev,
    ino: entry.ino,
  };
  acpxRuntimeSandboxRootOwners.set(root, owner);
  return owner;
}

async function revalidateAndRemoveOwnedAcpxRuntimeSandboxRoot(
  root: string,
  owner: AcpxRuntimeSandboxRootOwner,
): Promise<void> {
  const current = acpxRuntimeSandboxRootOwners.get(root);
  if (current === undefined || current.token !== owner.token) {
    // A later admission has since claimed this deterministic root. It is
    // live; a superseded owner must never delete it.
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
  await rm(root, { recursive: true });
  if (acpxRuntimeSandboxRootOwners.get(root) === current) {
    acpxRuntimeSandboxRootOwners.delete(root);
  }
}

/**
 * Remove a sandbox root through the exact ownership capability that created
 * it. Revalidates the root's directory identity and refuses the delete when
 * a later admission has since claimed the same deterministic path or the
 * identity no longer matches.
 */
export async function removeOwnedAcpxRuntimeSandboxRoot(
  sandbox: AcpxRuntimeSandbox,
): Promise<void> {
  const owner = acpxRuntimeSandboxRootOwnerByResult.get(sandbox);
  if (!owner) {
    throw new Error("ACPX sandbox root ownership capability is unavailable");
  }
  await revalidateAndRemoveOwnedAcpxRuntimeSandboxRoot(owner.root, owner);
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
