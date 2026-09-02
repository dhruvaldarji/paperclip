import fs from "node:fs/promises";
import path from "node:path";
import { resolvePaperclipInstanceRootForAdapter } from "./server-utils.js";

// A credential copy-back writes real token bytes to its destination
// directory. This guard is the containment check that a copy-back target must
// pass before any write. It accepts only a directory under one company's own
// tree (`<instanceRoot>/companies/<companyId>`) and rejects everything else —
// an external path, a path under a different company, or a path that only
// looks contained until a symbolic link is followed.
//
// The rejection message is fixed text with no path and no identifier, so a
// log line built from it can never leak which company or which path a run
// tried to reach.
const REJECTED_CREDENTIAL_HOME_MESSAGE =
  "The credential home is outside the company-managed directory tree.";

/**
 * Thrown only for a containment rejection: a candidate directory outside the
 * company-managed tree, under the wrong company, or reached through a
 * symbolic link. A caller can catch this class alone to treat "not
 * contained" as benign, and let every other error (a permission fault, an
 * unexpected read fault) stay fail-loud. The message is fixed text with no
 * path and no identifier.
 */
export class ManagedCredentialHomeRejectedError extends Error {
  constructor() {
    super(REJECTED_CREDENTIAL_HOME_MESSAGE);
    this.name = "ManagedCredentialHomeRejectedError";
  }
}

function rejectCredentialHome(): never {
  throw new ManagedCredentialHomeRejectedError();
}

/** True when `segment` is exactly one path component: not empty, not `.` or `..`, and free of a path separator. */
function isSafePathSegment(segment: string): boolean {
  if (!segment) return false;
  if (segment === "." || segment === "..") return false;
  return !segment.includes("/") && !segment.includes("\\");
}

export interface AssertManagedCredentialHomeInput {
  env?: NodeJS.ProcessEnv;
  companyId: string;
  candidateDir: string;
}

export interface ManagedCredentialHomeBoundaryInput {
  env?: NodeJS.ProcessEnv;
  companyId: string;
}

/**
 * Resolves the real (symbolic-link-free) path of `candidateDir`. When the
 * directory does not exist yet, this walks up to the nearest existing
 * ancestor, resolves that ancestor's real path, and joins the still-missing
 * segments back on. This way a candidate a caller has not created yet still
 * gets a real prefix to check, and a symbolic link anywhere on an EXISTING
 * part of the path still resolves to its true target.
 */
async function resolveRealPathAllowingMissingSegments(candidateDir: string): Promise<string> {
  const resolved = path.resolve(candidateDir);
  const missingSegments: string[] = [];
  let current = resolved;
  for (;;) {
    try {
      const realAncestor = await fs.realpath(current);
      return missingSegments.length > 0
        ? path.join(realAncestor, ...missingSegments.reverse())
        : realAncestor;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const parent = path.dirname(current);
      if (parent === current) throw error;
      missingSegments.push(path.basename(current));
      current = parent;
    }
  }
}

/**
 * Resolves and verifies the one real directory a company's credential writes
 * may land under: `<realCompaniesRoot>/<companyId>`.
 *
 * Anchors on the real `companies` directory itself, not on the company
 * directory. An earlier design resolved the company directory in isolation;
 * when the logical company directory was itself a symbolic link, that
 * resolution and a candidate's resolution both landed on the same link
 * target, so containment passed when it should not have. Anchoring one
 * level up removes that blind spot: `companyId` is validated as one path
 * segment and then checked with a no-follow `lstat`, so a symbolic link AT
 * the company-root segment is caught directly.
 *
 * Rejects with {@link REJECTED_CREDENTIAL_HOME_MESSAGE} when:
 * - the instance root does not exist.
 * - the `companies` directory does not exist.
 * - the `companies` directory is a symbolic link, or sits anywhere other
 *   than `<realInstanceRoot>/companies` once resolved — this stops a
 *   redirected `companies` entry from being silently adopted as the
 *   credential-write boundary.
 * - `companyId` is empty, is `.` or `..`, or contains a path separator.
 * - `<realCompaniesRoot>/<companyId>` is missing, is not a directory, or is
 *   a symbolic link.
 *
 * Call this again immediately before a write that uses the result. Do not
 * carry a boundary computed earlier across an `await` that the write does
 * not need — a mutable ancestor can be rebound while that write waits.
 */
export async function resolveManagedCredentialHomeBoundary(
  input: ManagedCredentialHomeBoundaryInput,
): Promise<string> {
  const env = input.env ?? process.env;
  const instanceRoot = resolvePaperclipInstanceRootForAdapter({ env });
  const companiesRoot = path.resolve(instanceRoot, "companies");

  let realInstanceRoot: string;
  try {
    realInstanceRoot = await fs.realpath(instanceRoot);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") rejectCredentialHome();
    throw error;
  }

  let realCompaniesRoot: string;
  try {
    realCompaniesRoot = await fs.realpath(companiesRoot);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") rejectCredentialHome();
    throw error;
  }

  // A symbolic link at (or above) the `companies` segment can redirect
  // `realCompaniesRoot` to any external location `fs.realpath` is willing to
  // follow. Require it to land exactly at `<realInstanceRoot>/companies` —
  // the only location a managed `companies` directory may occupy — so a
  // redirected companies root is rejected instead of silently adopted as the
  // credential-write boundary.
  if (realCompaniesRoot !== path.join(realInstanceRoot, "companies")) {
    rejectCredentialHome();
  }

  if (!isSafePathSegment(input.companyId)) rejectCredentialHome();

  const companyDir = path.join(realCompaniesRoot, input.companyId);
  let companyStat;
  try {
    companyStat = await fs.lstat(companyDir);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") rejectCredentialHome();
    throw error;
  }
  if (companyStat.isSymbolicLink() || !companyStat.isDirectory()) {
    rejectCredentialHome();
  }

  return companyDir;
}

/**
 * Verifies every EXISTING directory segment between `boundary` (a path
 * {@link resolveManagedCredentialHomeBoundary} already verified) and
 * `target` with a no-follow `lstat`, so a symbolic link anywhere in the
 * existing part of the chain is caught. Stops at the first segment that
 * does not exist yet — a copy-back may still create it, and a missing
 * segment carries no symbolic link to check.
 *
 * Node.js exposes no `openat`, `mkdirat`, or `renameat`, so this walk
 * cannot pin a directory file descriptor across the segments the way a
 * single kernel-level containment check would. Calling this immediately
 * before the write it guards — with no other `await` in between — is the
 * strongest containment the standard library supports; a segment could
 * still be rebound in the gap between this call returning and the write
 * that follows it.
 */
export async function assertNoSymlinkInManagedCredentialPath(
  boundary: string,
  target: string,
): Promise<void> {
  const relative = path.relative(boundary, target);
  if (relative === "") return;
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    rejectCredentialHome();
  }

  let current = boundary;
  for (const segment of relative.split(path.sep)) {
    current = path.join(current, segment);
    let stat;
    try {
      stat = await fs.lstat(current);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      rejectCredentialHome();
    }
  }
}

/**
 * Guards a Codex/Grok credential copy-back target. Call this with the
 * directory a copy-back is about to write into, before any file write.
 *
 * Verifies the company boundary with {@link resolveManagedCredentialHomeBoundary},
 * then walks the ORIGINAL, unresolved `candidateDir` against the literal
 * boundary text with a no-follow `lstat` through
 * {@link assertNoSymlinkInManagedCredentialPath}, so a symbolic link
 * anywhere in the candidate — even one whose target is still inside the
 * company tree — is rejected before it can be followed. Only then resolves
 * the real path of `candidateDir`, requires the candidate to equal the
 * boundary or sit under it, and re-checks every existing segment between
 * them a second time. Rejects every other candidate — a path outside the
 * instance root, a path under a different company, a symbolic link anywhere
 * on the chain, and a relative path that escapes with `..` — with the fixed
 * {@link REJECTED_CREDENTIAL_HOME_MESSAGE}.
 *
 * Returns the resolved, real candidate directory on success. A caller that
 * uses the result for a write must not treat it as still valid after an
 * unrelated `await` — re-verify with {@link assertNoSymlinkInManagedCredentialPath}
 * right before that write.
 */
export async function assertManagedCredentialHome(
  input: AssertManagedCredentialHomeInput,
): Promise<string> {
  const boundary = await resolveManagedCredentialHomeBoundary(input);

  // Reject a symbolic link anywhere in the ORIGINAL candidate path before any
  // symlink-following resolution runs. Compare against the LITERAL boundary
  // text (`<instanceRoot>/companies/<companyId>`, not yet real-pathed) — a
  // caller always builds a managed candidate directory with that same
  // literal text, so an honest candidate still passes. The resolution below
  // calls `fs.realpath`, which follows a symbolic link and adopts its
  // target — including an in-tree link that points at a different, equally
  // in-tree location, for example another account's credential home. A
  // no-follow walk over the ALREADY-RESOLVED path can never see a link the
  // resolution already followed, so this walk must run first, on the
  // unresolved path.
  const env = input.env ?? process.env;
  const instanceRoot = resolvePaperclipInstanceRootForAdapter({ env });
  const literalBoundary = path.resolve(instanceRoot, "companies", input.companyId);
  await assertNoSymlinkInManagedCredentialPath(literalBoundary, path.resolve(input.candidateDir));

  const realCandidateDir = await resolveRealPathAllowingMissingSegments(input.candidateDir);

  const isContained =
    realCandidateDir === boundary || realCandidateDir.startsWith(boundary + path.sep);
  if (!isContained) {
    rejectCredentialHome();
  }

  await assertNoSymlinkInManagedCredentialPath(boundary, realCandidateDir);

  return realCandidateDir;
}
