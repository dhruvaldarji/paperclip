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

export interface AssertManagedCredentialHomeInput {
  env?: NodeJS.ProcessEnv;
  companyId: string;
  candidateDir: string;
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
 * Guards a Codex/Grok credential copy-back target. Call this with the
 * directory a copy-back is about to write into, before any file write.
 *
 * Resolves the real path of the company root and the real path of
 * `candidateDir`, then accepts the candidate only when it equals the company
 * root or sits under it. Rejects every other candidate — a path outside the
 * instance root, a path under a different company, a symbolic link that
 * points outside the company root, and a relative path that escapes with
 * `..` — with the fixed {@link REJECTED_CREDENTIAL_HOME_MESSAGE}.
 *
 * Returns the resolved, real candidate directory on success, so the caller
 * writes through the same path this check just verified.
 */
export async function assertManagedCredentialHome(
  input: AssertManagedCredentialHomeInput,
): Promise<string> {
  const env = input.env ?? process.env;
  const instanceRoot = resolvePaperclipInstanceRootForAdapter({ env });
  const companyRoot = path.resolve(instanceRoot, "companies", input.companyId);
  const realCompanyRoot = await resolveRealPathAllowingMissingSegments(companyRoot);
  const realCandidateDir = await resolveRealPathAllowingMissingSegments(input.candidateDir);

  const isContained =
    realCandidateDir === realCompanyRoot ||
    realCandidateDir.startsWith(realCompanyRoot + path.sep);
  if (!isContained) {
    throw new Error(REJECTED_CREDENTIAL_HOME_MESSAGE);
  }
  return realCandidateDir;
}
