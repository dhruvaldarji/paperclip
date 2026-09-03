import { isAbsolute, resolve } from "node:path";

export const VERIFIED_RUNTIME_EXECUTABLE_ENV =
  "PAPERCLIP_VERIFIED_RUNTIME_EXECUTABLE";

/**
 * Recover the runner-authenticated executable inherited by a descriptor-loaded
 * sidecar. Linux children cannot use process.execPath here: Node resolves the
 * sealed image to a deleted memfd alias. Once the inherited descriptor has
 * authenticated the current image, `/proc/self/exe` keeps that exact live
 * image available to every fork/exec generation without granting a descendant
 * access to an ancestor's descriptor table.
 */
export function verifiedRuntimeExecutable(
  environment: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  _currentPid: number = process.pid,
  fallback: string = process.execPath,
): string {
  const configured = environment[VERIFIED_RUNTIME_EXECUTABLE_ENV];
  if (configured === undefined) return fallback;

  if (platform === "linux") {
    if (/^\/proc\/self\/fd\/[0-9]+$/.test(configured)) return "/proc/self/exe";
    if (configured === "/proc/self/exe") return configured;
    throw new Error("Verified runtime executable descriptor is invalid");
  }

  if (platform === "darwin") {
    if (
      !isAbsolute(fallback) ||
      resolve(fallback) !== fallback ||
      configured !== fallback
    ) {
      throw new Error("Verified runtime executable path is invalid");
    }
    // The Rust supervisor materializes the authenticated runtime as a private,
    // read-only executable and starts this process from that exact pathname.
    // Descendants may inherit the handoff variable, but they cannot nominate a
    // different absolute path and have it treated as verified.
    return fallback;
  }

  throw new Error(
    "Verified runtime executable is unsupported on this platform",
  );
}
