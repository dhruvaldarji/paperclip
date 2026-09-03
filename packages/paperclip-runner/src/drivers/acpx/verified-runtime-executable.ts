import { isAbsolute, resolve } from "node:path";

export const VERIFIED_RUNTIME_EXECUTABLE_ENV =
  "PAPERCLIP_VERIFIED_RUNTIME_EXECUTABLE";

/**
 * Recover the runner-authenticated executable inherited by a descriptor-loaded
 * sidecar. Linux children cannot use process.execPath here: Node resolves the
 * sealed image to a deleted memfd alias. Anchor the descriptor at the current
 * owner process before launching a descendant, whose own `/proc/self` would
 * otherwise name the wrong descriptor table.
 */
export function verifiedRuntimeExecutable(
  environment: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  currentPid: number = process.pid,
  fallback: string = process.execPath,
): string {
  const configured = environment[VERIFIED_RUNTIME_EXECUTABLE_ENV];
  if (configured === undefined) return fallback;

  if (platform === "linux") {
    const match = /^\/proc\/self\/fd\/([0-9]+)$/.exec(configured);
    if (match) return `/proc/${currentPid}/fd/${match[1]}`;
    if (/^\/proc\/[1-9][0-9]*\/fd\/[0-9]+$/.test(configured)) {
      return configured;
    }
    throw new Error("Verified runtime executable descriptor is invalid");
  }

  if (platform === "darwin") {
    if (!isAbsolute(configured) || resolve(configured) !== configured) {
      throw new Error("Verified runtime executable path is invalid");
    }
    return configured;
  }

  throw new Error(
    "Verified runtime executable is unsupported on this platform",
  );
}
