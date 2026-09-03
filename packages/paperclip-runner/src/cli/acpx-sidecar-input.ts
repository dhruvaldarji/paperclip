import { enqueueSerialInput } from "./serial-input-queue.js";

const ACPX_BOOTSTRAP_COMMANDS = new Set(["initialize", "session.open"]);

export function enqueueAcpxSidecarInput(
  pending: Promise<void>,
  operation: () => Promise<void>,
  onError: (error: unknown) => void | Promise<void>,
): Promise<void> {
  return enqueueSerialInput(pending, operation, onError);
}

export function recordAcpxBootstrapFailure(
  current: Error | null,
  command: string,
  error: Error,
): Error | null {
  return current ?? (ACPX_BOOTSTRAP_COMMANDS.has(command) ? error : null);
}

export function acpxBootstrapBlockedError(
  failure: Error | null,
  command: string,
): Error | null {
  return failure
    ? new Error(
        `ACPX provider bootstrap failed before ${command}: ${failure.message}`,
      )
    : null;
}

/**
 * Preserve only stable ACPX/provider error identities across the sidecar
 * boundary. Startup stderr can contain credentials or provider output, so it
 * contributes a closed category and is never copied into the code itself.
 */
export function acpxSidecarErrorCode(error: Error): string {
  const pending: Error[] = [error];
  const observed = new Set<Error>();
  while (pending.length > 0 && observed.size < 16) {
    const current = pending.shift()!;
    if (observed.has(current)) continue;
    observed.add(current);
    const code = directAcpxSidecarErrorCode(current);
    if (code !== null) return code;

    const details = current as Error & Record<string, unknown>;
    if (current instanceof AggregateError) {
      for (const nested of current.errors) {
        if (nested instanceof Error) pending.push(nested);
      }
    }
    if (details.cause instanceof Error) pending.push(details.cause);
  }
  return "acpx_sidecar_command_failed";
}

function directAcpxSidecarErrorCode(error: Error): string | null {
  const details = error as Error & Record<string, unknown>;
  const code =
    typeof details.code === "string"
      ? details.code
      : typeof details.detailCode === "string"
        ? details.detailCode
        : null;
  if (code === null) {
    return error.name === "AcpxSessionHandshakeTimeoutError" ||
      error.message === "ACPX session handshake exceeded its admission deadline"
      ? "ACPX_SESSION_HANDSHAKE_TIMEOUT"
      : null;
  }
  if (code !== "AGENT_STARTUP_FAILED") return code;

  const stderr =
    typeof details.stderrSummary === "string" ? details.stderrSummary : "";
  if (/ERR_ACPX_UNVERIFIED_MODULE/.test(stderr)) {
    return "AGENT_STARTUP_FAILED.UNVERIFIED_MODULE";
  }
  if (/ERR_MODULE_NOT_FOUND|Cannot find (?:module|package)/i.test(stderr)) {
    return "AGENT_STARTUP_FAILED.MODULE_NOT_FOUND";
  }
  if (/\bEACCES\b|permission denied/i.test(stderr)) {
    return "AGENT_STARTUP_FAILED.PERMISSION_DENIED";
  }
  if (/\bENOENT\b|no such file or directory/i.test(stderr)) {
    return "AGENT_STARTUP_FAILED.FILE_NOT_FOUND";
  }
  if (/SyntaxError|unexpected token/i.test(stderr)) {
    return "AGENT_STARTUP_FAILED.SYNTAX_ERROR";
  }
  if (/ERR_INVALID_ARG|invalid argument/i.test(stderr)) {
    return "AGENT_STARTUP_FAILED.INVALID_ARGUMENT";
  }
  if (!stderr.trim()) return "AGENT_STARTUP_FAILED.NO_STDERR";
  if (typeof details.signal === "string" && details.signal) {
    return "AGENT_STARTUP_FAILED.SIGNAL";
  }
  if (
    typeof details.exitCode === "number" &&
    Number.isInteger(details.exitCode) &&
    details.exitCode !== 0
  ) {
    return "AGENT_STARTUP_FAILED.EXIT_NONZERO";
  }
  return "AGENT_STARTUP_FAILED.OTHER";
}
