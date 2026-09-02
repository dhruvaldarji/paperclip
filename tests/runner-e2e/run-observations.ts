export interface ObservableRunState {
  status?: string | null;
  errorCode?: string | null;
}

export interface ObservableRunEvent {
  eventType?: string;
  payload?: Record<string, unknown> | null;
}

export interface ObservableProviderSessionRun {
  id: string;
  sessionIdBefore?: string | null;
  sessionIdAfter?: string | null;
  contextSnapshot?: Record<string, unknown> | null;
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

export function isNonExecutingReviewFenceRun(run: ObservableRunState) {
  return (
    run.status === "cancelled" &&
    run.errorCode === "issue_continuation_waiting_on_review"
  );
}

export function isControlPlaneGovernedResponseWait(
  events: readonly ObservableRunEvent[],
) {
  const accepted = events.filter(
    (event) => event.eventType === "run.result.accepted",
  );
  if (accepted.length !== 1) return false;
  const envelope = record(accepted[0]?.payload?.prpEvent);
  const result = record(record(envelope.payload).result);
  return (
    envelope.schema === "paperclip.prp.event.v1" &&
    envelope.eventType === "run.result.accepted" &&
    envelope.sourceKind === "control_plane" &&
    result.schema === "paperclip.run_result.v1" &&
    result.reportedWorkDisposition === "yielded" &&
    record(result.continuation).kind === "response_wake"
  );
}

export function providerSessionContinuityFailures(
  provider: "codex" | "opencode",
  runs: readonly ObservableProviderSessionRun[],
): string[] {
  const failures: string[] = [];
  for (let index = 0; index < runs.length; index += 1) {
    const current = runs[index]!;
    const currentSessionId = current.sessionIdAfter;
    if (!currentSessionId) {
      failures.push(
        `expected ${provider} run ${current.id} to record provider session identity`,
      );
      continue;
    }
    if (index === 0) continue;

    const previousSessionId = runs[index - 1]?.sessionIdAfter;
    const context = record(current.contextSnapshot);
    const acceptedPlanReset =
      context.forceFreshSession === true &&
      context.workspaceRefreshReason === "accepted_plan_confirmation" &&
      context.source === "issue.interaction.accept" &&
      context.interactionStatus === "accepted";
    if (acceptedPlanReset) {
      if (current.sessionIdBefore) {
        failures.push(
          `expected accepted Plan run ${current.id} to start without a prior provider session`,
        );
      }
      if (previousSessionId && currentSessionId === previousSessionId) {
        failures.push(
          `expected accepted Plan run ${current.id} to rotate the ${provider} provider session`,
        );
      }
      continue;
    }

    if (!previousSessionId || currentSessionId !== previousSessionId) {
      failures.push(
        `expected ${provider} to preserve its provider session for run ${current.id}`,
      );
      continue;
    }
    if (
      current.sessionIdBefore &&
      current.sessionIdBefore !== previousSessionId
    ) {
      failures.push(
        `expected ${provider} run ${current.id} to resume provider session ${previousSessionId}`,
      );
    }
  }
  return failures;
}

export function numberedPlanStepCount(body: string | null | undefined) {
  return (body ?? "").split(/\r?\n/).filter((line) => {
    const normalized = line
      .replaceAll("**", "")
      .replaceAll("__", "")
      .replaceAll("`", "");
    return /^\s*(?:#{1,6}\s*)?(?:[-*+]\s*)?(?:step\s+)?\d+(?:[.)]|\s*[-—:])(?:\s|$)/i.test(
      normalized,
    );
  }).length;
}
