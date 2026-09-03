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

export function acceptedPlanSessionResetFailures(
  provider: "codex" | "opencode" | "acpx",
  previousSessionId: string | null | undefined,
  current: ObservableProviderSessionRun,
): string[] | null {
  const context = record(current.contextSnapshot);
  const acceptedPlanReset =
    context.forceFreshSession === true &&
    context.workspaceRefreshReason === "accepted_plan_confirmation" &&
    context.source === "issue.interaction.accept" &&
    context.interactionStatus === "accepted";
  if (!acceptedPlanReset) return null;

  const failures: string[] = [];
  if (current.sessionIdBefore) {
    failures.push(
      `expected accepted Plan run ${current.id} to start without a prior provider session`,
    );
  }
  if (
    previousSessionId &&
    current.sessionIdAfter &&
    current.sessionIdAfter === previousSessionId
  ) {
    failures.push(
      `expected accepted Plan run ${current.id} to rotate the ${provider} provider session`,
    );
  }
  return failures;
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
  const continuation = record(result.continuation);
  const idempotencyKey = continuation.idempotencyKey;
  if (
    typeof idempotencyKey !== "string" ||
    !idempotencyKey.startsWith("interaction-response:")
  ) {
    return false;
  }
  const interactionId = idempotencyKey.slice("interaction-response:".length);
  if (!interactionId) return false;
  const interactionRef = `interaction:${interactionId}`;
  const hasEvidence =
    Array.isArray(result.evidence) &&
    result.evidence.some((value) => record(value).ref === interactionRef);
  const hasInteractionArtifact =
    Array.isArray(result.artifacts) &&
    result.artifacts.some((value) => {
      const artifact = record(value);
      return (
        artifact.kind === "issue_thread_interaction" &&
        artifact.ref === interactionRef
      );
    });
  return (
    envelope.schema === "paperclip.prp.event.v1" &&
    envelope.eventType === "run.result.accepted" &&
    envelope.sourceKind === "control_plane" &&
    result.schema === "paperclip.run_result.v1" &&
    result.reportedWorkDisposition === "yielded" &&
    continuation.kind === "response_wake" &&
    hasEvidence &&
    hasInteractionArtifact
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
    const acceptedPlanResetFailures = acceptedPlanSessionResetFailures(
      provider,
      previousSessionId,
      current,
    );
    if (acceptedPlanResetFailures) {
      failures.push(...acceptedPlanResetFailures);
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
