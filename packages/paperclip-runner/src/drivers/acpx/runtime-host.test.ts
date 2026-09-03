import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { openCodexAcpxRuntime } from "./codex-runtime-adapter.js";
import { stageManagedCodexCredential } from "./codex-credentials.js";
import type {
  VerifiedAcpxCommandLease,
  VerifiedAcpxInstallation,
} from "./installation-integrity.js";
import { resolveQualifiedAcpxProfile } from "./qualified-profiles.js";
import {
  AcpxRuntimeHost,
  type AcpxRuntimeHostDependencies,
  type AcpxRuntimePort,
  type AcpxRuntimePortOpenOptions,
  type AcpxRuntimeTurn,
} from "./runtime-host.js";
import {
  prepareAcpxRuntimeSandbox,
  removeOwnedAcpxRuntimeSandboxRoot,
  type AcpxRuntimeSandbox,
} from "./runtime-sandbox.js";

const temporaryDirectories: string[] = [];
const admissionControllers: AbortController[] = [];
const pendingAdmissionOpenings = new Set<Promise<void>>();
const pendingAdmissionCleanups = new Set<Promise<void>>();

afterEach(async () => {
  for (const controller of admissionControllers.splice(0)) {
    if (!controller.signal.aborted) {
      controller.abort(new Error("ACPX runtime host test cleanup"));
    }
  }
  await Promise.all([...pendingAdmissionOpenings]);
  await Promise.all([...pendingAdmissionCleanups]);
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

// Every wait below follows real sandbox preparation: private directories and
// files created with an fsync after each write (see runtime-sandbox.ts). A
// loaded CI runner can push that past the 1000ms vi.waitFor default, so every
// wait in this file goes through one named, bounded deadline instead.
const ACPX_ADMISSION_WAIT_TIMEOUT_MS = 10_000;

async function waitForAcpxAdmission<T>(
  check: () => T | Promise<T>,
): Promise<T> {
  return await vi.waitFor(check, { timeout: ACPX_ADMISSION_WAIT_TIMEOUT_MS });
}

describe("ACPX runtime host", () => {
  it("rejects a pre-aborted admission before acquiring provider resources", async () => {
    const fixture = await hostFixture();
    const controller = trackedAdmissionController();
    const cancellation = new Error("admission cancelled before start");
    controller.abort(cancellation);
    const openRuntime = vi.fn(async () => runtimePort());
    const verifyInstallation = vi.fn(
      fixture.dependencies({ openRuntime }).verifyInstallation!,
    );

    await expect(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "claude",
          model: "claude-sonnet-5",
          permissionMode: "deny-all",
          signal: controller.signal,
        },
        {
          ...fixture.dependencies({ openRuntime }),
          verifyInstallation,
        },
      ),
    ).rejects.toBe(cancellation);

    expect(verifyInstallation).not.toHaveBeenCalled();
    expect(openRuntime).not.toHaveBeenCalled();
    expect(fixture.commandClose).not.toHaveBeenCalled();
  });

  it("retains aborted sandbox preparation until its filesystem work settles", async () => {
    const fixture = await hostFixture();
    const controller = trackedAdmissionController();
    const cancellation = new Error("sandbox admission cancelled");
    const rootGate = deferred<void>();
    const prepareSandbox: NonNullable<
      AcpxRuntimeHostDependencies["prepareSandbox"]
    > = vi.fn((input) =>
      prepareAcpxRuntimeSandbox(input, {
        afterRootOwned: () => rootGate.promise,
      }),
    );
    const stageCredential = vi.fn(async () => {
      throw new Error("credential staging must not start");
    });
    const openRuntime = vi.fn(async () => runtimePort());
    const dependencies = fixture.dependencies({ openRuntime });
    dependencies.stageCredential = stageCredential;
    dependencies.prepareSandbox = prepareSandbox;

    const unhandled: unknown[] = [];
    const onUnhandledRejection = (reason: unknown) => {
      unhandled.push(reason);
    };
    process.on("unhandledRejection", onUnhandledRejection);
    try {
      const opening = trackAdmissionOpening(
        AcpxRuntimeHost.open(
          {
            ...fixture.options,
            agent: "codex",
            model: "gpt-5.6-sol",
            permissionMode: "deny-all",
            signal: controller.signal,
          },
          dependencies,
        ),
      );
      await waitForAcpxAdmission(() =>
        expect(prepareSandbox).toHaveBeenCalledOnce(),
      );

      controller.abort(cancellation);
      await expect(opening).rejects.toBe(cancellation);
      expect(stageCredential).not.toHaveBeenCalled();
      expect(openRuntime).not.toHaveBeenCalled();
      expect(fixture.commandClose).not.toHaveBeenCalled();

      rootGate.resolve();
      const sandbox: AcpxRuntimeSandbox =
        await prepareSandbox.mock.results[0]!.value;
      await waitForAcpxAdmission(() =>
        expect(stat(sandbox.root)).rejects.toMatchObject({ code: "ENOENT" }),
      );

      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(unhandled).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandledRejection);
    }
  });

  it("settles retained admission work when aborted sandbox preparation rejects", async () => {
    const fixture = await hostFixture();
    const controller = trackedAdmissionController();
    const cancellation = new Error("sandbox admission cancelled");
    const sandboxStarted = deferred<void>();
    const finishSandbox = deferred<void>();
    const stageCredential = vi.fn(async () => {
      throw new Error("credential staging must not start");
    });
    const openRuntime = vi.fn(async () => runtimePort());
    const dependencies = fixture.dependencies({ openRuntime });
    dependencies.stageCredential = stageCredential;
    dependencies.prepareSandbox = async (input) => {
      sandboxStarted.resolve(undefined);
      await finishSandbox.promise;
      return await prepareAcpxRuntimeSandbox(input);
    };

    const unhandled: unknown[] = [];
    const onUnhandledRejection = (reason: unknown) => {
      unhandled.push(reason);
    };
    process.on("unhandledRejection", onUnhandledRejection);
    try {
      const opening = trackAdmissionOpening(
        AcpxRuntimeHost.open(
          {
            ...fixture.options,
            agent: "codex",
            model: "gpt-5.6-sol",
            permissionMode: "deny-all",
            signal: controller.signal,
          },
          dependencies,
        ),
      );
      await sandboxStarted.promise;

      controller.abort(cancellation);
      await expect(opening).rejects.toBe(cancellation);

      finishSandbox.reject(new Error("sandbox preparation failed after abort"));
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(unhandled).toEqual([]);
      expect(stageCredential).not.toHaveBeenCalled();
      expect(openRuntime).not.toHaveBeenCalled();
      expect(fixture.commandClose).not.toHaveBeenCalled();
    } finally {
      process.off("unhandledRejection", onUnhandledRejection);
    }
  });

  it("scrubs credentials when abort wins before the adapter body starts", async () => {
    const fixture = await hostFixture();
    const controller = trackedAdmissionController();
    const cancellation = new Error("runtime admission cancelled before entry");
    const createRuntime = vi.fn();
    let credentialHome = "";
    const openRuntime = vi.fn((options: AcpxRuntimePortOpenOptions) => {
      credentialHome = options.launchEnvironment.CODEX_HOME!;
      // The host has scheduled its openRuntime callback and transferred the
      // staged credential to that pending admission. Abort before entering the
      // adapter so its pre-entry path must publish a completed cleanup proof.
      controller.abort(cancellation);
      return openCodexAcpxRuntime(options, { createRuntime });
    });

    await expect(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "codex",
          model: "gpt-5.6-sol",
          permissionMode: "deny-all",
          environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
          signal: controller.signal,
        },
        fixture.dependencies({ openRuntime }),
      ),
    ).rejects.toBe(cancellation);

    expect(openRuntime).toHaveBeenCalledOnce();
    expect(createRuntime).not.toHaveBeenCalled();
    expect(fixture.commandClose).toHaveBeenCalledOnce();
    const authPath = join(credentialHome, "auth.json");
    const contender = await waitForAcpxAdmission(() =>
      stageManagedCodexCredential({
        agentHomeDirectory: credentialHome,
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"contender"}',
        },
      }),
    );
    await contender.close();
    await expect(readFile(authPath)).rejects.toMatchObject({ code: "ENOENT" });

    const retryRuntime = runtimePort();
    const retryHost = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "deny-all",
        environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
      },
      fixture.dependencies({ openRuntime: async () => retryRuntime }),
    );
    await retryHost.close({ reason: "retry admission complete" });
    expect(retryRuntime.close).toHaveBeenCalledOnce();
  });

  it("composes admission, isolation, model verification, and cleanup", async () => {
    const fixture = await hostFixture();
    let capturedEnvironment: Readonly<NodeJS.ProcessEnv> = {};
    const runtime = runtimePort({
      onClose: vi.fn(async () => undefined),
    });
    const dependencies = fixture.dependencies({
      openRuntime: async (options) => {
        capturedEnvironment = options.launchEnvironment;
        await writeFile(
          join(options.launchEnvironment.CODEX_HOME!, "auth.json"),
          '{"provider_generated":true}',
        );
        return runtime;
      },
    });

    const host = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "approve-reads",
        environment: {
          PATH: process.env.PATH,
          OPENAI_API_KEY: "launch-secret",
          HTTPS_PROXY: "https://proxy-user:proxy-secret@example.test",
        },
        systemInstructions: "Use the supplied runtime context.",
      },
      dependencies,
    );
    expect(host.identity()).toMatchObject({
      schema: "paperclip.runner.acpx-identity.v1",
      acpxRecordId: "record-1",
      requestedModel: "gpt-5.6-sol",
      permissionMode: "approve-reads",
    });
    expect(capturedEnvironment.OPENAI_API_KEY).toBe("launch-secret");
    expect(host.persistedEnvironment().OPENAI_API_KEY).toBeUndefined();
    expect(host.persistedEnvironment().HTTPS_PROXY).toBeUndefined();
    const authPath = join(host.runtimeRoot(), "codex-home", "auth.json");
    await expect(readFile(authPath, "utf8")).resolves.toContain(
      "provider_generated",
    );

    await host.close({ reason: "test complete" });
    await expect(readFile(authPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(runtime.close).toHaveBeenCalledOnce();
    expect(fixture.commandClose).toHaveBeenCalledOnce();
  });

  it("revalidates a pinned workspace at the runtime-open boundary", async () => {
    const fixture = await hostFixture();
    const openRuntime = vi.fn(async () => runtimePort());
    const workspaceSubstituted = new Error("recovered workspace substituted");
    let assertions = 0;
    const assertWorkspaceHeld = vi.fn(() => {
      assertions += 1;
      if (assertions === 2) throw workspaceSubstituted;
    });

    await expect(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "codex",
          model: "gpt-5.6-sol",
          permissionMode: "approve-reads",
          environment: {
            PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}",
          },
          assertWorkspaceHeld,
        },
        fixture.dependencies({ openRuntime }),
      ),
    ).rejects.toBe(workspaceSubstituted);

    expect(assertWorkspaceHeld).toHaveBeenCalledTimes(2);
    expect(openRuntime).not.toHaveBeenCalled();
    expect(fixture.commandClose).toHaveBeenCalledOnce();
  });

  it("owns an authenticated semantic bridge without persisting its secret", async () => {
    const fixture = await hostFixture();
    const handler = vi.fn(async ({ tool }) => ({ tool, ok: true }));
    let bridge:
      | { url: string; bearerToken: string; name: string; runnerOwned: boolean }
      | undefined;
    const host = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "deny-all",
        environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
        semanticTools: {
          tools: [
            {
              name: "documents.read",
              description: "Read one document.",
              inputSchema: {
                type: "object",
                properties: { id: { type: "string" } },
                required: ["id"],
                additionalProperties: false,
              },
            },
          ],
          handler,
        },
      },
      fixture.dependencies({
        openRuntime: async (options) => {
          bridge = options.mcpServers[0];
          return runtimePort();
        },
      }),
    );

    expect(bridge).toMatchObject({
      name: "paperclip",
      runnerOwned: true,
    });
    expect(new URL(bridge!.url).hostname).toBe("127.0.0.1");
    const response = await fetch(bridge!.url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${bridge!.bearerToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "call-1",
        method: "tools/call",
        params: { name: "documents.read", arguments: { id: "doc-1" } },
      }),
    });
    expect(await response.json()).toMatchObject({
      result: { content: [{ text: '{"tool":"documents.read","ok":true}' }] },
    });
    expect(handler).toHaveBeenCalledOnce();
    expect(JSON.stringify(host.persistedEnvironment())).not.toContain(
      bridge!.bearerToken,
    );

    await host.close({ reason: "complete" });
    await expect(
      fetch(bridge!.url, {
        method: "POST",
        headers: { Authorization: `Bearer ${bridge!.bearerToken}` },
      }),
    ).rejects.toThrow();
  });

  it("rejects Pi before installation or runtime launch", async () => {
    const fixture = await hostFixture();
    const verifyInstallation = vi.fn();
    const openRuntime = vi.fn();
    await expect(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "pi" as never,
          model: "openrouter/deepseek/deepseek-v4-flash-0731",
          permissionMode: "approve-reads",
        },
        {
          verifyInstallation,
          openRuntime,
          reportRetainedCleanupFailure: vi.fn(),
        },
      ),
    ).rejects.toThrow("descriptor-confined verified launch");
    expect(verifyInstallation).not.toHaveBeenCalled();
    expect(openRuntime).not.toHaveBeenCalled();
  });

  it("selects and verifies Claude's qualified reported model", async () => {
    const fixture = await hostFixture();
    let selected = false;
    const setModel = vi.fn(async (model: string) => {
      expect(model).toBe("claude-sonnet-5");
      selected = true;
    });
    const runtime = runtimePort({
      getStatus: async () => ({
        models: {
          currentModelId: selected ? "sonnet" : "default",
          availableModelIds: ["default", "sonnet"],
        },
      }),
      setModel,
    });
    const host = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "claude",
        model: "claude-sonnet-5",
        permissionMode: "deny-all",
      },
      fixture.dependencies({ openRuntime: async () => runtime }),
    );

    expect(setModel).toHaveBeenCalledOnce();
    expect(host.identity().effectiveModel).toBe("claude-sonnet-5");
    await host.close({ reason: "verified" });
  });

  it("rejects recovery drift before opening the provider", async () => {
    const fixture = await hostFixture();
    const openRuntime = vi.fn(async () => runtimePort());

    await expect(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "claude",
          model: "claude-sonnet-5",
          permissionMode: "approve-reads",
          expectedIdentity: {
            kind: "acpx",
            normalizedSessionId: fixture.options.normalizedSessionId,
            acpxRecordId: "record-1",
            backendSessionId: "backend-1",
            agentSessionId: "agent-1",
            profileDigest: resolveQualifiedAcpxProfile(
              "claude",
              "claude-sonnet-5",
            ).commandDigest,
            workspaceDigest: `sha256:${"0".repeat(64)}`,
            requestedModel: "claude-sonnet-5",
            effectiveModel: "claude-sonnet-5",
            permissionMode: "approve-reads",
          },
        },
        fixture.dependencies({ openRuntime }),
      ),
    ).rejects.toThrow(/immutable session configuration/);
    expect(openRuntime).not.toHaveBeenCalled();
  });

  it("rejects an injected installation that does not match the profile", async () => {
    const fixture = await hostFixture();
    const openRuntime = vi.fn(async () => runtimePort());
    const dependencies = fixture.dependencies({ openRuntime });
    dependencies.verifyInstallation = async () => ({
      commandDigest: `sha256:${"f".repeat(64)}`,
      agentServerPackageJsonPath: join(fixture.root, "package.json"),
      agentRuntimePackageJsonPath: null,
      openCommand: async () => {
        throw new Error("mismatched installation must not open");
      },
    });

    await expect(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "claude",
          model: "claude-sonnet-5",
          permissionMode: "approve-all",
        },
        dependencies,
      ),
    ).rejects.toThrow(/does not match its profile/);
    expect(openRuntime).not.toHaveBeenCalled();
  });

  it("cleans credentials and command leases when provider open fails", async () => {
    const fixture = await hostFixture();
    let authPath = "";
    await expect(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "codex",
          model: "gpt-5.6-sol",
          permissionMode: "approve-all",
          environment: {
            PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET:
              '{"tokens":{"access_token":"canary"}}',
          },
        },
        fixture.dependencies({
          openRuntime: async (options) => {
            authPath = join(options.launchEnvironment.CODEX_HOME!, "auth.json");
            throw new Error("provider failed");
          },
        }),
      ),
    ).rejects.toThrow("provider failed");
    await expect(readFile(authPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(fixture.commandClose).toHaveBeenCalledOnce();
  });

  it.each([
    ["credential", "credential staging failed"],
    ["command", "command open failed"],
    ["runtime open", "provider open failed"],
    ["post-handshake verification", "model status failed"],
  ])(
    "releases the sandbox lease when %s fails after sandbox acquisition",
    async (_stage, failureMessage) => {
      const fixture = await hostFixture();
      const prepareSandbox: NonNullable<
        AcpxRuntimeHostDependencies["prepareSandbox"]
      > = vi.fn((input) => prepareAcpxRuntimeSandbox(input));
      const dependencies = fixture.dependencies({
        openRuntime: async () => {
          if (failureMessage === "provider open failed") {
            throw new Error(failureMessage);
          }
          return runtimePort({
            getStatus:
              failureMessage === "model status failed"
                ? async () => {
                    throw new Error(failureMessage);
                  }
                : undefined,
          });
        },
      });
      dependencies.prepareSandbox = prepareSandbox;
      if (failureMessage === "credential staging failed") {
        dependencies.stageCredential = async () => {
          throw new Error(failureMessage);
        };
      }
      if (failureMessage === "command open failed") {
        dependencies.verifyInstallation = async (profile) => ({
          commandDigest: profile.commandDigest,
          agentServerPackageJsonPath: join(fixture.root, "package.json"),
          agentRuntimePackageJsonPath: null,
          openCommand: async () => {
            throw new Error(failureMessage);
          },
        });
      }

      await expect(
        AcpxRuntimeHost.open(
          {
            ...fixture.options,
            agent: "codex",
            model: "gpt-5.6-sol",
            permissionMode: "approve-all",
            environment: {
              PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET:
                '{"tokens":{"access_token":"canary"}}',
            },
          },
          dependencies,
        ),
      ).rejects.toThrow(/failed/);

      const sandbox: AcpxRuntimeSandbox =
        await prepareSandbox.mock.results[0]!.value;
      // The root itself is never deleted outright: a later admission for
      // the same session may still reuse it.
      await expect(stat(sandbox.root)).resolves.toBeDefined();

      // The claim this admission never released would otherwise pin the
      // marker to its own identifier forever, so no later admission could
      // ever win delete authority over this root. Reuse the exact binding
      // this admission built its sandbox from to claim the root again, and
      // prove that claim now carries real delete authority.
      const [{ binding }] = prepareSandbox.mock.calls[0]!;
      const retriedSandbox = await waitForAcpxAdmission(() =>
        prepareAcpxRuntimeSandbox({ binding, agent: "codex" }),
      );
      expect(retriedSandbox.root).toBe(sandbox.root);
      await removeOwnedAcpxRuntimeSandboxRoot(retriedSandbox);
      await expect(stat(sandbox.root)).rejects.toMatchObject({
        code: "ENOENT",
      });
    },
  );

  it("retains failed admission cleanup until provider shutdown permits credential scrub", async () => {
    const fixture = await hostFixture();
    let authPath = "";
    let credentialHome = "";
    let resolveRetryClose!: () => void;
    const retryClose = new Promise<void>((resolve) => {
      resolveRetryClose = resolve;
    });
    const runtime = runtimePort({
      getStatus: async () => ({
        models: {
          currentModelId: "wrong-model",
          availableModelIds: ["wrong-model"],
        },
      }),
      onClose: vi
        .fn()
        .mockRejectedValueOnce(new Error("first admission cleanup failed"))
        .mockImplementationOnce(() => retryClose),
    });
    await expect(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "codex",
          model: "gpt-5.6-sol",
          permissionMode: "approve-all",
          environment: {
            PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET:
              '{"owner":"failed-admission"}',
          },
        },
        fixture.dependencies({
          openRuntime: async (options) => {
            credentialHome = options.launchEnvironment.CODEX_HOME!;
            authPath = join(credentialHome, "auth.json");
            return runtime;
          },
        }),
      ),
    ).rejects.toThrow(/initialization and cleanup failed/);

    await waitForAcpxAdmission(() =>
      expect(runtime.close).toHaveBeenCalledTimes(2),
    );
    await expect(readFile(authPath, "utf8")).resolves.toContain(
      "failed-admission",
    );
    await expect(
      stageManagedCodexCredential({
        agentHomeDirectory: credentialHome,
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"contender"}',
        },
      }),
    ).rejects.toThrow("already has an active lease");

    resolveRetryClose();
    await waitForAcpxAdmission(async () => {
      await expect(readFile(authPath)).rejects.toMatchObject({
        code: "ENOENT",
      });
    });
    const contender = await stageManagedCodexCredential({
      agentHomeDirectory: credentialHome,
      environment: {
        PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"contender"}',
      },
    });
    await contender.close();
  });

  it("bounds post-handshake model verification and cleans the runtime", async () => {
    const fixture = await hostFixture();
    const runtime = runtimePort({
      getStatus: () => new Promise<never>(() => undefined),
    });
    const dependencies = fixture.dependencies({
      openRuntime: async () => runtime,
    });
    dependencies.admissionVerificationTimeoutMs = 1;

    await expect(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "codex",
          model: "gpt-5.6-sol",
          permissionMode: "approve-all",
          environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
        },
        dependencies,
      ),
    ).rejects.toThrow("admission verification exceeded its deadline");
    expect(runtime.close).toHaveBeenCalledOnce();
    expect(fixture.commandClose).toHaveBeenCalledOnce();
  });

  it("bounds post-handshake cleanup while retaining its exact owner", async () => {
    const fixture = await hostFixture();
    let finishRuntimeClose!: () => void;
    const runtimeClose = new Promise<void>((resolve) => {
      finishRuntimeClose = resolve;
    });
    const runtime = runtimePort({
      getStatus: () => new Promise<never>(() => undefined),
      onClose: () => runtimeClose,
    });
    const dependencies = fixture.dependencies({
      openRuntime: async () => runtime,
    });
    let retainedAdmissionCleanup: Promise<void> | null = null;
    dependencies.retainAdmissionCleanup = (cleanup) => {
      retainedAdmissionCleanup = cleanup;
    };
    dependencies.admissionVerificationTimeoutMs = 1;
    dependencies.admissionCleanupTimeoutMs = 1;

    await expect(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "codex",
          model: "gpt-5.6-sol",
          permissionMode: "approve-all",
          environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
        },
        dependencies,
      ),
    ).rejects.toThrow("initialization and cleanup failed");
    expect(runtime.close).toHaveBeenCalledOnce();
    expect(fixture.commandClose).toHaveBeenCalledOnce();
    expect(retainedAdmissionCleanup).not.toBeNull();
    let cleanupSettled = false;
    void retainedAdmissionCleanup!.finally(() => {
      cleanupSettled = true;
    });
    await new Promise<void>((resolve) => setTimeout(resolve, 1));
    expect(cleanupSettled).toBe(false);

    finishRuntimeClose();
    await retainedAdmissionCleanup;
    expect(cleanupSettled).toBe(true);
  });

  it("retains credential ownership when runtime shutdown fails until retry succeeds", async () => {
    const fixture = await hostFixture();
    let failClose = true;
    const runtime = runtimePort({
      onClose: vi.fn(async () => {
        if (failClose) throw new Error("runtime close failed");
      }),
    });
    const host = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "approve-all",
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}",
        },
      },
      fixture.dependencies({ openRuntime: async () => runtime }),
    );
    const authPath = join(host.runtimeRoot(), "codex-home", "auth.json");

    await expect(host.close({ reason: "first close" })).rejects.toThrow(
      /cleanup failed/,
    );
    await expect(readFile(authPath, "utf8")).resolves.toBe("{}");
    await expect(
      stageManagedCodexCredential({
        agentHomeDirectory: join(host.runtimeRoot(), "codex-home"),
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"contender"}',
        },
      }),
    ).rejects.toThrow("already has an active lease");
    expect(fixture.commandClose).toHaveBeenCalledOnce();
    failClose = false;
    await expect(
      host.close({ reason: "retry close" }),
    ).resolves.toBeUndefined();
    await expect(readFile(authPath)).rejects.toMatchObject({ code: "ENOENT" });
    const contender = await stageManagedCodexCredential({
      agentHomeDirectory: join(host.runtimeRoot(), "codex-home"),
      environment: {
        PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"contender"}',
      },
    });
    await contender.close();
  });

  it("scrubs credentials only after the exact pending runtime close resolves", async () => {
    const fixture = await hostFixture();
    let resolveRuntimeClose!: () => void;
    const runtimeClose = new Promise<void>((resolve) => {
      resolveRuntimeClose = resolve;
    });
    const runtime = runtimePort({
      onClose: vi.fn(() => runtimeClose),
    });
    const host = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "approve-all",
        environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
      },
      fixture.dependencies({ openRuntime: async () => runtime }),
    );
    const credentialHome = join(host.runtimeRoot(), "codex-home");
    const authPath = join(credentialHome, "auth.json");

    const first = host.close({ reason: "runtime close pending" });
    await waitForAcpxAdmission(() =>
      expect(runtime.close).toHaveBeenCalledOnce(),
    );
    await waitForAcpxAdmission(() =>
      expect(fixture.commandClose).toHaveBeenCalledOnce(),
    );
    const second = host.close({ reason: "same exact close" });
    await expect(readFile(authPath, "utf8")).resolves.toBe("{}");
    await expect(
      stageManagedCodexCredential({
        agentHomeDirectory: credentialHome,
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"contender"}',
        },
      }),
    ).rejects.toThrow("already has an active lease");
    expect(runtime.close).toHaveBeenCalledOnce();

    resolveRuntimeClose();
    await expect(Promise.all([first, second])).resolves.toEqual([
      undefined,
      undefined,
    ]);
    await expect(readFile(authPath)).rejects.toMatchObject({ code: "ENOENT" });
    const contender = await stageManagedCodexCredential({
      agentHomeDirectory: credentialHome,
      environment: {
        PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"contender"}',
      },
    });
    await contender.close();
  });

  it("retains the exact pending cleanup while independent resources close", async () => {
    const fixture = await hostFixture();
    const firstClose = new Promise<void>(() => undefined);
    const runtime = runtimePort({
      onClose: vi
        .fn()
        .mockImplementationOnce(() => firstClose)
        .mockResolvedValueOnce(undefined),
    });
    const host = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "approve-all",
        environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
      },
      fixture.dependencies({ openRuntime: async () => runtime }),
    );

    const first = host.close({ reason: "first close stalls" });
    await waitForAcpxAdmission(() =>
      expect(runtime.close).toHaveBeenCalledOnce(),
    );
    const second = host.close({ reason: "same pending owner" });
    let settled = false;
    void Promise.all([first, second]).finally(() => {
      settled = true;
    });
    await Promise.resolve();
    expect(settled).toBe(false);
    expect(runtime.close).toHaveBeenCalledOnce();
    expect(fixture.commandClose).toHaveBeenCalledOnce();
  });

  it("retries only after the exact close outcome settles with failure", async () => {
    const fixture = await hostFixture();
    const runtime = runtimePort({
      onClose: vi
        .fn()
        .mockRejectedValueOnce(new Error("runtime close failed"))
        .mockResolvedValueOnce(undefined),
    });
    const host = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "approve-all",
        environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
      },
      fixture.dependencies({ openRuntime: async () => runtime }),
    );

    await expect(host.close({ reason: "first close" })).rejects.toThrow(
      /cleanup failed/,
    );
    await expect(
      host.close({ reason: "fresh attempt" }),
    ).resolves.toBeUndefined();
    await expect(
      host.close({ reason: "ownership released" }),
    ).resolves.toBeUndefined();
    expect(runtime.close).toHaveBeenCalledTimes(2);
  });

  it("admits one bounded turn and cancels it before shutdown", async () => {
    const fixture = await hostFixture();
    const turn = runtimeTurn();
    const startTurn = vi.fn(() => turn);
    const onElicitation = vi.fn();
    const runtime = runtimePort({ startTurn });
    const host = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "approve-reads",
        environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
      },
      fixture.dependencies({ openRuntime: async () => runtime }),
    );

    expect(
      host.startTurn({
        text: "Complete the task.",
        requestId: "turn-1",
        onElicitation,
      }),
    ).toBe(turn);
    expect(startTurn).toHaveBeenCalledWith({
      text: "Complete the task.",
      requestId: "turn-1",
      onElicitation,
    });
    expect(() =>
      host.startTurn({ text: "Concurrent", requestId: "turn-2" }),
    ).toThrow("already has an active turn");

    await host.interruptActiveTurn("user interrupt");
    expect(turn.cancel).toHaveBeenCalledWith({ reason: "user interrupt" });

    await host.close({ reason: "shutdown" });
    expect(turn.cancel).toHaveBeenCalledWith({ reason: "shutdown" });
    expect(runtime.close).toHaveBeenCalledOnce();
    expect(() => host.startTurn({ text: "Late", requestId: "turn-3" })).toThrow(
      "is closing",
    );
  });

  it("rejects oversized turn inputs before calling the runtime", async () => {
    const fixture = await hostFixture();
    const runtime = runtimePort();
    const host = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "approve-reads",
        environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
      },
      fixture.dependencies({ openRuntime: async () => runtime }),
    );

    expect(() => host.startTurn({ text: "ok", requestId: " " })).toThrow(
      "request id",
    );
    expect(() =>
      host.startTurn({ text: "x".repeat(1024 * 1024 + 1), requestId: "turn" }),
    ).toThrow("turn text");
    expect(runtime.startTurn).not.toHaveBeenCalled();
    await host.close({ reason: "complete" });
  });

  it("cleans runtime resources after a turn cancellation timeout", async () => {
    vi.useFakeTimers();
    try {
      const fixture = await hostFixture();
      const turn = runtimeTurn();
      turn.cancel.mockImplementation(() => new Promise(() => undefined));
      const runtime = runtimePort({ startTurn: () => turn });
      const host = await AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "codex",
          model: "gpt-5.6-sol",
          permissionMode: "approve-reads",
          environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
        },
        fixture.dependencies({ openRuntime: async () => runtime }),
      );
      host.startTurn({ text: "Complete the task.", requestId: "turn-1" });

      const closing = host.close({ reason: "shutdown" });
      await vi.advanceTimersByTimeAsync(2_000);
      await expect(closing).rejects.toThrow(/cleanup failed/);
      expect(turn.cancel).toHaveBeenCalledOnce();
      expect(runtime.close).toHaveBeenCalledOnce();
      expect(fixture.commandClose).toHaveBeenCalledOnce();
      await expect(
        host.close({ reason: "observe completed cleanup" }),
      ).resolves.toBeUndefined();
      expect(turn.cancel).toHaveBeenCalledOnce();
      expect(runtime.close).toHaveBeenCalledOnce();
      expect(fixture.commandClose).toHaveBeenCalledOnce();
    } finally {
      vi.useRealTimers();
    }
  });

  it("retains the cancellation handle while runtime cleanup remains retryable", async () => {
    const fixture = await hostFixture();
    const turn = runtimeTurn();
    let failRuntimeClose = true;
    const runtime = runtimePort({
      startTurn: () => turn,
      onClose: async () => {
        if (failRuntimeClose) throw new Error("runtime cleanup failed");
      },
    });
    const host = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "approve-reads",
        environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
      },
      fixture.dependencies({ openRuntime: async () => runtime }),
    );
    host.startTurn({ text: "Complete the task.", requestId: "turn-1" });
    const credentialHome = join(host.runtimeRoot(), "codex-home");
    const authPath = join(credentialHome, "auth.json");

    await expect(host.close({ reason: "first shutdown" })).rejects.toThrow(
      /cleanup failed/,
    );
    expect(turn.cancel).toHaveBeenCalledOnce();
    await expect(readFile(authPath, "utf8")).resolves.toBe("{}");
    await expect(
      stageManagedCodexCredential({
        agentHomeDirectory: credentialHome,
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"contender"}',
        },
      }),
    ).rejects.toThrow("already has an active lease");

    failRuntimeClose = false;
    await expect(
      host.close({ reason: "retry shutdown" }),
    ).resolves.toBeUndefined();
    expect(turn.cancel).toHaveBeenCalledTimes(2);
    expect(runtime.close).toHaveBeenCalledTimes(2);
    await expect(readFile(authPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("retains a settled turn when shutdown cleanup must be retried", async () => {
    const fixture = await hostFixture();
    let settleTurn!: (value: { stopReason: string }) => void;
    const turn = {
      ...runtimeTurn(),
      result: new Promise<{ stopReason: string }>((resolve) => {
        settleTurn = resolve;
      }),
    };
    let failRuntimeClose = true;
    const runtime = runtimePort({
      startTurn: () => turn,
      onClose: async () => {
        if (failRuntimeClose) throw new Error("runtime cleanup failed");
      },
    });
    const host = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "approve-reads",
        environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
      },
      fixture.dependencies({ openRuntime: async () => runtime }),
    );
    host.startTurn({ text: "Complete the task.", requestId: "turn-1" });

    const firstClose = host.close({ reason: "first shutdown" });
    settleTurn({ stopReason: "end_turn" });
    await expect(firstClose).rejects.toThrow(/cleanup failed/);
    expect(turn.cancel).toHaveBeenCalledOnce();

    failRuntimeClose = false;
    await expect(
      host.close({ reason: "retry shutdown" }),
    ).resolves.toBeUndefined();
    expect(turn.cancel).toHaveBeenCalledTimes(2);
    expect(runtime.close).toHaveBeenCalledTimes(2);
  });

  it("closes a command lease that resolves after admission is aborted", async () => {
    const fixture = await hostFixture();
    const commandAdmission = deferred<VerifiedAcpxCommandLease>();
    const commandAdmissionStarted = deferred<void>();
    const lateCommandClose = vi.fn(async () => undefined);
    const openCommand = vi.fn(() => {
      commandAdmissionStarted.resolve(undefined);
      return commandAdmission.promise;
    });
    const openRuntime = vi.fn(async () => runtimePort());
    const controller = trackedAdmissionController();
    const cancellation = new Error("command admission cancelled");
    const profile = resolveQualifiedAcpxProfile("claude", "claude-sonnet-5");
    const opening = trackAdmissionOpening(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "claude",
          model: "claude-sonnet-5",
          permissionMode: "deny-all",
          signal: controller.signal,
        },
        {
          verifyInstallation: async () => ({
            commandDigest: profile.commandDigest,
            agentServerPackageJsonPath: join(fixture.root, "package.json"),
            agentRuntimePackageJsonPath: null,
            openCommand,
          }),
          openRuntime,
          retainAdmissionCleanup: trackAdmissionCleanup,
          reportRetainedCleanupFailure: vi.fn(),
        },
      ),
    );
    await commandAdmissionStarted.promise;
    await waitForAcpxAdmission(() =>
      expect(openCommand).toHaveBeenCalledOnce(),
    );

    controller.abort(cancellation);
    await expect(opening).rejects.toBe(cancellation);
    commandAdmission.resolve({
      spawn: () => {
        throw new Error("late command must not spawn");
      },
      close: lateCommandClose,
    });

    await waitForAcpxAdmission(() =>
      expect(lateCommandClose).toHaveBeenCalledOnce(),
    );
    expect(openRuntime).not.toHaveBeenCalled();
  });

  it("closes a credential lease that resolves after admission is aborted", async () => {
    const fixture = await hostFixture();
    const lateCredentialPath = join(fixture.root, "late-auth.json");
    await writeFile(lateCredentialPath, '{"access_token":"canary"}');
    const credentialAdmission = deferred<{
      path: string;
      mode: "inline_json";
      lifetimeFenceFds: readonly [number, number];
      activateLifetimeOwner(pid: number): Promise<void>;
      close(): Promise<void>;
    }>();
    const cleanupFailure = new Error("transient credential cleanup failure");
    let cleanupAttempts = 0;
    const lateCredentialClose = vi.fn(async () => {
      cleanupAttempts += 1;
      if (cleanupAttempts === 1) throw cleanupFailure;
      await rm(lateCredentialPath);
    });
    const reportRetainedCleanupFailure = vi.fn();
    const credentialAdmissionStarted = deferred<void>();
    const stageCredential = vi.fn(() => {
      credentialAdmissionStarted.resolve(undefined);
      return credentialAdmission.promise;
    });
    const openRuntime = vi.fn(async () => runtimePort());
    const controller = trackedAdmissionController();
    const cancellation = new Error("credential admission cancelled");
    const opening = trackAdmissionOpening(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "codex",
          model: "gpt-5.6-sol",
          permissionMode: "deny-all",
          signal: controller.signal,
        },
        {
          ...fixture.dependencies({
            openRuntime,
            reportRetainedCleanupFailure,
          }),
          stageCredential,
        },
      ),
    );
    await credentialAdmissionStarted.promise;
    await waitForAcpxAdmission(() =>
      expect(stageCredential).toHaveBeenCalledOnce(),
    );

    controller.abort(cancellation);
    await expect(opening).rejects.toBe(cancellation);
    credentialAdmission.resolve({
      path: lateCredentialPath,
      mode: "inline_json",
      lifetimeFenceFds: [42, 43],
      activateLifetimeOwner: async () => undefined,
      close: lateCredentialClose,
    });

    await waitForAcpxAdmission(() =>
      expect(lateCredentialClose).toHaveBeenCalledTimes(2),
    );
    await waitForAcpxAdmission(async () =>
      expect(readFile(lateCredentialPath)).rejects.toMatchObject({
        code: "ENOENT",
      }),
    );
    expect(reportRetainedCleanupFailure).toHaveBeenCalledOnce();
    expect(reportRetainedCleanupFailure).toHaveBeenCalledWith({
      resource: "credential",
      attempt: 1,
      error: cleanupFailure,
    });
    expect(openRuntime).not.toHaveBeenCalled();
    expect(fixture.commandClose).not.toHaveBeenCalled();
  });

  it("retains managed credentials until an aborted late runtime is closed", async () => {
    const fixture = await hostFixture();
    const runtimeAdmission = deferred<AcpxRuntimePort>();
    const runtimeAdmissionStarted = deferred<void>();
    const retryClose = deferred<void>();
    const lateRuntime = runtimePort({
      onClose: vi
        .fn()
        .mockRejectedValueOnce(new Error("late runtime close failed"))
        .mockImplementationOnce(() => retryClose.promise),
    });
    let receivedSignal: AbortSignal | undefined;
    let credentialHome = "";
    let bridgeUrl = "";
    const openRuntime = vi.fn((options) => {
      receivedSignal = options.signal;
      credentialHome = options.launchEnvironment.CODEX_HOME!;
      bridgeUrl = options.mcpServers[0]!.url;
      runtimeAdmissionStarted.resolve(undefined);
      return runtimeAdmission.promise;
    });
    const controller = trackedAdmissionController();
    const cancellation = new Error("runtime admission cancelled");
    const opening = trackAdmissionOpening(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "codex",
          model: "gpt-5.6-sol",
          permissionMode: "deny-all",
          environment: {
            PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}",
          },
          signal: controller.signal,
          semanticTools: {
            tools: [],
            handler: async () => ({ ok: true }),
          },
        },
        fixture.dependencies({ openRuntime }),
      ),
    );
    await runtimeAdmissionStarted.promise;
    await waitForAcpxAdmission(() =>
      expect(openRuntime).toHaveBeenCalledOnce(),
    );
    expect(receivedSignal).toBe(controller.signal);

    controller.abort(cancellation);
    await expect(opening).rejects.toBe(cancellation);
    expect(fixture.commandClose).toHaveBeenCalledOnce();
    await expect(fetch(bridgeUrl)).rejects.toThrow();
    const authPath = join(credentialHome, "auth.json");
    await expect(readFile(authPath, "utf8")).resolves.toBe("{}");
    await expect(
      stageManagedCodexCredential({
        agentHomeDirectory: credentialHome,
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"contender"}',
        },
      }),
    ).rejects.toThrow("already has an active lease");

    runtimeAdmission.resolve(lateRuntime);
    await waitForAcpxAdmission(() =>
      expect(lateRuntime.close).toHaveBeenCalledTimes(2),
    );
    expect(lateRuntime.close).toHaveBeenNthCalledWith(1, {
      reason: "ACPX runtime admission aborted",
    });
    await expect(readFile(authPath, "utf8")).resolves.toBe("{}");
    await expect(
      stageManagedCodexCredential({
        agentHomeDirectory: credentialHome,
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"contender"}',
        },
      }),
    ).rejects.toThrow("already has an active lease");

    retryClose.resolve(undefined);
    await waitForAcpxAdmission(async () => {
      await expect(readFile(authPath)).rejects.toMatchObject({
        code: "ENOENT",
      });
    });
    // File removal precedes kernel lease release. Wait for the lease itself so
    // this assertion cannot race between those two ordered cleanup steps.
    const contender = await waitForAcpxAdmission(() =>
      stageManagedCodexCredential({
        agentHomeDirectory: credentialHome,
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"contender"}',
        },
      }),
    );
    await contender.close();
  });

  it("scrubs credentials after rejected runtime cleanup is proven", async () => {
    const fixture = await hostFixture();
    const runtimeAdmission = deferred<AcpxRuntimePort>();
    const runtimeAdmissionStarted = deferred<void>();
    const providerCleanup = deferred<void>();
    const credentialClose = vi.fn(async () => undefined);
    const controller = trackedAdmissionController();
    const cancellation = new Error("runtime admission cancelled");
    const openRuntime = vi.fn((options: AcpxRuntimePortOpenOptions) => {
      options.retainFailedAdmissionCleanup(providerCleanup.promise);
      runtimeAdmissionStarted.resolve(undefined);
      return runtimeAdmission.promise;
    });
    const opening = trackAdmissionOpening(
      AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "codex",
          model: "gpt-5.6-sol",
          permissionMode: "deny-all",
          signal: controller.signal,
        },
        {
          ...fixture.dependencies({ openRuntime }),
          stageCredential: async () => ({
            path: join(fixture.root, "auth.json"),
            mode: "inline_json",
            lifetimeFenceFds: [42, 43],
            activateLifetimeOwner: async () => undefined,
            close: credentialClose,
          }),
        },
      ),
    );
    await runtimeAdmissionStarted.promise;
    await waitForAcpxAdmission(() =>
      expect(openRuntime).toHaveBeenCalledOnce(),
    );

    controller.abort(cancellation);
    await expect(opening).rejects.toBe(cancellation);
    const cleanupFailure = new Error("provider survived forced cleanup");
    runtimeAdmission.reject(new AggregateError([cancellation, cleanupFailure]));
    await new Promise((resolve) => setImmediate(resolve));

    expect(credentialClose).not.toHaveBeenCalled();
    expect(fixture.commandClose).toHaveBeenCalledOnce();

    providerCleanup.resolve(undefined);
    await waitForAcpxAdmission(() =>
      expect(credentialClose).toHaveBeenCalledOnce(),
    );
  });

  it("removes an abandoned sandbox root once its delayed preparation settles after abort", async () => {
    const fixture = await hostFixture();
    const rootGate = deferred<void>();
    const prepareSandbox: NonNullable<
      AcpxRuntimeHostDependencies["prepareSandbox"]
    > = vi.fn((input) =>
      prepareAcpxRuntimeSandbox(input, {
        afterRootOwned: () => rootGate.promise,
      }),
    );
    const openRuntime = vi.fn(async () => runtimePort());
    const controller = new AbortController();
    const cancellation = new Error("sandbox admission cancelled");

    const unhandled: unknown[] = [];
    const onUnhandledRejection = (reason: unknown) => {
      unhandled.push(reason);
    };
    process.on("unhandledRejection", onUnhandledRejection);
    try {
      const opening = AcpxRuntimeHost.open(
        {
          ...fixture.options,
          agent: "claude",
          model: "claude-sonnet-5",
          permissionMode: "deny-all",
          signal: controller.signal,
        },
        {
          ...fixture.dependencies({ openRuntime }),
          prepareSandbox,
        },
      );
      await waitForAcpxAdmission(() =>
        expect(prepareSandbox).toHaveBeenCalledOnce(),
      );

      controller.abort(cancellation);
      await expect(opening).rejects.toBe(cancellation);
      expect(openRuntime).not.toHaveBeenCalled();

      rootGate.resolve();
      const sandbox: AcpxRuntimeSandbox =
        await prepareSandbox.mock.results[0]!.value;
      await waitForAcpxAdmission(() =>
        expect(stat(sandbox.root)).rejects.toMatchObject({ code: "ENOENT" }),
      );

      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(unhandled).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandledRejection);
    }
  });

  it("keeps a later admission's live root when an earlier aborted admission's cleanup settles late", async () => {
    const fixture = await hostFixture();
    const rootGate = deferred<void>();
    const prepareSandbox: NonNullable<
      AcpxRuntimeHostDependencies["prepareSandbox"]
    > = vi.fn((input) =>
      prepareAcpxRuntimeSandbox(input, {
        afterRootOwned: () => rootGate.promise,
      }),
    );
    const firstOpenRuntime = vi.fn(async () => runtimePort());
    const controller = new AbortController();
    const cancellation = new Error("first admission cancelled");

    const opening = AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "deny-all",
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"first"}',
        },
        signal: controller.signal,
      },
      {
        ...fixture.dependencies({ openRuntime: firstOpenRuntime }),
        prepareSandbox,
      },
    );
    await waitForAcpxAdmission(() =>
      expect(prepareSandbox).toHaveBeenCalledOnce(),
    );

    controller.abort(cancellation);
    await expect(opening).rejects.toBe(cancellation);
    expect(firstOpenRuntime).not.toHaveBeenCalled();

    // A second, independent admission for the same normalized session id
    // resolves to the same deterministic root while the first admission's
    // cleanup is still pending behind the gate.
    const secondRuntime = runtimePort();
    const secondHost = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "deny-all",
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"second"}',
        },
      },
      fixture.dependencies({ openRuntime: async () => secondRuntime }),
    );
    const authPath = join(secondHost.runtimeRoot(), "codex-home", "auth.json");
    await expect(readFile(authPath, "utf8")).resolves.toContain("second");

    // Let the first admission's delayed sandbox preparation finish and its
    // retained cleanup run. A superseded owner must leave the live root
    // alone.
    rootGate.resolve();
    await prepareSandbox.mock.results[0]!.value;
    await new Promise((resolve) => setTimeout(resolve, 50));
    await expect(readFile(authPath, "utf8")).resolves.toContain("second");

    await secondHost.close({ reason: "test complete" });
  });

  it("lets a later admission claim and clean up its own abort once the owning admission closes", async () => {
    const fixture = await hostFixture();
    const firstRuntime = runtimePort();
    const firstHost = await AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "deny-all",
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"first"}',
        },
      },
      fixture.dependencies({ openRuntime: async () => firstRuntime }),
    );
    const root = firstHost.runtimeRoot();

    // Closing the first admission releases its exclusive claim on the root
    // without deleting it, so a later admission for the same session can
    // claim the root outright instead of being declined.
    await firstHost.close({ reason: "first admission complete" });

    const rootGate = deferred<void>();
    const prepareSandbox: NonNullable<
      AcpxRuntimeHostDependencies["prepareSandbox"]
    > = vi.fn((input) =>
      prepareAcpxRuntimeSandbox(input, {
        afterRootOwned: () => rootGate.promise,
      }),
    );
    const openRuntime = vi.fn(async () => runtimePort());
    const controller = new AbortController();
    const cancellation = new Error("second admission cancelled");

    const opening = AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "deny-all",
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"owner":"second"}',
        },
        signal: controller.signal,
      },
      {
        ...fixture.dependencies({ openRuntime }),
        prepareSandbox,
      },
    );
    await waitForAcpxAdmission(() =>
      expect(prepareSandbox).toHaveBeenCalledOnce(),
    );

    controller.abort(cancellation);
    await expect(opening).rejects.toBe(cancellation);
    expect(openRuntime).not.toHaveBeenCalled();

    rootGate.resolve();
    await waitForAcpxAdmission(() =>
      expect(stat(root)).rejects.toMatchObject({ code: "ENOENT" }),
    );
  });

  it("removes a codex credential staged after an aborted admission's sandbox preparation resolves", async () => {
    const fixture = await hostFixture();
    const rootGate = deferred<void>();
    const prepareSandbox: NonNullable<
      AcpxRuntimeHostDependencies["prepareSandbox"]
    > = vi.fn(async (input) => {
      const sandbox = await prepareAcpxRuntimeSandbox(input, {
        afterRootOwned: () => rootGate.promise,
      });
      // Stage a real Codex credential into the sandbox before it is handed
      // back, so the root that gets removed later is not empty: it must
      // sweep a credential staged after the sandbox itself was built too.
      await stageManagedCodexCredential({
        agentHomeDirectory: sandbox.agentHomeDirectory,
        environment: {
          PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: '{"staged":"after-abort"}',
        },
      });
      return sandbox;
    });
    const openRuntime = vi.fn(async () => runtimePort());
    const controller = new AbortController();
    const cancellation = new Error(
      "sandbox admission cancelled before credential staging",
    );

    const opening = AcpxRuntimeHost.open(
      {
        ...fixture.options,
        agent: "codex",
        model: "gpt-5.6-sol",
        permissionMode: "deny-all",
        environment: { PAPERCLIP_ACPX_CODEX_AUTH_JSON_SECRET: "{}" },
        signal: controller.signal,
      },
      {
        ...fixture.dependencies({ openRuntime }),
        prepareSandbox,
      },
    );
    await waitForAcpxAdmission(() =>
      expect(prepareSandbox).toHaveBeenCalledOnce(),
    );

    controller.abort(cancellation);
    await expect(opening).rejects.toBe(cancellation);
    expect(openRuntime).not.toHaveBeenCalled();

    rootGate.resolve();
    const sandbox: AcpxRuntimeSandbox =
      await prepareSandbox.mock.results[0]!.value;
    const authPath = join(sandbox.agentHomeDirectory, "auth.json");
    await expect(readFile(authPath, "utf8")).resolves.toContain("staged");

    await waitForAcpxAdmission(() =>
      expect(readFile(authPath)).rejects.toMatchObject({ code: "ENOENT" }),
    );
    await expect(stat(sandbox.root)).rejects.toMatchObject({ code: "ENOENT" });
  });
});

function runtimePort(
  input: {
    getStatus?: AcpxRuntimePort["getStatus"];
    setModel?: NonNullable<AcpxRuntimePort["setModel"]>;
    startTurn?: AcpxRuntimePort["startTurn"];
    onClose?: AcpxRuntimePort["close"];
  } = {},
): AcpxRuntimePort & { close: ReturnType<typeof vi.fn> } {
  return {
    identity: async () => ({
      acpxRecordId: "record-1",
      backendSessionId: "backend-1",
      agentSessionId: "agent-1",
    }),
    getStatus:
      input.getStatus ??
      (async () => ({
        models: {
          currentModelId: "gpt-5.6-sol",
          availableModelIds: ["gpt-5.6-sol"],
        },
      })),
    ...(input.setModel ? { setModel: input.setModel } : {}),
    startTurn: vi.fn(input.startTurn ?? (() => runtimeTurn())),
    close: vi.fn(input.onClose ?? (async () => undefined)),
  };
}

function runtimeTurn(): AcpxRuntimeTurn & {
  cancel: ReturnType<typeof vi.fn>;
} {
  return {
    requestId: "turn-1",
    promptStarted: Promise.resolve(),
    events: {
      async *[Symbol.asyncIterator]() {
        yield { type: "text_delta" as const, text: "done" };
      },
    },
    result: new Promise(() => undefined),
    cancel: vi.fn(async () => undefined),
    closeStream: vi.fn(async () => undefined),
  };
}

async function hostFixture() {
  const root = await mkdtemp(join(tmpdir(), "paperclip-acpx-host-"));
  temporaryDirectories.push(root);
  const runtimeDirectory = join(root, "runtime");
  const workingDirectory = join(root, "workspace");
  await Promise.all([mkdir(runtimeDirectory), mkdir(workingDirectory)]);
  const commandClose = vi.fn(async () => undefined);
  const command: VerifiedAcpxCommandLease = {
    spawn: () => {
      throw new Error("test command is not spawnable");
    },
    close: commandClose,
  };
  return {
    root,
    commandClose,
    options: {
      runtimeDirectory,
      normalizedSessionId: "normalized-session-1",
      workingDirectory,
    },
    dependencies(
      input: Pick<AcpxRuntimeHostDependencies, "openRuntime"> &
        Partial<
          Pick<AcpxRuntimeHostDependencies, "reportRetainedCleanupFailure">
        >,
    ): AcpxRuntimeHostDependencies {
      return {
        verifyInstallation: async (profile) =>
          ({
            commandDigest: profile.commandDigest,
            agentServerPackageJsonPath: join(root, "package.json"),
            agentRuntimePackageJsonPath: null,
            openCommand: async () => command,
          }) satisfies VerifiedAcpxInstallation,
        openRuntime: input.openRuntime,
        retainAdmissionCleanup: trackAdmissionCleanup,
        reportRetainedCleanupFailure:
          input.reportRetainedCleanupFailure ?? vi.fn(),
      };
    },
  };
}

function trackedAdmissionController(): AbortController {
  const controller = new AbortController();
  admissionControllers.push(controller);
  return controller;
}

function trackAdmissionOpening<T>(opening: Promise<T>): Promise<T> {
  trackSettledPromise(pendingAdmissionOpenings, opening);
  return opening;
}

function trackAdmissionCleanup(cleanup: Promise<void>): void {
  trackSettledPromise(pendingAdmissionCleanups, cleanup);
}

function trackSettledPromise<T>(
  pending: Set<Promise<void>>,
  promise: Promise<T>,
): void {
  const observed = promise.then(
    () => undefined,
    () => undefined,
  );
  pending.add(observed);
  void observed.finally(() => pending.delete(observed));
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(reason: unknown): void;
} {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((settle, fail) => {
    resolve = settle;
    reject = fail;
  });
  return { promise, resolve, reject };
}
