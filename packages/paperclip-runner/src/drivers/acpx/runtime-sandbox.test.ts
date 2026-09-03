import { spawnSync } from "node:child_process";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  rename,
  rm,
  stat,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { resolveQualifiedAcpxProfile } from "./qualified-profiles.js";
import { createAcpxRecoveryBinding } from "./recovery-identity.js";
import {
  prepareAcpxRuntimeSandbox,
  readAcpxRecoveryWorkspace,
  releaseAcpxRuntimeSandboxRootClaim,
  removeOwnedAcpxRuntimeSandboxRoot,
} from "./runtime-sandbox.js";

const CONCURRENT_CLAIM_HEAD_START_MS = 25;

/** Gives a concurrently kicked-off claim a real chance to run ahead, so a
 * later "did not settle yet" check is meaningful rather than incidental. */
function waitForConcurrentClaimHeadStart(): Promise<void> {
  return new Promise((resolve) =>
    setTimeout(resolve, CONCURRENT_CLAIM_HEAD_START_MS),
  );
}

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("ACPX runtime sandbox", () => {
  it.each([
    ["pi", "OPENROUTER_API_KEY", "pi-home"],
    ["claude", "ANTHROPIC_API_KEY", "claude-home"],
    ["codex", "OPENAI_API_KEY", "codex-home"],
  ] as const)(
    "creates a private %s filesystem and split environment",
    async (agent, credentialName, homeSuffix) => {
      const fixture = await sandboxFixture(agent);
      const sandbox = await prepareAcpxRuntimeSandbox({
        binding: fixture.binding,
        agent,
        environment: {
          PATH: process.env.PATH,
          [credentialName]: "provider-secret",
          UNRELATED_SECRET: "must-not-enter",
          HTTPS_PROXY: "https://proxy-user:proxy-password@example.test",
          PAPERCLIP_NATIVE_MCP_URL:
            "https://mcp.example.test/connect?ticket=secret",
          PAPERCLIP_NATIVE_MCP_TOKEN: "native-secret",
        },
      });

      expect(sandbox.agentHomeDirectory).toContain(homeSuffix);
      expect(sandbox.launchEnvironment[credentialName]).toBe("provider-secret");
      expect(sandbox.launchEnvironment.HTTPS_PROXY).toContain("proxy-password");
      expect(sandbox.launchEnvironment.UNRELATED_SECRET).toBeUndefined();
      expect(
        sandbox.launchEnvironment.PAPERCLIP_NATIVE_MCP_TOKEN,
      ).toBeUndefined();
      expect(sandbox.launchEnvironment.HOME).toBe(sandbox.homeDirectory);
      expect(sandbox.launchEnvironment.XDG_CONFIG_HOME).toBe(
        sandbox.configDirectory,
      );
      expect(sandbox.launchEnvironment.XDG_DATA_HOME).toBe(
        sandbox.dataDirectory,
      );
      expect(sandbox.launchEnvironment.XDG_CACHE_HOME).toBe(
        sandbox.cacheDirectory,
      );
      expect(Object.isFrozen(sandbox.launchEnvironment)).toBe(true);
      expect(sandbox.persistedEnvironment[credentialName]).toBeUndefined();
      expect(sandbox.persistedEnvironment.HTTPS_PROXY).toBeUndefined();
      expect(
        sandbox.persistedEnvironment.PAPERCLIP_NATIVE_MCP_URL,
      ).toBeUndefined();
      expect(
        sandbox.persistedEnvironment.PAPERCLIP_NATIVE_MCP_TOKEN,
      ).toBeUndefined();
      expect(sandbox.persistedEnvironment.HOME).toBe(sandbox.homeDirectory);
      expect(await readFile(sandbox.workspaceRecordPath, "utf8")).toBe(
        `${fixture.binding.workspacePath}\n`,
      );
      const recoveryWorkspace = await readAcpxRecoveryWorkspace({
        runtimeDirectory: join(fixture.root, "runtime"),
        normalizedSessionId: `sandbox-${agent}`,
      });
      expect(recoveryWorkspace.path).toBe(fixture.binding.workspacePath);
      expect(() => recoveryWorkspace.assertHeld()).not.toThrow();
      await recoveryWorkspace.close();
      expect((await lstat(sandbox.root)).isSymbolicLink()).toBe(false);
      if (process.platform !== "win32") {
        expect((await stat(sandbox.root)).mode & 0o777).toBe(0o700);
        expect((await stat(sandbox.workspaceRecordPath)).mode & 0o777).toBe(
          0o600,
        );
      }
      if (agent === "pi") {
        await expect(
          readFile(join(sandbox.agentHomeDirectory, "settings.json"), "utf8"),
        ).resolves.toContain('"defaultProjectTrust":"never"');
      }
    },
  );

  it("re-prepares and re-synchronizes an existing private sandbox", async () => {
    const fixture = await sandboxFixture("claude");
    const first = await prepareAcpxRuntimeSandbox({
      binding: fixture.binding,
      agent: "claude",
      environment: { ANTHROPIC_API_KEY: "first" },
    });
    const second = await prepareAcpxRuntimeSandbox({
      binding: fixture.binding,
      agent: "claude",
      environment: { ANTHROPIC_API_KEY: "second" },
    });

    expect(second.root).toBe(first.root);
    expect(second.launchEnvironment.ANTHROPIC_API_KEY).toBe("second");
    expect(await readFile(second.workspaceRecordPath, "utf8")).toBe(
      `${fixture.binding.workspacePath}\n`,
    );
  });

  it("removes a partially built root when preparation fails after claiming it", async () => {
    const fixture = await sandboxFixture("codex");
    const failure = new Error("simulated sandbox preparation failure");

    await expect(
      prepareAcpxRuntimeSandbox(
        { binding: fixture.binding, agent: "codex" },
        {
          afterRootOwned: async () => {
            throw failure;
          },
        },
      ),
    ).rejects.toBe(failure);

    await expect(stat(fixture.binding.runtimeRoot)).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it.runIf(process.platform !== "win32")(
    "repairs existing directory permissions through its no-follow handle",
    async () => {
      const fixture = await sandboxFixture("codex");
      const first = await prepareAcpxRuntimeSandbox({
        binding: fixture.binding,
        agent: "codex",
      });
      await chmod(first.root, 0o755);

      const second = await prepareAcpxRuntimeSandbox({
        binding: fixture.binding,
        agent: "codex",
      });

      expect(second.root).toBe(first.root);
      expect((await stat(second.root)).mode & 0o777).toBe(0o700);
    },
  );

  it.runIf(process.platform !== "win32")(
    "rejects a symbolic-link ACPX namespace",
    async () => {
      const fixture = await sandboxFixture("codex");
      const namespace = dirname(fixture.binding.runtimeRoot);
      const outside = join(fixture.root, "outside");
      await mkdir(outside);
      await symlink(outside, namespace);

      await expect(
        prepareAcpxRuntimeSandbox({
          binding: fixture.binding,
          agent: "codex",
        }),
      ).rejects.toThrow(/real directory|escaped/);
    },
  );

  it("rejects a malformed workspace recovery record", async () => {
    const fixture = await sandboxFixture("codex");
    const sandbox = await prepareAcpxRuntimeSandbox({
      binding: fixture.binding,
      agent: "codex",
    });
    const handle = await open(sandbox.workspaceRecordPath, "a");
    await handle.write("extra");
    await handle.close();

    await expect(
      readAcpxRecoveryWorkspace({
        runtimeDirectory: join(fixture.root, "runtime"),
        normalizedSessionId: "sandbox-codex",
      }),
    ).rejects.toThrow("record is invalid");
  });

  it.runIf(process.platform !== "win32")(
    "does not follow a substituted workspace recovery record",
    async () => {
      const fixture = await sandboxFixture("codex");
      const sandbox = await prepareAcpxRuntimeSandbox({
        binding: fixture.binding,
        agent: "codex",
      });
      await rm(sandbox.workspaceRecordPath);
      await symlink(fixture.binding.workspacePath, sandbox.workspaceRecordPath);

      await expect(
        readAcpxRecoveryWorkspace({
          runtimeDirectory: join(fixture.root, "runtime"),
          normalizedSessionId: "sandbox-codex",
        }),
      ).rejects.toThrow("record is unavailable");
    },
  );

  it.runIf(process.platform !== "win32")(
    "does not follow a substituted recovery session directory",
    async () => {
      const fixture = await sandboxFixture("codex");
      const sandbox = await prepareAcpxRuntimeSandbox({
        binding: fixture.binding,
        agent: "codex",
      });
      const outside = join(fixture.root, "outside-recovery");
      await mkdir(outside);
      await rm(sandbox.root, { recursive: true });
      await symlink(outside, sandbox.root);

      await expect(
        readAcpxRecoveryWorkspace({
          runtimeDirectory: join(fixture.root, "runtime"),
          normalizedSessionId: "sandbox-codex",
        }),
      ).rejects.toThrow("runtime directory is unavailable");
    },
  );

  it.runIf(process.platform !== "win32")(
    "rejects a recovery session directory swapped after its handle is pinned",
    async () => {
      const fixture = await sandboxFixture("codex");
      const sandbox = await prepareAcpxRuntimeSandbox({
        binding: fixture.binding,
        agent: "codex",
      });
      const displacedRoot = `${sandbox.root}-displaced`;

      await expect(
        readAcpxRecoveryWorkspace(
          {
            runtimeDirectory: join(fixture.root, "runtime"),
            normalizedSessionId: "sandbox-codex",
          },
          {
            afterRuntimeRootPinned: async () => {
              await rename(sandbox.root, displacedRoot);
              await mkdir(sandbox.root);
              await writeFile(
                join(sandbox.root, "workspace"),
                `${fixture.binding.workspacePath}\n`,
              );
            },
          },
        ),
      ).rejects.toThrow("workspace record is unavailable");
    },
  );

  it.runIf(process.platform !== "win32")(
    "pins the recovered workspace until provider admission",
    async () => {
      const fixture = await sandboxFixture("codex");
      await prepareAcpxRuntimeSandbox({
        binding: fixture.binding,
        agent: "codex",
      });
      const recoveryWorkspace = await readAcpxRecoveryWorkspace({
        runtimeDirectory: join(fixture.root, "runtime"),
        normalizedSessionId: "sandbox-codex",
      });
      const displacedWorkspace = `${fixture.binding.workspacePath}-displaced`;
      await rename(fixture.binding.workspacePath, displacedWorkspace);
      await mkdir(fixture.binding.workspacePath);

      expect(() => recoveryWorkspace.assertHeld()).toThrow(
        "workspace changed before provider admission",
      );
      await recoveryWorkspace.close();
    },
  );

  it("keeps a live admission's root and credential when a second, declined admission aborts", async () => {
    const fixture = await sandboxFixture("codex");
    const first = await prepareAcpxRuntimeSandbox({
      binding: fixture.binding,
      agent: "codex",
    });
    const credentialPath = join(first.agentHomeDirectory, "auth.json");
    await writeFile(credentialPath, '{"owner":"first"}\n');

    // The second admission resolves to the same deterministic root. Its own
    // claim is declined, since the first admission already owns the root's
    // exclusive marker, so it must never gain delete authority over it.
    const second = await prepareAcpxRuntimeSandbox({
      binding: fixture.binding,
      agent: "codex",
    });
    expect(second.root).toBe(first.root);

    await removeOwnedAcpxRuntimeSandboxRoot(second);

    await expect(readFile(credentialPath, "utf8")).resolves.toContain("first");
    await expect(stat(first.root)).resolves.toBeDefined();
  });

  it("keeps a live admission's root when a same-root claim declined in a fresh process registry aborts", async () => {
    const fixture = await sandboxFixture("codex");
    const first = await prepareAcpxRuntimeSandbox({
      binding: fixture.binding,
      agent: "codex",
    });
    const credentialPath = join(first.agentHomeDirectory, "auth.json");
    await writeFile(credentialPath, '{"owner":"first"}\n');

    // A second Runner process starts with an empty in-process registry.
    // Simulate that by loading a fresh module instance instead of reusing
    // this file's, so the only state the second admission can observe is
    // whatever is on disk.
    vi.resetModules();
    const secondProcess: typeof import("./runtime-sandbox.js") =
      await import("./runtime-sandbox.js");
    const second = await secondProcess.prepareAcpxRuntimeSandbox({
      binding: fixture.binding,
      agent: "codex",
    });
    expect(second.root).toBe(first.root);

    await secondProcess.removeOwnedAcpxRuntimeSandboxRoot(second);

    await expect(readFile(credentialPath, "utf8")).resolves.toContain("first");
    await expect(stat(first.root)).resolves.toBeDefined();
  });

  it("keeps a live cross-process admission's root when its owner closes and a later admission aborts", async () => {
    const fixture = await sandboxFixture("codex");
    const owner = await prepareAcpxRuntimeSandbox({
      binding: fixture.binding,
      agent: "codex",
    });

    // A second Runner process starts with an empty in-process registry. Its
    // claim on the same deterministic root is declined, since the first
    // admission already owns the marker, but it still builds a live sandbox
    // on the shared root and keeps using it.
    vi.resetModules();
    const sharingProcess: typeof import("./runtime-sandbox.js") =
      await import("./runtime-sandbox.js");
    const sharedOccupant = await sharingProcess.prepareAcpxRuntimeSandbox({
      binding: fixture.binding,
      agent: "codex",
    });
    expect(sharedOccupant.root).toBe(owner.root);
    const credentialPath = join(sharedOccupant.agentHomeDirectory, "auth.json");
    await writeFile(credentialPath, '{"owner":"shared-occupant"}\n');

    // The owner admission reaches a live host and closes normally, in its
    // own process. The shared occupant's durable lease is still on disk, so
    // this must not free the marker for reclaim by a later admission.
    await releaseAcpxRuntimeSandboxRootClaim(owner);

    // A third Runner process claims the same deterministic root. If the
    // owner's close had freed the marker, this admission would become the
    // new owner and its own later abort would delete the shared occupant's
    // still-live root.
    vi.resetModules();
    const laterProcess: typeof import("./runtime-sandbox.js") =
      await import("./runtime-sandbox.js");
    const later = await laterProcess.prepareAcpxRuntimeSandbox({
      binding: fixture.binding,
      agent: "codex",
    });
    expect(later.root).toBe(owner.root);
    await laterProcess.removeOwnedAcpxRuntimeSandboxRoot(later);

    await expect(readFile(credentialPath, "utf8")).resolves.toContain(
      "shared-occupant",
    );
    await expect(stat(owner.root)).resolves.toBeDefined();
  });

  it("never frees a marker for a concurrent claim to slip past a still-deciding release", async () => {
    const fixture = await sandboxFixture("codex");
    const first = await prepareAcpxRuntimeSandbox({
      binding: fixture.binding,
      agent: "codex",
    });
    const credentialPath = join(first.agentHomeDirectory, "auth.json");
    await writeFile(credentialPath, '{"owner":"first"}\n');

    let concurrentProcess: typeof import("./runtime-sandbox.js") | null =
      null;
    let concurrentClaim: ReturnType<typeof prepareAcpxRuntimeSandbox> | null =
      null;
    let concurrentClaimSettled = false;

    // The owner admission closes normally. Once it has decided the marker
    // is free to release, race a second, concurrent admission's claim for
    // the same deterministic root against that decision, simulated as a
    // second Runner process.
    await releaseAcpxRuntimeSandboxRootClaim(first, {
      afterLeaseCountDecision: async () => {
        vi.resetModules();
        concurrentProcess = await import("./runtime-sandbox.js");
        concurrentClaim = concurrentProcess
          .prepareAcpxRuntimeSandbox({
            binding: fixture.binding,
            agent: "codex",
          })
          .finally(() => {
            concurrentClaimSettled = true;
          });
        await waitForConcurrentClaimHeadStart();
        // The concurrent claim's own marker write needs this admission's
        // ownership gate, which this admission still holds here.
        expect(concurrentClaimSettled).toBe(false);
      },
    });

    const second = await concurrentClaim!;
    expect(second.root).toBe(first.root);
    // The concurrent claim only proceeded once the release had fully
    // finished, so it became this root's sole new owner with a fresh
    // ownership marker, rather than sharing a marker this admission was
    // about to free regardless of who else was using the root.
    await concurrentProcess!.removeOwnedAcpxRuntimeSandboxRoot(second);
    await expect(stat(first.root)).rejects.toMatchObject({ code: "ENOENT" });

    const siblingEntries = await readdir(dirname(first.root));
    expect(siblingEntries).not.toContain(`${basename(first.root)}.gate`);
  });

  it("keeps a concurrent claim's own outcome well-defined when it races an in-flight abort's delete decision", async () => {
    const fixture = await sandboxFixture("codex");
    const first = await prepareAcpxRuntimeSandbox({
      binding: fixture.binding,
      agent: "codex",
    });

    let concurrentProcess: typeof import("./runtime-sandbox.js") | null =
      null;
    let concurrentClaim: ReturnType<typeof prepareAcpxRuntimeSandbox> | null =
      null;
    let concurrentClaimSettled = false;

    // Nobody else is using the root, so this abort will delete it. Once it
    // has made that decision, race a second, concurrent admission's claim
    // for the same deterministic root against the delete itself, simulated
    // as a second Runner process.
    await removeOwnedAcpxRuntimeSandboxRoot(first, {
      afterLeaseCountDecision: async () => {
        vi.resetModules();
        concurrentProcess = await import("./runtime-sandbox.js");
        concurrentClaim = concurrentProcess
          .prepareAcpxRuntimeSandbox({
            binding: fixture.binding,
            agent: "codex",
          })
          .finally(() => {
            concurrentClaimSettled = true;
          });
        await waitForConcurrentClaimHeadStart();
        // The concurrent claim's own marker write needs this admission's
        // ownership gate, which this admission still holds here.
        expect(concurrentClaimSettled).toBe(false);
      },
    });

    // The concurrent claim was deferred until after this admission's delete
    // fully finished, so it never raced the delete itself; the deleted root
    // was never live for it to lose. It either lost the root outright and
    // failed cleanly, or it rebuilt a complete fresh one and succeeded
    // cleanly — never a half-built directory silently reported as ready.
    const outcome = await concurrentClaim!.then(
      (sandbox) => ({ ok: true as const, sandbox }),
      (error: unknown) => ({ ok: false as const, error }),
    );
    if (outcome.ok) {
      expect(outcome.sandbox.root).toBe(first.root);
      await expect(
        stat(outcome.sandbox.stateDirectory),
      ).resolves.toBeDefined();
      await concurrentProcess!.removeOwnedAcpxRuntimeSandboxRoot(
        outcome.sandbox,
      );
    } else {
      expect(outcome.error).toBeInstanceOf(Error);
    }

    const siblingEntries = await readdir(dirname(first.root));
    expect(siblingEntries).not.toContain(`${basename(first.root)}.gate`);
  });

  it("recovers a gate left behind by a holder process that no longer exists", async () => {
    const fixture = await sandboxFixture("codex");
    const probe = await prepareAcpxRuntimeSandbox({
      binding: fixture.binding,
      agent: "codex",
    });
    await releaseAcpxRuntimeSandboxRootClaim(probe);
    const gatePath = join(dirname(probe.root), `${basename(probe.root)}.gate`);

    // A holder crashed while it held the gate: write a gate file naming a
    // process that has already exited.
    const deadHolder = spawnSync(process.execPath, ["-e", "0"]);
    await writeFile(gatePath, String(deadHolder.pid), { flag: "wx" });

    const recovered = await prepareAcpxRuntimeSandbox({
      binding: fixture.binding,
      agent: "codex",
    });
    expect(recovered.root).toBe(probe.root);
    await expect(stat(gatePath)).rejects.toMatchObject({ code: "ENOENT" });
    await removeOwnedAcpxRuntimeSandboxRoot(recovered);
  });

  it("never removes a live gate that replaced the stale gate recovery inspected", async () => {
    const fixture = await sandboxFixture("codex");
    const probe = await prepareAcpxRuntimeSandbox({
      binding: fixture.binding,
      agent: "codex",
    });
    await releaseAcpxRuntimeSandboxRootClaim(probe);
    const gatePath = join(dirname(probe.root), `${basename(probe.root)}.gate`);

    // A holder crashed while it held the gate: write a gate file naming a
    // process that has already exited.
    const deadHolder = spawnSync(process.execPath, ["-e", "0"]);
    await writeFile(gatePath, String(deadHolder.pid), { flag: "wx" });

    vi.resetModules();
    const recoveringProcess: typeof import("./runtime-sandbox.js") =
      await import("./runtime-sandbox.js");

    // Once recovery has read the dead gate and proved its holder is gone,
    // but before it removes the gate by pathname, replace the file at that
    // same path with a fresh, live gate — simulating a second admission
    // that broke in on the same dead gate first and is now using it. Its
    // content names this test process, the same real process the
    // recovering call also runs in, plus a marker suffix production code
    // never writes itself: a plain pid alone cannot tell this exact
    // replacement apart from a later gate the recovering call might create
    // for its own use, since both would then name the same pid.
    const replacementGateContents = `${process.pid}:live-replacement`;
    const recovered = recoveringProcess.prepareAcpxRuntimeSandbox(
      { binding: fixture.binding, agent: "codex" },
      {
        beforeStaleGateRemoval: async () => {
          await unlink(gatePath);
          await writeFile(gatePath, replacementGateContents, { flag: "wx" });
        },
      },
    );

    await waitForConcurrentClaimHeadStart();
    // Finding anything other than this exact marker — the file gone, or a
    // fresh gate holding only this process's own acquisition token — proves
    // recovery removed the live replacement it found in place of the dead
    // gate it inspected.
    await expect(readFile(gatePath, "utf8")).resolves.toBe(
      replacementGateContents,
    );

    // Free the replacement gate, as its own holder would on completing its
    // claim, so the still-retrying recovery call above can proceed.
    await unlink(gatePath);

    const sandbox = await recovered;
    expect(sandbox.root).toBe(probe.root);
    await recoveringProcess.removeOwnedAcpxRuntimeSandboxRoot(sandbox);
  });
});

async function sandboxFixture(agent: "pi" | "claude" | "codex") {
  const root = await mkdtemp(join(tmpdir(), "paperclip-acpx-sandbox-"));
  temporaryDirectories.push(root);
  const workspace = join(root, "workspace");
  const runtimeDirectory = join(root, "runtime");
  await Promise.all([mkdir(workspace), mkdir(runtimeDirectory)]);
  const models = {
    pi: "openrouter/deepseek/deepseek-v4-flash-0731",
    claude: "claude-sonnet-5",
    codex: "gpt-5.6-sol",
  } as const;
  const binding = await createAcpxRecoveryBinding({
    runtimeDirectory,
    normalizedSessionId: `sandbox-${agent}`,
    workingDirectory: workspace,
    profile: resolveQualifiedAcpxProfile(agent, models[agent]),
    requestedModel: models[agent],
    permissionMode: "approve-reads",
  });
  return { root, binding };
}
