import { mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { assertManagedCredentialHome } from "./managed-credential-home.js";

describe("assertManagedCredentialHome", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    while (cleanupDirs.length > 0) {
      const dir = cleanupDirs.pop();
      if (!dir) continue;
      await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  async function setUpInstance() {
    const homeDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-managed-credential-home-"));
    cleanupDirs.push(homeDir);
    const env: NodeJS.ProcessEnv = { PAPERCLIP_HOME: homeDir, PAPERCLIP_INSTANCE_ID: "default" };
    const instanceRoot = path.join(homeDir, "instances", "default");
    const companyId = "company-a";
    const companyRoot = path.join(instanceRoot, "companies", companyId);
    await mkdir(companyRoot, { recursive: true });
    return { env, companyId, companyRoot, instanceRoot };
  }

  it("accepts the company default home", async () => {
    const { env, companyId, companyRoot } = await setUpInstance();
    const candidateDir = path.join(companyRoot, "codex-home");
    await mkdir(candidateDir, { recursive: true });

    const resolved = await assertManagedCredentialHome({ env, companyId, candidateDir });

    expect(resolved).toBe(candidateDir);
  });

  it("accepts an account home under the company root", async () => {
    const { env, companyId, companyRoot } = await setUpInstance();
    const candidateDir = path.join(companyRoot, "codex-auth-cache", "some-handle");
    await mkdir(candidateDir, { recursive: true });

    const resolved = await assertManagedCredentialHome({ env, companyId, candidateDir });

    expect(resolved).toBe(candidateDir);
  });

  it("rejects a path outside the instance root", async () => {
    const { env, companyId } = await setUpInstance();
    const outsideDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-outside-"));
    cleanupDirs.push(outsideDir);

    await expect(
      assertManagedCredentialHome({ env, companyId, candidateDir: outsideDir }),
    ).rejects.toThrow("outside the company-managed directory tree");
  });

  it("rejects a path under another company", async () => {
    const { env, companyId, instanceRoot } = await setUpInstance();
    const otherCompanyDir = path.join(instanceRoot, "companies", "company-b", "codex-home");
    await mkdir(otherCompanyDir, { recursive: true });

    await expect(
      assertManagedCredentialHome({ env, companyId, candidateDir: otherCompanyDir }),
    ).rejects.toThrow("outside the company-managed directory tree");
  });

  it("rejects a symbolic link inside the company root that points outside it", async () => {
    const { env, companyId, companyRoot } = await setUpInstance();
    const outsideTarget = await mkdtemp(path.join(os.tmpdir(), "paperclip-symlink-target-"));
    cleanupDirs.push(outsideTarget);
    const linkPath = path.join(companyRoot, "codex-home");
    await symlink(outsideTarget, linkPath, "dir");

    await expect(
      assertManagedCredentialHome({ env, companyId, candidateDir: linkPath }),
    ).rejects.toThrow("outside the company-managed directory tree");
  });

  it("rejects a relative path that escapes with \"..\"", async () => {
    const { env, companyId, companyRoot } = await setUpInstance();
    const escapingPath = path.join(companyRoot, "..", "..", "escaped");

    await expect(
      assertManagedCredentialHome({ env, companyId, candidateDir: escapingPath }),
    ).rejects.toThrow("outside the company-managed directory tree");
  });

  it("accepts a candidate directory that does not exist yet", async () => {
    const { env, companyId, companyRoot } = await setUpInstance();
    const candidateDir = path.join(companyRoot, "codex-auth-cache", "not-created-yet");

    const resolved = await assertManagedCredentialHome({ env, companyId, candidateDir });

    expect(resolved).toBe(candidateDir);
  });

  it("names no path and no identifier in its rejection message", async () => {
    const { env, companyId } = await setUpInstance();
    const outsideDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-outside-"));
    cleanupDirs.push(outsideDir);

    await expect(
      assertManagedCredentialHome({ env, companyId, candidateDir: outsideDir }),
    ).rejects.toThrow(/^The credential home is outside the company-managed directory tree\.$/);
  });
});
