import { mkdir, mkdtemp, readdir, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  assertManagedCredentialHome,
  assertNoSymlinkInManagedCredentialPath,
} from "./managed-credential-home.js";

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

  /** Same as {@link setUpInstance}, but leaves the company directory itself unmade, so a test can put a symbolic link there instead. */
  async function setUpInstanceWithoutCompanyDir() {
    const homeDir = await mkdtemp(path.join(os.tmpdir(), "paperclip-managed-credential-home-"));
    cleanupDirs.push(homeDir);
    const env: NodeJS.ProcessEnv = { PAPERCLIP_HOME: homeDir, PAPERCLIP_INSTANCE_ID: "default" };
    const instanceRoot = path.join(homeDir, "instances", "default");
    const companiesRoot = path.join(instanceRoot, "companies");
    await mkdir(companiesRoot, { recursive: true });
    return { env, instanceRoot, companiesRoot };
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

  it("rejects a company-root symbolic link that points at another company's directory", async () => {
    const { env, companiesRoot } = await setUpInstanceWithoutCompanyDir();
    const companyId = "company-a";
    const otherCompanyDir = path.join(companiesRoot, "company-b");
    await mkdir(otherCompanyDir, { recursive: true });
    const companyLinkPath = path.join(companiesRoot, companyId);
    await symlink(otherCompanyDir, companyLinkPath, "dir");

    await expect(
      assertManagedCredentialHome({
        env,
        companyId,
        candidateDir: path.join(companyLinkPath, "codex-home"),
      }),
    ).rejects.toThrow("outside the company-managed directory tree");
  });

  it("rejects a company-root symbolic link that points outside the instance tree", async () => {
    const { env, companiesRoot } = await setUpInstanceWithoutCompanyDir();
    const companyId = "company-a";
    const outsideTarget = await mkdtemp(path.join(os.tmpdir(), "paperclip-outside-company-root-"));
    cleanupDirs.push(outsideTarget);
    const companyLinkPath = path.join(companiesRoot, companyId);
    await symlink(outsideTarget, companyLinkPath, "dir");

    await expect(
      assertManagedCredentialHome({
        env,
        companyId,
        candidateDir: path.join(companyLinkPath, "codex-home"),
      }),
    ).rejects.toThrow("outside the company-managed directory tree");
  });

  it("rejects a symbolic-link swap made after the check, so no token file lands at the swapped-to target", async () => {
    const { env, companyId, companyRoot } = await setUpInstance();
    const candidateDir = path.join(companyRoot, "codex-home");
    await mkdir(candidateDir, { recursive: true });

    const resolved = await assertManagedCredentialHome({ env, companyId, candidateDir });
    expect(resolved).toBe(candidateDir);

    // An attacker swaps the checked directory for a symbolic link to an
    // external target between the check above and a caller's write below.
    const externalTarget = await mkdtemp(path.join(os.tmpdir(), "paperclip-swap-target-"));
    cleanupDirs.push(externalTarget);
    await rm(candidateDir, { recursive: true, force: true });
    await symlink(externalTarget, candidateDir, "dir");

    // A caller must re-verify with a no-follow check immediately before it
    // writes. This simulates that contract: the token write only runs when
    // the re-check passes.
    async function writeTokenIfStillContained(): Promise<void> {
      await assertNoSymlinkInManagedCredentialPath(companyRoot, resolved);
      await writeFile(path.join(resolved, "auth.json"), "token-bytes");
    }

    await expect(writeTokenIfStillContained()).rejects.toThrow(
      "outside the company-managed directory tree",
    );
    expect(await readdir(externalTarget)).toEqual([]);
  });
});
