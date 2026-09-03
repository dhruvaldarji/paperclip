import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { Worker } from "node:worker_threads";
import { afterEach, describe, expect, it } from "vitest";
import {
  withWorktreePortRegistryLock,
  withWorktreePortRegistryLockSync,
} from "./worktree-port-registry.js";

const temporaryRoots: string[] = [];

function makeTemporaryRoot(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "paperclip-port-registry-lock-"));
  temporaryRoots.push(root);
  return root;
}

// Answers the same one-exchange ownership probe protocol the real lock
// heartbeat serves, so a test can hold a lock's "owner is alive and
// responsive" state without a live heartbeat thread touching the lock's
// mtime in the background. This runs on its own worker thread, not the
// main thread, because the code under test blocks the calling thread
// (Atomics.wait) while it waits for a probe answer; a same-thread server
// could never respond to its own blocked caller.
const FAKE_OWNERSHIP_PROBE_SOURCE = `
const net = require("node:net");
const { parentPort, workerData } = require("node:worker_threads");
const control = new Int32Array(workerData.control);
const server = net.createServer((socket) => {
  socket.once("data", (candidate) => {
    socket.end(candidate.toString("utf8") === workerData.token ? "owned" : "denied");
  });
});
server.once("error", () => {
  Atomics.store(control, 0, -1);
  Atomics.notify(control, 0);
});
server.listen(0, "127.0.0.1", () => {
  const address = server.address();
  Atomics.store(control, 1, address.port);
  Atomics.store(control, 0, 1);
  Atomics.notify(control, 0);
});
parentPort.once("message", () => {
  server.close(() => process.exit(0));
});
`;

function startFakeOwnershipProbe(token: string): { port: number; close: () => Promise<void> } {
  const control = new Int32Array(new SharedArrayBuffer(8));
  const worker = new Worker(FAKE_OWNERSHIP_PROBE_SOURCE, {
    eval: true,
    execArgv: [],
    workerData: { control: control.buffer, token },
  });
  Atomics.wait(control, 0, 0, 2_000);
  const port = Atomics.load(control, 1);
  if (Atomics.load(control, 0) !== 1 || port <= 0) {
    void worker.terminate();
    throw new Error("The fake ownership probe failed to start.");
  }
  return {
    port,
    close: () => new Promise<void>((resolve) => {
      worker.once("exit", () => resolve());
      worker.postMessage("stop");
    }),
  };
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

describe("worktree port registry lock", () => {
  it("does not reclaim a stale lock while its fallback ownership probe responds", async () => {
    const homeDir = makeTemporaryRoot();
    const lockPath = path.join(homeDir, ".worktree-port-reservations.lock");
    const token = "fixed-owner-token";
    const probe = startFakeOwnershipProbe(token);

    // Build the contended state directly instead of holding the lock through
    // a real withWorktreePortRegistryLock call. A real call starts a live
    // heartbeat that rewrites the lock's mtime once a second on a worker
    // thread. That refresh runs concurrently with, and can land inside, the
    // gap between this test backdating the mtime and reading it back, which
    // made the assertion below fail at random under CPU contention. With no
    // live heartbeat, nothing touches the mtime until this test says so.
    fs.mkdirSync(lockPath);
    fs.writeFileSync(
      path.join(lockPath, "owner.json"),
      `${JSON.stringify({
        version: 1,
        pid: process.pid,
        // Deliberately wrong, so a reclaim can only be blocked by the probe
        // answering "owned" below, not by the process-identity fallback.
        processIdentity: "mismatched-process-identity",
        probePort: probe.port,
        token,
      })}\n`,
    );
    const oldTimestamp = new Date(Date.now() - 10_000);
    fs.utimesSync(lockPath, oldTimestamp, oldTimestamp);

    // Nothing refreshes the lock after this point, so its age only grows.
    expect(Date.now() - fs.statSync(lockPath).mtimeMs).toBeGreaterThan(5_000);

    let secondEntered = false;
    const second = withWorktreePortRegistryLock(homeDir, async () => {
      secondEntered = true;
    });
    // The lock never looks fresh (nothing refreshes its mtime), so every
    // retry re-probes the owner, each probe launching its own worker
    // thread. A long wait here invites many retries and stacks up worker
    // launches for no added signal; one retry cycle is already enough to
    // show the lock is not reclaimed while the probe answers.
    await delay(30);

    expect(secondEntered).toBe(false);

    // Retire the owner: the probe stops answering, so the next reclaim
    // attempt falls through to the process-identity check, which the
    // mismatched identity above fails, and the lock is reclaimed.
    await probe.close();
    await second;
    expect(secondEntered).toBe(true);
  }, 10_000);

  it("refreshes the lease throughout an async critical section", async () => {
    const homeDir = makeTemporaryRoot();
    const lockPath = path.join(homeDir, ".worktree-port-reservations.lock");

    await withWorktreePortRegistryLock(homeDir, async () => {
      await delay(5_250);
      // The heartbeat's only correctness job is to keep the lock's mtime
      // below the staleness threshold (5 seconds) while the lock is held.
      // A tighter bound, such as one heartbeat interval, ties the assertion
      // to CPU-bound worker-thread scheduling and fails at random under
      // load. The threshold itself is what a contender relies on, so assert
      // against it directly.
      expect(Date.now() - fs.statSync(lockPath).mtimeMs).toBeLessThan(5_000);
    });

    expect(fs.existsSync(lockPath)).toBe(false);
  }, 10_000);

  it("reclaims an old lock after its owner process exits", async () => {
    const homeDir = makeTemporaryRoot();
    const lockPath = path.join(homeDir, ".worktree-port-reservations.lock");
    fs.mkdirSync(lockPath);
    fs.writeFileSync(
      path.join(lockPath, "owner.json"),
      `${JSON.stringify({
        version: 1,
        pid: 2_147_483_647,
        processIdentity: "dead-process",
        probePort: 1,
        token: "dead-owner",
      })}\n`,
    );
    const oldTimestamp = new Date(Date.now() - 10_000);
    fs.utimesSync(lockPath, oldTimestamp, oldTimestamp);

    let entered = false;
    await withWorktreePortRegistryLock(homeDir, async () => {
      entered = true;
    });

    expect(entered).toBe(true);
    expect(fs.existsSync(lockPath)).toBe(false);
  });

  it("reclaims an old lock when its pid belongs to a different process", async () => {
    const homeDir = makeTemporaryRoot();
    const lockPath = path.join(homeDir, ".worktree-port-reservations.lock");
    fs.mkdirSync(lockPath);
    fs.writeFileSync(
      path.join(lockPath, "owner.json"),
      `${JSON.stringify({
        version: 1,
        pid: process.pid,
        processIdentity: "reused-pid-owner",
        probePort: 1,
        token: "abandoned-owner",
      })}\n`,
    );
    const oldTimestamp = new Date(Date.now() - 10_000);
    fs.utimesSync(lockPath, oldTimestamp, oldTimestamp);

    let entered = false;
    await withWorktreePortRegistryLock(homeDir, async () => {
      entered = true;
    });

    expect(entered).toBe(true);
    expect(fs.existsSync(lockPath)).toBe(false);
  });

  it("refreshes the lease while a synchronous critical section blocks the main thread", () => {
    const homeDir = makeTemporaryRoot();
    const lockPath = path.join(homeDir, ".worktree-port-reservations.lock");
    const blocker = new Int32Array(new SharedArrayBuffer(4));

    withWorktreePortRegistryLockSync(homeDir, () => {
      const oldTimestamp = new Date(Date.now() - 10_000);
      fs.utimesSync(lockPath, oldTimestamp, oldTimestamp);
      Atomics.wait(blocker, 0, 0, 1_500);
      // Same reasoning as the async critical-section test above: assert
      // against the staleness threshold the heartbeat exists to defend,
      // not a tight margin coupled to one heartbeat interval.
      expect(Date.now() - fs.statSync(lockPath).mtimeMs).toBeLessThan(5_000);
    });

    expect(fs.existsSync(lockPath)).toBe(false);
  });
});
