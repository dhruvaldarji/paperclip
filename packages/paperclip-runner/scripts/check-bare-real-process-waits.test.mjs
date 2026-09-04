import assert from "node:assert/strict";
import { test } from "node:test";

import { findBareRealProcessWaits } from "./lib/bare-real-process-wait.mjs";

test("rejects a vi.waitFor( with no in-process marker on the line above", () => {
  const source = [
    "async function example() {",
    "  await vi.waitFor(() => expect(x).toBe(1));",
    "}",
  ].join("\n");

  assert.deepEqual(findBareRealProcessWaits(source), [
    { line: 2, pattern: "vi.waitFor(" },
  ]);
});

test("allows a vi.waitFor( marked as settling fully in-process", () => {
  const source = [
    "async function example() {",
    "  // bare-wait-ok: settles fully in-process, no spawned OS process.",
    "  await vi.waitFor(() => expect(x).toBe(1));",
    "}",
  ].join("\n");

  assert.deepEqual(findBareRealProcessWaits(source), []);
});

test("allows the named real-process wait helper instead of vi.waitFor", () => {
  const source = [
    "async function example() {",
    '  await waitForCapabilityLiveProcess("label", () => expect(x).toBe(1));',
    "}",
  ].join("\n");

  assert.deepEqual(findBareRealProcessWaits(source), []);
});

test("flags every unmarked vi.waitFor( in a file with a mix of marked and unmarked calls", () => {
  const source = [
    "async function example() {",
    "  await vi.waitFor(() => expect(a).toBe(1));",
    "  // bare-wait-ok: settles fully in-process, no spawned OS process.",
    "  await vi.waitFor(() => expect(b).toBe(2));",
    "  await vi.waitFor(() => expect(c).toBe(3));",
    "}",
  ].join("\n");

  assert.deepEqual(findBareRealProcessWaits(source), [
    { line: 2, pattern: "vi.waitFor(" },
    { line: 5, pattern: "vi.waitFor(" },
  ]);
});

test("rejects a bare expect.poll( with no in-process marker on the line above", () => {
  const source = [
    "async function example() {",
    "  await expect",
    "    .poll(async () => readFile(path, 'utf8'))",
    "    .toBe('done');",
    "}",
  ].join("\n");

  assert.deepEqual(findBareRealProcessWaits(source), [
    { line: 2, pattern: "expect.poll(" },
  ]);
});

test("allows an expect.poll( marked as settling fully in-process", () => {
  const source = [
    "async function example() {",
    "  // bare-wait-ok: settles fully in-process, no spawned OS process.",
    "  await expect",
    "    .poll(async () => readFile(path, 'utf8'))",
    "    .toBe('done');",
    "}",
  ].join("\n");

  assert.deepEqual(findBareRealProcessWaits(source), []);
});

test("allows an expect.poll( that passes an explicit timeout option", () => {
  const source = [
    "async function example() {",
    "  await expect",
    "    .poll(async () => readFile(path, 'utf8'), { timeout: 10_000 })",
    "    .toBe('done');",
    "}",
  ].join("\n");

  assert.deepEqual(findBareRealProcessWaits(source), []);
});
