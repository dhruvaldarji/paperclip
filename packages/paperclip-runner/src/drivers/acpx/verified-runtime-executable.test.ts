import { describe, expect, it } from "vitest";

import {
  VERIFIED_RUNTIME_EXECUTABLE_ENV,
  verifiedRuntimeExecutable,
} from "./verified-runtime-executable.js";

describe("verified runtime executable", () => {
  it("anchors an inherited Linux descriptor at its current owner", () => {
    expect(
      verifiedRuntimeExecutable(
        { [VERIFIED_RUNTIME_EXECUTABLE_ENV]: "/proc/self/fd/17" },
        "linux",
        4321,
        "/usr/bin/node",
      ),
    ).toBe("/proc/4321/fd/17");
  });

  it("preserves an already anchored descendant runtime", () => {
    expect(
      verifiedRuntimeExecutable(
        { [VERIFIED_RUNTIME_EXECUTABLE_ENV]: "/proc/4321/fd/17" },
        "linux",
        8765,
        "/usr/bin/node",
      ),
    ).toBe("/proc/4321/fd/17");
  });

  it("rejects mutable Linux paths at the verified boundary", () => {
    expect(() =>
      verifiedRuntimeExecutable(
        { [VERIFIED_RUNTIME_EXECUTABLE_ENV]: "/usr/bin/node" },
        "linux",
        4321,
        "/usr/bin/node",
      ),
    ).toThrow("descriptor is invalid");
  });

  it("uses process identity only when no verified runtime was supplied", () => {
    expect(verifiedRuntimeExecutable({}, "linux", 4321, "/usr/bin/node")).toBe(
      "/usr/bin/node",
    );
  });
});
