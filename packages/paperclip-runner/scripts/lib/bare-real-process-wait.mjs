import { readdir, readFile } from "node:fs/promises";
import { relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const libraryDirectory = fileURLToPath(new URL(".", import.meta.url));
export const defaultPackageRoot = resolve(libraryDirectory, "../..");

const SCANNED_EXTENSIONS = new Set([".ts", ".tsx"]);

// A wait against a spawned operating-system process can run far longer than
// vitest's default `vi.waitFor` or `expect.poll` deadline (see the helper
// and its evidence comment in test/wait-for-live-process.ts). A wait that
// settles fully in-process never needs that deadline, so this check does
// not force every wait onto the real-process helper — it only requires that
// a bare call in this directory carries an explicit note that the wait
// settles in-process, or an explicit `timeout` option that states its own
// envelope.
const IN_PROCESS_WAIT_MARKER = "bare-wait-ok:";

// `expect.poll(` can span two lines as `expect\n  .poll(`, so each pattern
// allows whitespace (including a newline) around the dot.
const BARE_WAIT_PATTERNS = [
  { name: "vi.waitFor(", regex: /\bvi\s*\.\s*waitFor\(/g },
  { name: "expect.poll(", regex: /\bexpect\s*\.\s*poll\(/g },
];

const EXPLICIT_TIMEOUT_PATTERN = /\btimeout\s*:/;

function extension(path) {
  const match = path.match(/\.[^./\\]+$/);
  return match?.[0] ?? "";
}

async function collectSourceFiles(target) {
  const entries = await readdir(target, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (["dist", "node_modules", ".git"].includes(entry.name)) {
      continue;
    }
    const path = resolve(target, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await collectSourceFiles(path)));
    } else if (entry.isFile() && SCANNED_EXTENSIONS.has(extension(entry.name))) {
      files.push(path);
    }
  }
  return files;
}

// Find the index of the close paren that matches the open paren at
// `openParenIndex`, tracking nested `()`, `{}`, and `[]`, and skipping over
// string and template literals so a brace or paren inside one never throws
// off the count.
function findMatchingCloseParenIndex(source, openParenIndex) {
  let depth = 0;
  for (let index = openParenIndex; index < source.length; index += 1) {
    const character = source[index];
    if (character === "(" || character === "{" || character === "[") {
      depth += 1;
    } else if (character === ")" || character === "}" || character === "]") {
      depth -= 1;
      if (depth === 0) return index;
    } else if (character === "'" || character === '"' || character === "`") {
      const quote = character;
      index += 1;
      while (index < source.length && source[index] !== quote) {
        if (source[index] === "\\") index += 1;
        index += 1;
      }
    }
  }
  return source.length;
}

/**
 * Find each real-process-shaped wait call (`vi.waitFor(`, or `expect.poll(`,
 * including the two-line `expect\n  .poll(` form) in `source` that has
 * neither an `IN_PROCESS_WAIT_MARKER` note on the line directly above it
 * nor an explicit `timeout` option in its own argument list. A call site
 * with the marker declares, in place, that it settles fully in-process. A
 * call site with an explicit `timeout` option already states its own
 * envelope. Either one needs no real-process deadline.
 */
export function findBareRealProcessWaits(source) {
  const lines = source.split("\n");
  const found = [];
  for (const { name, regex } of BARE_WAIT_PATTERNS) {
    regex.lastIndex = 0;
    for (
      let match = regex.exec(source);
      match !== null;
      match = regex.exec(source)
    ) {
      const line = source.slice(0, match.index).split("\n").length;
      const precedingLine = lines[line - 2] ?? "";
      if (precedingLine.includes(IN_PROCESS_WAIT_MARKER)) {
        continue;
      }
      const openParenIndex = match.index + match[0].length - 1;
      const closeParenIndex = findMatchingCloseParenIndex(source, openParenIndex);
      const callArguments = source.slice(openParenIndex + 1, closeParenIndex);
      if (EXPLICIT_TIMEOUT_PATTERN.test(callArguments)) {
        continue;
      }
      found.push({ line, pattern: name });
    }
  }
  found.sort((a, b) => a.line - b.line);
  return found;
}

export async function checkBareRealProcessWaits({
  packageRoot = defaultPackageRoot,
  scanRoot = "src/live",
} = {}) {
  const root = resolve(packageRoot, scanRoot);
  const files = (await collectSourceFiles(root)).sort();
  const violations = [];
  for (const file of files) {
    const source = await readFile(file, "utf8");
    for (const { line, pattern } of findBareRealProcessWaits(source)) {
      violations.push({ file, line, pattern });
    }
  }
  return violations;
}

export function formatBareRealProcessWaitViolation(violation, packageRoot = defaultPackageRoot) {
  return (
    `${relative(packageRoot, violation.file)}:${violation.line} calls a bare ${violation.pattern}: ` +
    "use waitForCapabilityLiveProcess (test/wait-for-live-process.ts) for a wait bound to a real " +
    "spawned process, mark a wait that settles fully in-process with a comment containing " +
    `"${IN_PROCESS_WAIT_MARKER}" on the line above the call, or pass an explicit timeout option ` +
    "that states the wait's own envelope"
  );
}
