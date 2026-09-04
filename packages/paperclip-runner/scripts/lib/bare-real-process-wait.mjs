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

// Replace every comment and every string- or template-literal body with
// spaces, one for one, so the result keeps the same length and the same
// line breaks as `source`. A line count taken from the result still lines
// up with `source`, and neither a wait-call pattern nor a `timeout` option
// written inside a comment or a literal can survive into the result.
function maskCommentsAndStrings(source) {
  const masked = source.split("");
  let index = 0;
  while (index < source.length) {
    const twoCharacters = source.slice(index, index + 2);
    const character = source[index];
    if (twoCharacters === "//") {
      while (index < source.length && source[index] !== "\n") {
        masked[index] = " ";
        index += 1;
      }
      continue;
    }
    if (twoCharacters === "/*") {
      masked[index] = " ";
      masked[index + 1] = " ";
      index += 2;
      while (index < source.length && source.slice(index, index + 2) !== "*/") {
        if (source[index] !== "\n") masked[index] = " ";
        index += 1;
      }
      if (index < source.length) {
        masked[index] = " ";
        masked[index + 1] = " ";
        index += 2;
      }
      continue;
    }
    if (character === "'" || character === '"' || character === "`") {
      const quote = character;
      masked[index] = " ";
      index += 1;
      while (index < source.length && source[index] !== quote) {
        if (source[index] === "\\" && index + 1 < source.length) {
          masked[index] = " ";
          index += 1;
          if (source[index] !== "\n") masked[index] = " ";
          index += 1;
          continue;
        }
        if (source[index] !== "\n") masked[index] = " ";
        index += 1;
      }
      if (index < source.length) {
        masked[index] = " ";
        index += 1;
      }
      continue;
    }
    index += 1;
  }
  return masked.join("");
}

// Find the index of the close paren that matches the open paren at
// `openParenIndex`, tracking nested `()`, `{}`, and `[]`. Callers pass a
// comment- and string-masked source, so a stray bracket inside a comment or
// a literal never throws off the count.
function findMatchingCloseParenIndex(maskedSource, openParenIndex) {
  let depth = 0;
  for (let index = openParenIndex; index < maskedSource.length; index += 1) {
    const character = maskedSource[index];
    if (character === "(" || character === "{" || character === "[") {
      depth += 1;
    } else if (character === ")" || character === "}" || character === "]") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return maskedSource.length;
}

// Split a call's argument-list text on its top-level commas, so a comma
// nested inside a callback body, an object, or an array does not split a
// single argument in two.
function splitTopLevelArguments(maskedCallArguments) {
  const args = [];
  let depth = 0;
  let current = "";
  for (const character of maskedCallArguments) {
    if (character === "(" || character === "{" || character === "[") {
      depth += 1;
      current += character;
    } else if (character === ")" || character === "}" || character === "]") {
      depth -= 1;
      current += character;
    } else if (character === "," && depth === 0) {
      args.push(current);
      current = "";
    } else {
      current += character;
    }
  }
  args.push(current);
  return args;
}

// Return the wait call's own options argument (`vi.waitFor(callback,
// options)` or `expect.poll(callback, options)`), or `null` when the call
// passes no second argument. Only this text, not the callback body, states
// the call's own timeout.
function findOptionsArgument(maskedSource, openParenIndex, closeParenIndex) {
  const callArguments = maskedSource.slice(openParenIndex + 1, closeParenIndex);
  const topLevelArguments = splitTopLevelArguments(callArguments);
  return topLevelArguments.length >= 2 ? topLevelArguments[1] : null;
}

/**
 * Find each real-process-shaped wait call (`vi.waitFor(`, or `expect.poll(`,
 * including the two-line `expect\n  .poll(` form) in `source` that has
 * neither an `IN_PROCESS_WAIT_MARKER` note on the line directly above it
 * nor an explicit `timeout` option in its own options argument. A call site
 * with the marker declares, in place, that it settles fully in-process. A
 * call site with an explicit `timeout` option already states its own
 * envelope. Either one needs no real-process deadline. A pattern written
 * inside a comment or inside a string or template literal is source text,
 * not a call, and never counts as one.
 */
export function findBareRealProcessWaits(source) {
  const lines = source.split("\n");
  const masked = maskCommentsAndStrings(source);
  const found = [];
  for (const { name, regex } of BARE_WAIT_PATTERNS) {
    regex.lastIndex = 0;
    for (
      let match = regex.exec(masked);
      match !== null;
      match = regex.exec(masked)
    ) {
      const line = masked.slice(0, match.index).split("\n").length;
      const precedingLine = lines[line - 2] ?? "";
      if (precedingLine.includes(IN_PROCESS_WAIT_MARKER)) {
        continue;
      }
      const openParenIndex = match.index + match[0].length - 1;
      const closeParenIndex = findMatchingCloseParenIndex(masked, openParenIndex);
      const optionsArgument = findOptionsArgument(masked, openParenIndex, closeParenIndex);
      if (optionsArgument !== null && EXPLICIT_TIMEOUT_PATTERN.test(optionsArgument)) {
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
