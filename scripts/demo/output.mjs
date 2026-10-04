// Console output for the demo: numbered steps, PASS/FAIL lines, and a
// failure counter that decides the process exit code.

const color = process.stdout.isTTY && !process.env.NO_COLOR;
/** @param {string} code */
const ansi = (code) => (color ? `\x1b[${code}m` : "");
export const style = {
  dim: ansi("2"),
  bold: ansi("1"),
  green: ansi("32"),
  red: ansi("31"),
  yellow: ansi("33"),
  cyan: ansi("36"),
  reset: ansi("0"),
};

let failures = 0;

/** @param {number} n @param {string} title */
export function step(n, title) {
  console.log(`\n${style.bold}${style.cyan}[${n}]${style.reset} ${style.bold}${title}${style.reset}`);
}

/** @param {string} line */
export function info(line) {
  console.log(`    ${line}`);
}

/**
 * Prints PASS or FAIL and counts failures.
 * @param {boolean} condition
 * @param {string} message
 */
export function expect(condition, message) {
  if (condition) {
    console.log(`    ${style.green}PASS${style.reset} ${message}`);
  } else {
    failures++;
    console.log(`    ${style.red}FAIL${style.reset} ${message}`);
  }
}

/** Number of failed `expect` calls so far. */
export const failureCount = () => failures;
