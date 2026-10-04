// Starts and stops the demo's local processes (anvil, mock banks, notary,
// verifier). Each writes to .run/<name>.log; readiness is detected from logs.
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { ROOT } from "../../lib/constants.mjs";

/** Scratch directory for logs, proofs and attestations. Gitignored. */
export const RUN_DIR = path.join(ROOT, ".run");

/** @type {import("node:child_process").ChildProcess[]} */
const children = [];

/**
 * Starts a background process with its output in `.run/<name>.log`.
 * @param {string} name
 * @param {string} cmd
 * @param {string[]} args
 * @param {Record<string, string | number>} [env]
 */
export function startService(name, cmd, args, env = {}) {
  const log = fs.openSync(path.join(RUN_DIR, `${name}.log`), "w");
  const stringEnv = Object.fromEntries(Object.entries(env).map(([k, v]) => [k, String(v)]));
  const child = spawn(cmd, args, { cwd: ROOT, env: { ...process.env, ...stringEnv }, stdio: ["ignore", log, log] });
  child.on("error", (e) => {
    fs.appendFileSync(path.join(RUN_DIR, `${name}.log`), `\n[demo] failed to start ${cmd}: ${e.message}\n`);
  });
  children.push(child);
  return child;
}

/** Sends SIGTERM to every started process. Safe to call more than once. */
export function stopServices() {
  for (const child of children) {
    if (child.exitCode === null && !child.killed) child.kill("SIGTERM");
  }
}

/** @param {number} ms */
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Polls `probe` every 100 ms until it returns true. A probe that throws is
 * treated as "not ready yet" (e.g. a port that is not listening).
 * @param {() => boolean | Promise<unknown>} probe
 * @param {string} what   used in the timeout error
 * @param {number} [timeoutMs]
 */
export async function waitFor(probe, what, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if (await probe()) return;
    } catch {
      // not ready yet
    }
    await sleep(100);
  }
  throw new Error(`timed out after ${timeoutMs} ms waiting for ${what}; see .run/*.log`);
}

/**
 * Probe that is true once `.run/<name>.log` contains `text`.
 * @param {string} name
 * @param {string} text
 */
export const logContains = (name, text) => () =>
  fs.readFileSync(path.join(RUN_DIR, `${name}.log`), "utf8").includes(text);

/** @param {string} name */
export const readLog = (name) => fs.readFileSync(path.join(RUN_DIR, `${name}.log`), "utf8");
