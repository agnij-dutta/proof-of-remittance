// Proving and verifying the Noir predicate by shelling out to `nargo` and
// `bb`. bb has no stable JS API for this exact version, and the CLI output is
// byte-identical to what the generated Solidity verifier expects.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { bytesToHex, hexToBytes } from "viem";
import { CIRCUIT_DIR, VK_PATH } from "./constants.mjs";

/** Longest amount string the circuit accepts (MAX_AMOUNT_LEN in main.nr). */
export const MAX_AMOUNT_LEN = 16;

/**
 * @typedef {object} CommandResult
 * @property {boolean} ok   exit status was 0
 * @property {number} ms    wall-clock duration
 * @property {string} out   stdout followed by stderr
 * @property {string} [spawnError]  set if the command could not be started at all
 */

/**
 * Runs a command synchronously and captures its output.
 * @param {string} cmd
 * @param {string[]} args
 * @param {import("node:child_process").SpawnSyncOptions} [opts]
 * @returns {CommandResult}
 */
export function runCommand(cmd, args, opts = {}) {
  const t0 = performance.now();
  const r = spawnSync(cmd, args, { encoding: "utf8", ...opts });
  const ms = Math.round(performance.now() - t0);
  if (r.error) return { ok: false, ms, out: "", spawnError: `${cmd}: ${r.error.message}` };
  return { ok: r.status === 0, ms, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

/** @param {Uint8Array} bytes */
const tomlBytes = (bytes) => `[${Array.from(bytes).join(", ")}]`;

/**
 * Private values from the prover's `secrets.json`.
 * @typedef {object} Secrets
 * @property {{ plaintext: string, blinder: `0x${string}` }} amount
 * @property {{ plaintext: string, blinder: `0x${string}` }} ts
 */

/**
 * @typedef {{ ok: true, witnessMs: number, proveMs: number, proofHex: `0x${string}`, proofBytes: number }
 *   | { ok: false, stage: "input" | "witness" | "prove", reason: string }} ProveResult
 */

/**
 * Builds the witness and an EVM-target UltraHonk proof that the committed
 * amount is >= `thresholdPaise` and the committed timestamp is >= `minTs`.
 * A false predicate fails at the witness stage, so no proof can exist for it.
 *
 * @param {object} p
 * @param {Secrets} p.secrets                 plaintexts + blinders from the prover
 * @param {{ amount_commitment: `0x${string}`, ts_commitment: `0x${string}` }} p.attestation
 * @param {bigint} p.thresholdPaise
 * @param {bigint} p.minTs
 * @param {string} p.outDir                   where bb writes `proof`
 * @returns {ProveResult}
 */
export function proveZk({ secrets, attestation, thresholdPaise, minTs, outDir }) {
  const amount = Buffer.from(secrets.amount.plaintext, "utf8");
  const ts = Buffer.from(secrets.ts.plaintext, "utf8");
  if (amount.length > MAX_AMOUNT_LEN) {
    return { ok: false, stage: "input", reason: `amount is ${amount.length} bytes, circuit max is ${MAX_AMOUNT_LEN}` };
  }
  const padded = Buffer.concat([amount, Buffer.alloc(MAX_AMOUNT_LEN - amount.length)]);
  const toml = [
    `threshold_paise = "${thresholdPaise}"`,
    `min_ts = "${minTs}"`,
    `amount_hash = ${tomlBytes(hexToBytes(attestation.amount_commitment))}`,
    `ts_hash = ${tomlBytes(hexToBytes(attestation.ts_commitment))}`,
    `amount = ${tomlBytes(padded)}`,
    `amount_len = "${amount.length}"`,
    `amount_blinder = ${tomlBytes(hexToBytes(secrets.amount.blinder))}`,
    `ts = ${tomlBytes(ts)}`,
    `ts_blinder = ${tomlBytes(hexToBytes(secrets.ts.blinder))}`,
  ].join("\n");
  // nargo reads Prover.toml from the package dir; it is gitignored because it
  // holds the private witness.
  fs.writeFileSync(path.join(CIRCUIT_DIR, "Prover.toml"), `${toml}\n`);
  const witness = runCommand("nargo", ["execute"], { cwd: CIRCUIT_DIR });
  if (witness.spawnError) throw new Error(`cannot run nargo (is it installed?): ${witness.spawnError}`);
  if (!witness.ok) {
    const m = witness.out.match(/Failed assertion[^\n]*|assertion[^\n]*|error:[^\n]*/i);
    return { ok: false, stage: "witness", reason: m ? m[0].trim() : witness.out.slice(-400) };
  }
  fs.mkdirSync(outDir, { recursive: true });
  const prove = runCommand(
    "bb",
    [
      "prove",
      "-b",
      "target/remittance.json",
      "-w",
      "target/remittance.gz",
      "-k",
      "target/vk",
      "-o",
      outDir,
      "-t",
      "evm",
    ],
    { cwd: CIRCUIT_DIR },
  );
  if (prove.spawnError) throw new Error(`cannot run bb (is it installed?): ${prove.spawnError}`);
  if (!prove.ok) return { ok: false, stage: "prove", reason: prove.out.slice(-400) };
  const proof = fs.readFileSync(path.join(outDir, "proof"));
  return {
    ok: true,
    witnessMs: witness.ms,
    proveMs: prove.ms,
    proofHex: bytesToHex(proof),
    proofBytes: proof.length,
  };
}

/**
 * The circuit's 66 public inputs in declaration order, as bytes32 words:
 * threshold_paise, min_ts, amount_hash[32], ts_hash[32]. Mirrors
 * `RemittanceEscrow.publicInputs`.
 *
 * @param {bigint | number | string} thresholdPaise
 * @param {bigint | number | string} minTs
 * @param {`0x${string}`} amountCommitment
 * @param {`0x${string}`} tsCommitment
 * @returns {`0x${string}`[]}
 */
export function publicInputs(thresholdPaise, minTs, amountCommitment, tsCommitment) {
  /** @param {bigint | number | string} n @returns {`0x${string}`} */
  const word = (n) => `0x${BigInt(n).toString(16).padStart(64, "0")}`;
  return [
    word(thresholdPaise),
    word(minTs),
    ...Array.from(hexToBytes(amountCommitment)).map(word),
    ...Array.from(hexToBytes(tsCommitment)).map(word),
  ];
}

/**
 * Verifies an UltraHonk proof with `bb verify` against the committed vk.
 * `ok` is true only if bb exits 0 and reports success. Throws if bb cannot be
 * started, so a missing tool is never reported as an invalid proof.
 *
 * @param {object} p
 * @param {`0x${string}`} p.proofHex
 * @param {`0x${string}`[]} p.pubInputs  from `publicInputs`
 * @param {string} p.workDir             scratch dir for bb's input files
 * @returns {{ ok: boolean, ms: number, out: string }}
 */
export function verifyZk({ proofHex, pubInputs, workDir }) {
  fs.mkdirSync(workDir, { recursive: true });
  const proofPath = path.join(workDir, "proof");
  const inputsPath = path.join(workDir, "public_inputs");
  fs.writeFileSync(proofPath, hexToBytes(proofHex));
  fs.writeFileSync(inputsPath, Buffer.concat(pubInputs.map((x) => Buffer.from(hexToBytes(x)))));
  const r = runCommand("bb", ["verify", "-p", proofPath, "-i", inputsPath, "-k", VK_PATH, "-t", "evm"]);
  if (r.spawnError) throw new Error(`cannot run bb (is it installed?): ${r.spawnError}`);
  return { ok: r.ok && /verified successfully/i.test(r.out), ms: r.ms, out: r.out };
}
