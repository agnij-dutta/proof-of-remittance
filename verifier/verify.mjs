// Off-chain verification of a proof-of-remittance bundle. Runs the same
// checks as RemittanceEscrow.release(), in the same order, so a relying party
// (an off-ramp backend, an agent orchestrator) can accept a proof without a
// chain.
//
// The caller MUST take `escrow` (chain, contract, id, threshold, minTs) from
// its own records or from the chain, never from the party submitting the
// proof. Otherwise the submitter picks their own threshold.
//
// verifyBundle is stateless: it does not remember accepted bundles. Making
// sure one escrow pays out once is the caller's job (the contract does it
// with its `settled` flag).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { attestationDigest, recoverNotary } from "../lib/attestation.mjs";
import { ATTESTATION_VERSION, CURRENCY, ENDPOINT, narrationFor, SERVER_DOMAIN } from "../lib/constants.mjs";
import { publicInputs, verifyZk } from "../lib/zk.mjs";

/** @typedef {import("../lib/attestation.mjs").Attestation} Attestation */

/**
 * Terms of the escrow the proof is checked against.
 * @typedef {object} EscrowTerms
 * @property {number | string} chainId            chain the escrow contract lives on
 * @property {string} contract                    escrow contract address
 * @property {number | string} id                 escrow id; with chainId and contract it sets the required narration
 * @property {number | string | bigint} thresholdPaise  minimum credit in paise (1 INR = 100 paise)
 * @property {number | string | bigint} minTs      credit and session must be at or after this unix time
 */

/**
 * @typedef {object} Bundle
 * @property {EscrowTerms} escrow
 * @property {Attestation} attestation
 * @property {`0x${string}`} proof   UltraHonk proof, hex
 */

/**
 * @typedef {object} Check
 * @property {string} name
 * @property {boolean} ok
 * @property {string} detail
 */

/**
 * @typedef {object} VerifyResult
 * @property {boolean} ok        true only if every check passed
 * @property {Check[]} checks
 */

const HEX32 = /^0x[0-9a-fA-F]{64}$/;
const HEX = /^0x([0-9a-fA-F]{2})+$/;

/**
 * Throws a descriptive error if `bundle` is not shaped like a {@link Bundle}.
 * @param {unknown} bundle
 * @returns {asserts bundle is Bundle}
 */
export function assertBundleShape(bundle) {
  /** @param {boolean} cond @param {string} msg */
  const need = (cond, msg) => {
    if (!cond) throw new TypeError(`invalid bundle: ${msg}`);
  };
  const b = /** @type {Record<string, any>} */ (bundle);
  need(typeof b === "object" && b !== null, "expected a JSON object");
  need(typeof b.escrow === "object" && b.escrow !== null, "missing escrow");
  for (const k of ["chainId", "id", "thresholdPaise", "minTs"]) {
    need(/^\d{1,20}$/.test(String(b.escrow[k])), `escrow.${k} must be a non-negative integer`);
  }
  need(/^0x[0-9a-fA-F]{40}$/.test(String(b.escrow.contract)), "escrow.contract must be a 0x address");
  const a = b.attestation;
  need(typeof a === "object" && a !== null, "missing attestation");
  for (const k of ["version", "server_name", "endpoint", "currency", "narration"]) {
    need(typeof a[k] === "string", `attestation.${k} must be a string`);
  }
  need(HEX32.test(a.amount_commitment), "attestation.amount_commitment must be 32-byte hex");
  need(HEX32.test(a.ts_commitment), "attestation.ts_commitment must be 32-byte hex");
  need(Number.isSafeInteger(a.session_time) && a.session_time >= 0, "attestation.session_time must be an integer");
  need(
    typeof a.signature === "string" && /^0x[0-9a-fA-F]{130}$/.test(a.signature),
    "attestation.signature must be 65 bytes hex",
  );
  need(typeof b.proof === "string" && HEX.test(b.proof), "proof must be hex");
}

/**
 * Checks a bundle against escrow terms and a trusted notary address.
 *
 * @param {Bundle} bundle
 * @param {{ notary: string }} trust   the only notary address to accept
 * @returns {Promise<VerifyResult>}
 */
export async function verifyBundle({ escrow, attestation: a, proof }, { notary }) {
  /** @type {Check[]} */
  const checks = [];
  /** @param {string} name @param {boolean} ok @param {string} [detail] */
  const add = (name, ok, detail = "") => checks.push({ name, ok, detail });

  add("version", a.version === ATTESTATION_VERSION, a.version);
  add("server", a.server_name === SERVER_DOMAIN, a.server_name);
  add("endpoint", a.endpoint === ENDPOINT, a.endpoint);
  add("currency", a.currency === CURRENCY, a.currency);
  add("narration", a.narration === narrationFor(escrow), `${a.narration} vs expected ${narrationFor(escrow)}`);
  add("fresh session", BigInt(a.session_time) >= BigInt(escrow.minTs), `${a.session_time} >= ${escrow.minTs}`);
  // `digest` is optional and informational; when present it must match.
  if (a.digest !== undefined) {
    add("digest", attestationDigest(a) === a.digest, "recomputed keccak digest matches");
  }
  let signer = "";
  let signerError = "";
  try {
    signer = (await recoverNotary(a)).toLowerCase();
  } catch (e) {
    signerError = e instanceof Error ? e.message.split("\n")[0] : String(e);
  }
  add("notary signature", signer !== "" && signer === notary.toLowerCase(), signer || `unrecoverable: ${signerError}`);

  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "por-verify-"));
  try {
    const zk = verifyZk({
      proofHex: proof,
      pubInputs: publicInputs(escrow.thresholdPaise, escrow.minTs, a.amount_commitment, a.ts_commitment),
      workDir,
    });
    add("zk: amount >= threshold, ts >= minTs", zk.ok, `bb verify ${zk.ms} ms`);
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }

  return { ok: checks.every((c) => c.ok), checks };
}
