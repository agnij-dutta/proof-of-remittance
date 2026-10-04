// Loads the real bundle captured from `npm run demo` (also used by the
// Foundry and Rust tests) in the shapes the JS modules expect.
import fs from "node:fs";
import path from "node:path";
import { ROOT } from "../lib/constants.mjs";

const raw = JSON.parse(fs.readFileSync(path.join(ROOT, "contracts/test/fixtures/bundle.json"), "utf8"));

/** @returns {import("../verifier/verify.mjs").Bundle & { notary: string }} */
export function loadFixture() {
  return {
    notary: raw.notary,
    escrow: {
      chainId: raw.chainId,
      contract: raw.escrowAddress,
      id: raw.escrowId,
      thresholdPaise: raw.thresholdPaise,
      minTs: raw.minTs,
    },
    attestation: {
      version: "POR_TLSN_V1",
      server_name: raw.serverName,
      endpoint: raw.endpoint,
      currency: raw.currency,
      narration: raw.narration,
      amount_commitment: raw.amountCommitment,
      ts_commitment: raw.tsCommitment,
      session_time: raw.sessionTime,
      signature: raw.signature,
    },
    proof: raw.proof,
  };
}
