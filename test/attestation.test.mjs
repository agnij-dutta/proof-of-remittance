import assert from "node:assert/strict";
import { test } from "node:test";
import { recoverNotary, toSolidityAttestation } from "../lib/attestation.mjs";
import { narrationFor } from "../lib/constants.mjs";
import { publicInputs } from "../lib/zk.mjs";
import { loadFixture } from "./fixture.mjs";

test("JS digest matches the Rust notary: fixture signature recovers to the notary", async () => {
  const { attestation, notary } = loadFixture();
  assert.equal((await recoverNotary(attestation)).toLowerCase(), notary.toLowerCase());
});

test("changing any signed field changes the recovered signer", async () => {
  const { attestation, notary } = loadFixture();
  for (const change of [
    { narration: "POR-00000000000000000000" },
    { currency: "USD" },
    { session_time: attestation.session_time + 1 },
    { amount_commitment: /** @type {`0x${string}`} */ (`0x${"11".repeat(32)}`) },
  ]) {
    const signer = await recoverNotary({ ...attestation, ...change });
    assert.notEqual(signer.toLowerCase(), notary.toLowerCase(), JSON.stringify(change));
  }
});

test("toSolidityAttestation maps every field", () => {
  const { attestation } = loadFixture();
  const sol = toSolidityAttestation(attestation);
  assert.equal(sol.narration, attestation.narration);
  assert.equal(sol.amountCommitment, attestation.amount_commitment);
  assert.equal(sol.sessionTime, BigInt(attestation.session_time));
});

test("publicInputs lays out threshold, minTs, then one word per commitment byte", () => {
  const amount = /** @type {`0x${string}`} */ (`0x${"ab".repeat(32)}`);
  const ts = /** @type {`0x${string}`} */ (`0x${"01".repeat(32)}`);
  const words = publicInputs(4_500_000n, 1_700_000_000, amount, ts);
  assert.equal(words.length, 66);
  assert.equal(BigInt(words[0]), 4_500_000n);
  assert.equal(BigInt(words[1]), 1_700_000_000n);
  assert.equal(BigInt(words[2]), 0xabn);
  assert.equal(BigInt(words[65]), 0x01n);
});

test("narrationFor matches the contract (fixture narration was read from RemittanceEscrow.narrationFor)", () => {
  const { escrow, attestation } = loadFixture();
  assert.equal(narrationFor(escrow), attestation.narration);
});

test("narrationFor separates escrow id, contract and chain", () => {
  const { escrow } = loadFixture();
  const base = narrationFor(escrow);
  assert.match(base, /^POR-[0-9A-F]{20}$/);
  assert.notEqual(narrationFor({ ...escrow, id: 2 }), base);
  assert.notEqual(narrationFor({ ...escrow, chainId: 1 }), base);
  assert.notEqual(narrationFor({ ...escrow, contract: "0x000000000000000000000000000000000000bEEF" }), base);
});
