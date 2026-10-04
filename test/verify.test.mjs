// verifyBundle against the captured real proof. Needs `bb` on PATH, because
// the ZK check shells out to `bb verify`.
import assert from "node:assert/strict";
import { test } from "node:test";
import { assertBundleShape, verifyBundle } from "../verifier/verify.mjs";
import { loadFixture } from "./fixture.mjs";

/** @param {import("../verifier/verify.mjs").VerifyResult} r */
const failed = (r) => r.checks.filter((c) => !c.ok).map((c) => c.name);

test("accepts the genuine bundle", async () => {
  const { notary, ...bundle } = loadFixture();
  const r = await verifyBundle(bundle, { notary });
  assert.deepEqual(failed(r), []);
  assert.equal(r.ok, true);
});

test("rejects a notary the relying party does not trust", async () => {
  const { notary: _real, ...bundle } = loadFixture();
  const r = await verifyBundle(bundle, { notary: "0x000000000000000000000000000000000000dEaD" });
  assert.deepEqual(failed(r), ["notary signature"]);
});

test("rejects a higher threshold than the proof was made for", async () => {
  const { notary, ...bundle } = loadFixture();
  const r = await verifyBundle({ ...bundle, escrow: { ...bundle.escrow, thresholdPaise: 10_000_000 } }, { notary });
  assert.deepEqual(failed(r), ["zk: amount >= threshold, ts >= minTs"]);
});

test("rejects the proof against a different escrow id", async () => {
  const { notary, ...bundle } = loadFixture();
  const r = await verifyBundle({ ...bundle, escrow: { ...bundle.escrow, id: 2 } }, { notary });
  assert.ok(failed(r).includes("narration"));
});

test("rejects the proof against the same escrow id on another deployment", async () => {
  const { notary, ...bundle } = loadFixture();
  const other = "0x000000000000000000000000000000000000bEEF";
  const r = await verifyBundle({ ...bundle, escrow: { ...bundle.escrow, contract: other } }, { notary });
  assert.deepEqual(failed(r), ["narration"]);
  const r2 = await verifyBundle({ ...bundle, escrow: { ...bundle.escrow, chainId: 1 } }, { notary });
  assert.deepEqual(failed(r2), ["narration"]);
});

test("rejects a session older than the escrow", async () => {
  const { notary, ...bundle } = loadFixture();
  const later = bundle.attestation.session_time + 1;
  const r = await verifyBundle({ ...bundle, escrow: { ...bundle.escrow, minTs: later } }, { notary });
  assert.ok(failed(r).includes("fresh session"));
});

test("rejects a tampered proof", async () => {
  const { notary, ...bundle } = loadFixture();
  const p = bundle.proof;
  const proof = /** @type {`0x${string}`} */ (p.slice(0, 602) + (p[602] === "0" ? "1" : "0") + p.slice(603));
  const r = await verifyBundle({ ...bundle, proof }, { notary });
  assert.deepEqual(failed(r), ["zk: amount >= threshold, ts >= minTs"]);
});

test("rejects a malformed signature without throwing", async () => {
  const { notary, ...bundle } = loadFixture();
  const r = await verifyBundle({ ...bundle, attestation: { ...bundle.attestation, signature: "0x1234" } }, { notary });
  assert.ok(failed(r).includes("notary signature"));
});

test("assertBundleShape rejects bad input with a specific message", () => {
  const { notary: _n, ...bundle } = loadFixture();
  assert.doesNotThrow(() => assertBundleShape(bundle));
  assert.throws(() => assertBundleShape(null), /expected a JSON object/);
  assert.throws(() => assertBundleShape({ ...bundle, proof: "nothex" }), /proof must be hex/);
  assert.throws(() => assertBundleShape({ ...bundle, escrow: { ...bundle.escrow, contract: "0x12" } }), /contract/);
  assert.throws(
    () => assertBundleShape({ ...bundle, escrow: { ...bundle.escrow, thresholdPaise: -1 } }),
    /thresholdPaise/,
  );
});
