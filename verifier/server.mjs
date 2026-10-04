// HTTP wrapper around verifyBundle.
//
//   POST /verify  { escrow: {id, thresholdPaise, minTs}, attestation, proof }
//   200 -> { ok, checks: [{name, ok, detail}] }   (ok:false means "rejected")
//   400 -> { ok:false, error }                     malformed request
//   500 -> { ok:false, error }                     verifier could not run (e.g. bb missing)
//
// Env: NOTARY_ADDRESS (required), VERIFIER_PORT (default 8787).
// Binds to 127.0.0.1 only. Put it behind your own auth before exposing it.
import http from "node:http";
import { isAddress } from "viem";
import { assertBundleShape, verifyBundle } from "./verify.mjs";

const PORT = Number(process.env.VERIFIER_PORT ?? 8787);
const NOTARY = process.env.NOTARY_ADDRESS ?? "";
/** A bundle is about 20 KB (9 KB proof as hex plus the attestation). */
const MAX_BODY_BYTES = 64 * 1024;

if (!isAddress(NOTARY)) {
  console.error("verifier: NOTARY_ADDRESS must be set to the notary's 0x address (see .env.example)");
  process.exit(1);
}

/**
 * @param {http.ServerResponse} res
 * @param {number} status
 * @param {unknown} body
 */
function sendJson(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
}

http
  .createServer((req, res) => {
    if (req.method !== "POST" || req.url !== "/verify") {
      sendJson(res, 404, { ok: false, error: "POST /verify only" });
      return;
    }
    /** @type {Buffer[]} */
    const chunks = [];
    let size = 0;
    let tooLarge = false;
    req.on("data", (/** @type {Buffer} */ chunk) => {
      if (tooLarge) return;
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        tooLarge = true;
        sendJson(res, 413, { ok: false, error: `body larger than ${MAX_BODY_BYTES} bytes` });
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", async () => {
      if (tooLarge) return;
      /** @type {unknown} */
      let bundle;
      try {
        bundle = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        assertBundleShape(bundle);
      } catch (e) {
        sendJson(res, 400, { ok: false, error: e instanceof Error ? e.message : String(e) });
        return;
      }
      try {
        sendJson(res, 200, await verifyBundle(bundle, { notary: NOTARY }));
      } catch (e) {
        sendJson(res, 500, { ok: false, error: e instanceof Error ? e.message : String(e) });
      }
    });
  })
  .listen(PORT, "127.0.0.1", () => {
    console.log(`[verifier] http://127.0.0.1:${PORT}/verify trusting notary ${NOTARY}`);
  });
