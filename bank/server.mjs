// MockBank: a small HTTPS "net-banking" API that stands in for a real bank's
// statement endpoint. Every account, amount and reference here is made up.
//
//   HTTPS BANK_PORT      GET  /api/v1/accounts/me/credits   (needs the Bearer session token)
//   HTTP  BANK_SIM_PORT  POST /_sim/credit {amount, narration, ts?, currency?}
//                        simulates an inbound IMPS/UPI credit landing in the account
//
// TLS is pinned to 1.2 because TLSNotary's MPC-TLS speaks TLS 1.2 only.
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import { fileURLToPath } from "node:url";

const CERT_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "certs");
const HTTPS_PORT = Number(process.env.BANK_PORT ?? 8443);
const SIM_PORT = Number(process.env.BANK_SIM_PORT ?? 8444);
// Impostor mode serves the same API under the same hostname, with a
// certificate chained to a CA the notary does not trust.
const IMPOSTOR = process.env.BANK_EVIL === "1";

/** Session token of the fake account holder. The prover sends it; the proof hides it. */
export const SESSION_TOKEN = "mockbank_sess_9f3c1e7a2b";

const account = {
  number: "000012345678",
  holder: "Test Account Holder",
  ifsc: "MOCK0000001",
  balance: "812345.67",
};

/**
 * @typedef {object} Credit
 * @property {string} amount     decimal rupees with 2 places, e.g. "50000.00"
 * @property {string} currency
 * @property {string} narration  free text set by the payer
 * @property {string} ref        UTR / RRN
 * @property {number} ts         unix seconds
 */

/** @type {Credit[]} */
const credits = [
  { amount: "1250.00", currency: "INR", narration: "UPI-SALARY-ADV", ref: "UTR400112233445", ts: 1759100000 },
  { amount: "320.50", currency: "INR", narration: "UPI-REFUND-STORE", ref: "UTR400112299887", ts: 1759200000 },
];

/**
 * @param {http.ServerResponse} res
 * @param {number} status
 * @param {unknown} obj
 */
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
  });
  res.end(body);
}

/** @param {string} file */
function readCert(file) {
  const p = path.join(CERT_DIR, file);
  if (!fs.existsSync(p)) {
    console.error(`bank: ${p} not found. Run \`npm run certs\` first.`);
    process.exit(1);
  }
  return fs.readFileSync(p);
}

const api = https.createServer(
  {
    key: readCert(IMPOSTOR ? "evil.key" : "bank.key"),
    cert: readCert(IMPOSTOR ? "evil.crt" : "bank.crt"),
    minVersion: "TLSv1.2",
    maxVersion: "TLSv1.2",
  },
  (req, res) => {
    const url = new URL(req.url ?? "/", "https://netbanking.mockbank.test");
    if (req.method === "GET" && url.pathname === "/api/v1/accounts/me/credits") {
      if (req.headers.authorization !== `Bearer ${SESSION_TOKEN}`) {
        sendJson(res, 401, { error: "unauthorized" });
        return;
      }
      // Newest first, like most statement APIs.
      const list = [...credits].sort((x, y) => y.ts - x.ts);
      sendJson(res, 200, { account, credits: list });
      return;
    }
    sendJson(res, 404, { error: "not_found" });
  },
);

const simulator = http.createServer((req, res) => {
  if (req.method !== "POST" || req.url !== "/_sim/credit") {
    sendJson(res, 404, { error: "not_found" });
    return;
  }
  let raw = "";
  req.on("data", (chunk) => {
    raw += chunk;
  });
  req.on("end", () => {
    /** @type {Record<string, unknown>} */
    let body;
    try {
      body = JSON.parse(raw || "{}");
    } catch {
      sendJson(res, 400, { error: "body must be JSON" });
      return;
    }
    if (!/^\d+\.\d{2}$/.test(String(body.amount)) || typeof body.narration !== "string") {
      sendJson(res, 400, { error: 'need {"amount":"<digits>.<2 digits>","narration":"..."}' });
      return;
    }
    /** @type {Credit} */
    const credit = {
      amount: String(body.amount),
      currency: typeof body.currency === "string" ? body.currency : "INR",
      narration: body.narration,
      ref: `UTR${crypto.randomInt(100000000000, 999999999999)}`,
      ts: Number(body.ts ?? Math.floor(Date.now() / 1000)),
    };
    credits.push(credit);
    sendJson(res, 201, credit);
  });
});

api.listen(HTTPS_PORT, "127.0.0.1", () => {
  console.log(`[bank] https://netbanking.mockbank.test:${HTTPS_PORT} (127.0.0.1)${IMPOSTOR ? " IMPOSTOR CERT" : ""}`);
});
simulator.listen(SIM_PORT, "127.0.0.1", () => {
  console.log(`[bank] simulator http://127.0.0.1:${SIM_PORT}`);
});
