// npm run demo
//
// End-to-end run on one machine, against a mock bank:
//   bank -> zkTLS (TLSNotary MPC-TLS) -> ZK predicate (Noir / UltraHonk)
//        -> off-chain verifier service -> on-chain escrow release (anvil)
// then six attacks that must all be rejected. Exits non-zero if any check fails.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { formatUnits } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { toSolidityAttestation } from "../lib/attestation.mjs";
import { ENDPOINT, narrationFor, ROOT, SERVER_DOMAIN } from "../lib/constants.mjs";
import { proveZk, runCommand } from "../lib/zk.mjs";
import { anvilClients, deployContract, revertName } from "./demo/chain.mjs";
import { expect, failureCount, info, step, style } from "./demo/output.mjs";
import { logContains, RUN_DIR, readLog, sleep, startService, stopServices, waitFor } from "./demo/services.mjs";

/** @typedef {import("../lib/attestation.mjs").Attestation} Attestation */
/** @typedef {import("../lib/zk.mjs").Secrets} Secrets */
/** @typedef {import("viem").Hex} Hex */

// Non-default ports so the demo does not collide with `npm run bank` etc.
const PORTS = {
  anvil: Number(process.env.POR_ANVIL_PORT ?? 18545),
  bank: Number(process.env.POR_BANK_PORT ?? 18443),
  bankSim: Number(process.env.POR_SIM_PORT ?? 18444),
  impostor: Number(process.env.POR_EVIL_PORT ?? 18445),
  impostorSim: Number(process.env.POR_EVIL_SIM_PORT ?? 18446),
  notary: Number(process.env.POR_NOTARY_PORT ?? 17047),
  verifier: Number(process.env.POR_VERIFIER_PORT ?? 18787),
};
const SESSION_TOKEN = "mockbank_sess_9f3c1e7a2b"; // the mock bank's fake token
const RUST_BIN = path.join(ROOT, "prover-rs", "target", "release");

// anvil's default dev accounts #0, #3, #2. These keys are printed by every
// anvil instance and are public; never use them anywhere else.
const TREASURY = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const AGENT = privateKeyToAccount("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");
const ATTACKER = privateKeyToAccount("0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6");

/** @param {number | bigint} whole */
const usdc = (whole) => BigInt(whole) * 1_000_000n;

/** @type {Record<string, unknown>} */
const metrics = {};

/**
 * Runs the Rust prover against a bank and returns its output files.
 * @param {{ narration: string, bankPort?: number, ca?: string, outDir: string, timeoutMs?: number }} p
 */
function notarize({ narration, bankPort = PORTS.bank, ca = "certs/root_ca.der", outDir, timeoutMs = 90_000 }) {
  const result = runCommand(
    path.join(RUST_BIN, "prove"),
    [
      "--notary",
      `127.0.0.1:${PORTS.notary}`,
      "--bank",
      `127.0.0.1:${bankPort}`,
      "--ca",
      ca,
      "--token",
      SESSION_TOKEN,
      "--narration",
      narration,
      "--out",
      outDir,
      "--timeout",
      String(Math.ceil(timeoutMs / 1000) - 5),
    ],
    { cwd: ROOT, env: { ...process.env, RUST_LOG: "error" }, timeout: timeoutMs, killSignal: "SIGKILL" },
  );
  if (result.spawnError) throw new Error(result.spawnError);
  /** @param {string} file */
  const readJson = (file) => JSON.parse(fs.readFileSync(path.join(outDir, file), "utf8"));
  return {
    ...result,
    /** @returns {Attestation} */ attestation: () => readJson("attestation.json"),
    /** @returns {Secrets} */ secrets: () => readJson("secrets.json"),
    /** @returns {Record<string, number>} */ metrics: () => readJson("tlsn-metrics.json"),
  };
}

/**
 * @param {number} port
 * @param {{ amount: string, narration: string, ts: number }} credit
 * @returns {Promise<{ ref: string }>}
 */
async function bookCredit(port, credit) {
  const res = await fetch(`http://127.0.0.1:${port}/_sim/credit`, { method: "POST", body: JSON.stringify(credit) });
  if (!res.ok) throw new Error(`bank simulator returned ${res.status}: ${await res.text()}`);
  return res.json();
}

/**
 * @param {unknown} bundle
 * @returns {Promise<import("../verifier/verify.mjs").VerifyResult>}
 */
async function postVerify(bundle) {
  const res = await fetch(`http://127.0.0.1:${PORTS.verifier}/verify`, {
    method: "POST",
    body: JSON.stringify(bundle),
  });
  const body = await res.json();
  if (res.status !== 200) throw new Error(`verifier service error ${res.status}: ${body.error}`);
  return body;
}

/** @param {import("../verifier/verify.mjs").VerifyResult} v */
const failedChecks = (v) =>
  v.checks
    .filter((c) => !c.ok)
    .map((c) => c.name)
    .join(", ");

function checkPrerequisites() {
  const required = [
    [path.join(RUST_BIN, "prove"), "npm run build:rust"],
    [path.join(ROOT, "contracts/out/RemittanceEscrow.sol/RemittanceEscrow.json"), "npm run build:contracts"],
    [path.join(ROOT, "circuit/target/remittance.json"), "npm run build:circuit"],
    [path.join(ROOT, "certs/root_ca.der"), "npm run certs"],
  ];
  for (const [file, fix] of required) {
    if (!fs.existsSync(file))
      throw new Error(`missing ${path.relative(ROOT, file)}; run \`${fix}\` (or \`npm run build\`)`);
  }
}

async function main() {
  checkPrerequisites();
  fs.rmSync(RUN_DIR, { recursive: true, force: true });
  fs.mkdirSync(RUN_DIR, { recursive: true });
  console.log(
    `${style.bold}Proof of Remittance${style.reset}: TLSNotary + Noir + EVM escrow, all local, mock bank only`,
  );

  // ------------------------------------------------------------------ boot
  step(0, "Boot: local chain, mock bank, impostor bank, notary, verifier service");
  // Fresh notary key per run: nothing persistent to leak.
  const notaryKey = generatePrivateKey();
  const notaryAddress = privateKeyToAccount(notaryKey).address;
  startService("anvil", "anvil", ["--port", String(PORTS.anvil), "--silent"]);
  startService("bank", "node", ["bank/server.mjs"], { BANK_PORT: PORTS.bank, BANK_SIM_PORT: PORTS.bankSim });
  startService("impostor", "node", ["bank/server.mjs"], {
    BANK_PORT: PORTS.impostor,
    BANK_SIM_PORT: PORTS.impostorSim,
    BANK_EVIL: "1",
  });
  startService(
    "notary",
    path.join(RUST_BIN, "notary"),
    ["--listen", `127.0.0.1:${PORTS.notary}`, "--ca", "certs/root_ca.der"],
    {
      NOTARY_KEY: notaryKey,
      RUST_LOG: "error",
    },
  );
  startService("verifier", "node", ["verifier/server.mjs"], {
    VERIFIER_PORT: PORTS.verifier,
    NOTARY_ADDRESS: notaryAddress,
  });

  const { publicClient, walletFor } = anvilClients(PORTS.anvil);
  await waitFor(() => publicClient.getChainId(), "anvil (is Foundry installed?)");
  await waitFor(logContains("bank", "simulator"), "mock bank");
  await waitFor(logContains("impostor", "simulator"), "impostor bank");
  await waitFor(logContains("notary", "listening"), "notary");
  await waitFor(logContains("verifier", "/verify"), "verifier service");
  info(
    `anvil :${PORTS.anvil} · bank https://${SERVER_DOMAIN}:${PORTS.bank} · notary :${PORTS.notary} (signer ${notaryAddress})`,
  );

  // ------------------------------------------------------------------ deploy
  step(1, "Deploy MockUSDC, HonkVerifier (generated by bb), RemittanceEscrow");
  const treasury = walletFor(TREASURY);
  /** @param {string} name @param {readonly unknown[]} [args] */
  const deploy = (name, args = []) => deployContract(publicClient, treasury, name, args, info);
  const token = await deploy("MockUSDC");
  const honk = await deploy("HonkVerifier");
  const escrow = await deploy("RemittanceEscrow", [
    token.address,
    honk.address,
    notaryAddress,
    SERVER_DOMAIN,
    ENDPOINT,
  ]);
  metrics.deployGasHonkVerifier = Number(honk.gas);

  /**
   * @param {ReturnType<typeof walletFor>} wallet
   * @param {import("./demo/chain.mjs").Deployed} contract
   * @param {string} functionName
   * @param {readonly unknown[]} args
   */
  const write = async (wallet, contract, functionName, args) => {
    const hash = await wallet.writeContract({ address: contract.address, abi: contract.abi, functionName, args });
    return publicClient.waitForTransactionReceipt({ hash });
  };
  /**
   * @param {import("./demo/chain.mjs").Deployed} contract
   * @param {string} functionName
   * @param {readonly unknown[]} [args]
   */
  const read = (contract, functionName, args = []) =>
    publicClient.readContract({ address: contract.address, abi: contract.abi, functionName, args });
  /** @param {bigint} id @returns {Promise<bigint>} escrow.minTs */
  const minTsOf = async (id) =>
    /** @type {readonly [unknown, unknown, unknown, unknown, bigint]} */ (await read(escrow, "escrows", [id]))[4];

  // ------------------------------------------------------------------ escrow
  step(2, "Treasury escrows 500 USDC for the agent, unlocks on an INR credit >= Rs 45,000");
  await write(treasury, token, "mint", [TREASURY.address, usdc(1000)]);
  await write(treasury, token, "approve", [escrow.address, usdc(1000)]);
  await write(treasury, escrow, "createEscrow", [AGENT.address, usdc(500), 4_500_000n, 86_400n]);
  await write(treasury, escrow, "createEscrow", [AGENT.address, usdc(300), 10_000_000n, 86_400n]);
  const minTs1 = await minTsOf(1n);
  const minTs2 = await minTsOf(2n);
  const chainId = await publicClient.getChainId();
  /** Escrow terms as a relying party would read them from the contract. */
  const termsOf = (/** @type {bigint} */ id, /** @type {bigint} */ thresholdPaise, /** @type {bigint} */ minTs) => ({
    chainId: String(chainId),
    contract: escrow.address,
    id: String(id),
    thresholdPaise: String(thresholdPaise),
    minTs: String(minTs),
  });
  const narration1 = /** @type {string} */ (await read(escrow, "narrationFor", [1n]));
  const narration2 = /** @type {string} */ (await read(escrow, "narrationFor", [2n]));
  if (narration1 !== narrationFor({ chainId, contract: escrow.address, id: 1 })) {
    throw new Error("JS narrationFor disagrees with RemittanceEscrow.narrationFor");
  }
  info(`escrow #1: 500 USDC -> agent ${AGENT.address.slice(0, 10)}..., threshold Rs 45,000.00, minTs ${minTs1}`);
  info(`payer must use narration "${narration1}" (derived from chain id, contract and escrow id)`);
  info("escrow #2: 300 USDC, threshold Rs 1,00,000.00 (target of the attacks below)");

  // ------------------------------------------------------------------ fiat leg
  step(3, "Fiat leg: a Rs 50,000.00 IMPS credit lands in the (mock) bank account");
  const credit = await bookCredit(PORTS.bankSim, {
    amount: "50000.00",
    narration: narration1,
    ts: Math.max(Number(minTs1) + 5, Math.floor(Date.now() / 1000)),
  });
  info(`bank booked: ${JSON.stringify(credit)}`);
  await bookCredit(PORTS.bankSim, { amount: "1500.00", narration: narration2, ts: Number(minTs2) + 6 });
  info("(also a Rs 1,500.00 credit for escrow #2, far below its threshold)");

  // ------------------------------------------------------------------ zkTLS
  step(4, "zkTLS: prover and notary run MPC-TLS against the bank, prover discloses selectively");
  const run1 = notarize({ narration: narration1, outDir: path.join(RUN_DIR, "proof1") });
  if (!run1.ok) throw new Error(`prover failed:\n${run1.out}`);
  const att = run1.attestation();
  const secrets = run1.secrets();
  const tlsn = run1.metrics();
  Object.assign(metrics, { tlsn, tlsnWallMs: run1.ms });
  info(
    `MPC-TLS session + disclosure: ${tlsn.total_ms} ms (setup ${tlsn.mpc_setup_ms}, request ${tlsn.tls_request_ms}, disclose ${tlsn.selective_disclosure_ms}); process wall ${run1.ms} ms`,
  );
  info(`transcript: ${tlsn.sent_bytes} B sent, ${tlsn.recv_bytes} B received`);
  const body = att.redacted_view ?? "";
  const objStart = body.indexOf('{"amount"');
  info(`what the notary saw of the body (${body.length} B, * = hidden):`);
  info(
    `${style.dim}${body.slice(0, 40)}...${style.reset}${style.yellow}${body.slice(objStart, body.indexOf("}", objStart) + 1)}${style.reset}${style.dim}...${style.reset}`,
  );
  info(
    `notary signed: currency=${att.currency} narration=${att.narration} amount_commitment=${att.amount_commitment.slice(0, 18)}...`,
  );
  expect(
    !body.includes("50000.00") && !body.includes(credit.ref) && !body.includes("000012345678"),
    "notary never saw the amount, the UTR ref, or the account number",
  );

  // ------------------------------------------------------------------ ZK
  step(5, "ZK predicate (Noir, UltraHonk/keccak): amount >= Rs 45,000 and ts >= minTs, values hidden");
  const zk = proveZk({
    secrets,
    attestation: att,
    thresholdPaise: 4_500_000n,
    minTs: minTs1,
    outDir: path.join(RUN_DIR, "proof1", "zk"),
  });
  if (!zk.ok) throw new Error(`zk failed at ${zk.stage}: ${zk.reason}`);
  Object.assign(metrics, { zkWitnessMs: zk.witnessMs, zkProveMs: zk.proveMs, zkProofBytes: zk.proofBytes });
  info(`witness ${zk.witnessMs} ms, proof ${zk.proveMs} ms, ${zk.proofBytes} bytes`);
  const bundle = {
    escrow: termsOf(1n, 4_500_000n, minTs1),
    attestation: att,
    proof: zk.proofHex,
  };
  fs.writeFileSync(path.join(RUN_DIR, "bundle1.json"), JSON.stringify(bundle));
  // Foundry/JS replay fixture. `npm run fixture` copies it to contracts/test/fixtures.
  fs.writeFileSync(
    path.join(RUN_DIR, "fixture.json"),
    `${JSON.stringify(
      {
        chainId,
        escrowAddress: escrow.address,
        escrowId: 1,
        thresholdPaise: 4500000,
        minTs: Number(minTs1),
        notary: notaryAddress,
        serverName: att.server_name,
        endpoint: att.endpoint,
        currency: att.currency,
        narration: att.narration,
        amountCommitment: att.amount_commitment,
        tsCommitment: att.ts_commitment,
        sessionTime: att.session_time,
        signature: att.signature,
        proof: zk.proofHex,
      },
      null,
      1,
    )}\n`,
  );

  // ------------------------------------------------------------------ off-chain verify
  step(6, "Verifier service (off-chain): same checks as the contract");
  const verdict = await postVerify(bundle);
  for (const check of verdict.checks) {
    const mark = check.ok ? `${style.green}ok ` : `${style.red}BAD`;
    info(`${mark}${style.reset} ${check.name} ${style.dim}${check.detail}${style.reset}`);
  }
  expect(verdict.ok, "verifier service accepts the proof");

  // ------------------------------------------------------------------ on-chain
  step(7, "On-chain: RemittanceEscrow.release() checks notary sig + UltraHonk proof, pays the agent");
  const sol = toSolidityAttestation(att);
  const escrow1Inputs = await read(escrow, "publicInputs", [1n, sol]);
  const verifyGas = await publicClient.estimateContractGas({
    address: honk.address,
    abi: honk.abi,
    functionName: "verify",
    args: [zk.proofHex, escrow1Inputs],
  });
  const balanceOf = async () => /** @type {bigint} */ (await read(token, "balanceOf", [AGENT.address]));
  const before = await balanceOf();
  // Anyone may submit; funds can only go to the escrow's beneficiary.
  const receipt = await write(walletFor(ATTACKER), escrow, "release", [1n, sol, att.signature, zk.proofHex]);
  const after = await balanceOf();
  metrics.releaseGas = Number(receipt.gasUsed);
  metrics.honkVerifyGasEstimate = Number(verifyGas);
  info(
    `release tx ${receipt.transactionHash.slice(0, 18)}... status=${receipt.status}, gas ${receipt.gasUsed} (HonkVerifier.verify alone ~${verifyGas})`,
  );
  info(`agent USDC: ${formatUnits(before, 6)} -> ${formatUnits(after, 6)}`);
  expect(receipt.status === "success" && after - before === usdc(500), "escrow #1 released 500 USDC to the agent");

  // ------------------------------------------------------------------ attacks
  step(8, "Attacks (each must be rejected)");
  /** @param {readonly unknown[]} args @returns {Promise<string>} the revert error name */
  const simulateRelease = async (args) => {
    try {
      await publicClient.simulateContract({
        account: ATTACKER,
        address: escrow.address,
        abi: escrow.abi,
        functionName: "release",
        args,
      });
      return "NOT REVERTED";
    } catch (e) {
      return revertName(e);
    }
  };

  // a. Replay.
  let outcome = await simulateRelease([1n, sol, att.signature, zk.proofHex]);
  expect(outcome === "AlreadySettled", `replay on escrow #1 -> ${outcome}`);

  // b. Tampered proof: flip one hex digit.
  const flipAt = 602;
  const tampered = /** @type {Hex} */ (
    zk.proofHex.slice(0, flipAt) + (zk.proofHex[flipAt] === "0" ? "1" : "0") + zk.proofHex.slice(flipAt + 1)
  );
  const tamperedVerdict = await postVerify({ ...bundle, proof: tampered });
  expect(!tamperedVerdict.ok, `tampered proof: verifier service -> rejected (${failedChecks(tamperedVerdict)})`);
  const honkOnTampered = await publicClient
    .readContract({ address: honk.address, abi: honk.abi, functionName: "verify", args: [tampered, escrow1Inputs] })
    .then((accepted) => (accepted ? "accepted" : "returned false"))
    .catch((e) => `reverted: ${revertName(e)}`);
  expect(!honkOnTampered.startsWith("accepted"), `tampered proof: on-chain HonkVerifier -> ${honkOnTampered}`);

  // c. Under threshold: the genuine Rs 1,500 credit against escrow #2 (Rs 1,00,000).
  const run2 = notarize({ narration: narration2, outDir: path.join(RUN_DIR, "proof2") });
  if (!run2.ok) throw new Error(`prover failed for escrow #2:\n${run2.out}`);
  const att2 = run2.attestation();
  const secrets2 = run2.secrets();
  info("zkTLS for escrow #2's credit: notarized (amount still hidden)");
  const zk2 = proveZk({
    secrets: secrets2,
    attestation: att2,
    thresholdPaise: 10_000_000n,
    minTs: minTs2,
    outDir: path.join(RUN_DIR, "proof2", "zk"),
  });
  expect(!zk2.ok, `under-threshold credit: prover cannot build a ZK proof -> ${zk2.ok ? "proof built!" : zk2.reason}`);
  outcome = await simulateRelease([2n, toSolidityAttestation(att2), att2.signature, zk.proofHex]);
  expect(outcome === "ZkProofRejected", `under-threshold, submitting escrow #1's proof bytes instead -> ${outcome}`);

  // d. Forged commitment: commit to an invented Rs 1,50,000.00 with the
  //    attacker's own blinder, build a VALID ZK proof for it, keep the notary
  //    signature. The circuit is satisfied; the signature no longer matches.
  const fakeBlinder = /** @type {Hex} */ (`0x${crypto.randomBytes(16).toString("hex")}`);
  const fakeCommitment = /** @type {Hex} */ (
    `0x${crypto
      .createHash("sha256")
      .update(Buffer.concat([Buffer.from("150000.00"), Buffer.from(fakeBlinder.slice(2), "hex")]))
      .digest("hex")}`
  );
  const forged = { ...att2, amount_commitment: fakeCommitment };
  const forgedZk = proveZk({
    secrets: { ...secrets2, amount: { plaintext: "150000.00", blinder: fakeBlinder } },
    attestation: forged,
    thresholdPaise: 10_000_000n,
    minTs: minTs2,
    outDir: path.join(RUN_DIR, "forged-zk"),
  });
  if (!forgedZk.ok) throw new Error(`could not build the forged proof: ${forgedZk.reason}`);
  info("attacker's ZK proof for the invented commitment: generated (the circuit is satisfied)");
  const forgedVerdict = await postVerify({
    escrow: termsOf(2n, 10_000_000n, minTs2),
    attestation: forged,
    proof: forgedZk.proofHex,
  });
  expect(!forgedVerdict.ok, `forged commitment: verifier service -> rejected (${failedChecks(forgedVerdict)})`);
  outcome = await simulateRelease([2n, toSolidityAttestation(forged), att2.signature, forgedZk.proofHex]);
  expect(outcome === "BadNotarySignature", `forged commitment on-chain -> ${outcome}`);

  // e. Cross-escrow reuse.
  outcome = await simulateRelease([2n, sol, att.signature, zk.proofHex]);
  expect(outcome === "WrongNarration", `reuse escrow #1's attestation on escrow #2 -> ${outcome}`);

  // f. Cross-deployment replay: a second escrow contract trusting the same
  //    notary, with its own escrow #1. The narration hashes in (chain id,
  //    contract, id), so escrow #1's credit does not match it.
  const escrowB = await deploy("RemittanceEscrow", [
    token.address,
    honk.address,
    notaryAddress,
    SERVER_DOMAIN,
    ENDPOINT,
  ]);
  await write(treasury, token, "approve", [escrowB.address, usdc(100)]);
  await write(treasury, escrowB, "createEscrow", [AGENT.address, usdc(100), 4_500_000n, 86_400n]);
  info(`second deployment's escrow #1 expects narration "${await read(escrowB, "narrationFor", [1n])}"`);
  try {
    await publicClient.simulateContract({
      account: ATTACKER,
      address: escrowB.address,
      abi: escrowB.abi,
      functionName: "release",
      args: [1n, sol, att.signature, zk.proofHex],
    });
    outcome = "NOT REVERTED";
  } catch (e) {
    outcome = revertName(e);
  }
  expect(outcome === "WrongNarration", `replay escrow #1's bundle on another deployment's escrow #1 -> ${outcome}`);

  // g. Impostor bank: same hostname, valid chain to an "Impostor CA" that a
  //    malicious prover trusts but the notary does not.
  await bookCredit(PORTS.impostorSim, { amount: "999999.00", narration: narration2, ts: Number(minTs2) + 7 });
  const impostorDir = path.join(RUN_DIR, "impostor");
  const impostor = notarize({
    narration: narration2,
    bankPort: PORTS.impostor,
    ca: "certs/evil_ca.der",
    outDir: impostorDir,
    timeoutMs: 20_000,
  });
  await sleep(200);
  const rejection =
    readLog("notary")
      .trim()
      .split("\n")
      .filter((l) => l.includes("REJECTED"))
      .pop() ?? "";
  expect(
    !impostor.ok && !fs.existsSync(path.join(impostorDir, "attestation.json")) && rejection.includes("certificate"),
    `impostor bank (untrusted CA): no attestation issued ${style.dim}${rejection.slice(0, 120)}${style.reset}`,
  );

  // ------------------------------------------------------------------ summary
  step(9, "Numbers (this run, this machine, loopback network)");
  const { redacted_view: _omitted, ...attestationWithoutView } = att;
  Object.assign(metrics, { attestationJsonBytes: Buffer.byteLength(JSON.stringify(attestationWithoutView)) });
  for (const [k, v] of Object.entries(metrics))
    info(`${k.padEnd(24)} ${typeof v === "object" ? JSON.stringify(v) : v}`);
  fs.writeFileSync(path.join(RUN_DIR, "metrics.json"), JSON.stringify(metrics, null, 2));

  const failures = failureCount();
  console.log(
    failures === 0
      ? `\n${style.green}${style.bold}ALL CHECKS PASSED${style.reset}`
      : `\n${style.red}${style.bold}${failures} CHECK(S) FAILED${style.reset}`,
  );
  return failures === 0 ? 0 : 1;
}

process.on("SIGINT", () => {
  stopServices();
  process.exit(130);
});

main()
  .then((code) => {
    stopServices();
    process.exit(code);
  })
  .catch((e) => {
    console.error(`\n${style.red}demo aborted:${style.reset}`, e instanceof Error ? e.message : e);
    stopServices();
    process.exit(1);
  });
