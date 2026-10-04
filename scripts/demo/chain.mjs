// Local-chain helpers for the demo: viem clients for anvil, Foundry artifact
// loading with library linking, and revert-reason extraction.
import fs from "node:fs";
import path from "node:path";
import {
  BaseError,
  ContractFunctionRevertedError,
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
} from "viem";
import { ROOT } from "../../lib/constants.mjs";

/** @typedef {import("viem").Abi} Abi */
/** @typedef {import("viem").Address} Address */
/** @typedef {import("viem").Hex} Hex */
/** @typedef {import("viem").Account} Account */
/** @typedef {{ address: Address, abi: Abi, gas: bigint }} Deployed */

/** @param {number} port */
export function anvilClients(port) {
  const chain = defineChain({
    id: 31337,
    name: "anvil",
    nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [`http://127.0.0.1:${port}`] } },
  });
  const publicClient = createPublicClient({ chain, transport: http() });
  /** @param {Account} account */
  const walletFor = (account) => createWalletClient({ account, chain, transport: http() });
  return { publicClient, walletFor };
}

/** @typedef {ReturnType<typeof anvilClients>["publicClient"]} PublicClient */
/** @typedef {ReturnType<ReturnType<typeof anvilClients>["walletFor"]>} WalletClient */

/**
 * Reads a Foundry artifact from contracts/out.
 * @param {string} contract   contract name
 * @param {string} [file]     source file stem, if different from the contract name
 */
function loadArtifact(contract, file = contract) {
  const p = path.join(ROOT, "contracts", "out", `${file}.sol`, `${contract}.json`);
  if (!fs.existsSync(p)) throw new Error(`missing ${path.relative(ROOT, p)}; run \`npm run build:contracts\``);
  const json = JSON.parse(fs.readFileSync(p, "utf8"));
  return {
    /** @type {Abi} */ abi: json.abi,
    /** @type {Hex} */ bytecode: json.bytecode.object,
    /** @type {Record<string, Record<string, { start: number, length: number }[]>>} */
    links: json.bytecode.linkReferences ?? {},
  };
}

/**
 * Deploys a contract, first deploying and linking any external libraries it
 * references (bb's HonkVerifier links ZKTranscriptLib).
 *
 * @param {PublicClient} publicClient
 * @param {WalletClient} wallet
 * @param {string} contract
 * @param {readonly unknown[]} [args]
 * @param {(line: string) => void} [log]
 * @param {string} [file]
 * @returns {Promise<Deployed>}
 */
export async function deployContract(publicClient, wallet, contract, args = [], log = () => {}, file = contract) {
  const artifact = loadArtifact(contract, file);
  let code = artifact.bytecode;
  for (const [source, libs] of Object.entries(artifact.links)) {
    for (const [lib, refs] of Object.entries(libs)) {
      const deployed = await deployContract(publicClient, wallet, lib, [], log, path.basename(source, ".sol"));
      const addr = deployed.address.slice(2).toLowerCase();
      for (const { start, length } of refs) {
        const at = 2 + start * 2; // hex chars, after "0x"
        code = /** @type {Hex} */ (code.slice(0, at) + addr + code.slice(at + length * 2));
      }
    }
  }
  const hash = await wallet.deployContract({ abi: artifact.abi, bytecode: code, args });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (!receipt.contractAddress) throw new Error(`${contract} deployment produced no address`);
  log(`${contract.padEnd(17)} ${receipt.contractAddress}  (${receipt.gasUsed} gas)`);
  return { address: receipt.contractAddress, abi: artifact.abi, gas: receipt.gasUsed };
}

/**
 * Custom error name (or reason string) from a failed contract call.
 * @param {unknown} e
 */
export function revertName(e) {
  if (e instanceof BaseError) {
    const reverted = e.walk((x) => x instanceof ContractFunctionRevertedError);
    if (reverted instanceof ContractFunctionRevertedError) {
      return reverted.data?.errorName ?? reverted.reason ?? "reverted";
    }
    return e.shortMessage;
  }
  return e instanceof Error ? e.message.split("\n")[0] : String(e);
}
