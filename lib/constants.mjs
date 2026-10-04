// Values shared by the verifier service, the demo and the tests. They must
// match prover-rs/src/lib.rs and the RemittanceEscrow constructor arguments.
import path from "node:path";
import { fileURLToPath } from "node:url";
import { encodeAbiParameters, keccak256 } from "viem";

/** Repository root. */
export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
/** Noir circuit package directory. */
export const CIRCUIT_DIR = path.join(ROOT, "circuit");
/** Verification key written by `bb write_vk` (committed, so the verifier works without building the circuit). */
export const VK_PATH = path.join(CIRCUIT_DIR, "target", "vk");

/** TLS server name the notary authenticates. */
export const SERVER_DOMAIN = "netbanking.mockbank.test";
/** Request line the attestation commits to. */
export const ENDPOINT = "GET /api/v1/accounts/me/credits";
/** Domain separator hashed into every attestation digest. */
export const ATTESTATION_VERSION = "POR_TLSN_V1";
/** Only currency the escrow accepts. */
export const CURRENCY = "INR";

/**
 * Narration the payer must put on the transfer for escrow `id` of the escrow
 * contract `contract` on chain `chainId`: "POR-" plus the first 10 bytes of
 * keccak256(abi.encode(chainId, contract, id)) as uppercase hex. Mirrors
 * `RemittanceEscrow.narrationFor`.
 *
 * Binding the deployment into the narration is what stops one bank credit
 * from releasing "escrow #1" on every contract that trusts the same notary.
 * @param {{ chainId: number | bigint | string, contract: string, id: number | bigint | string }} escrow
 */
export function narrationFor({ chainId, contract, id }) {
  const h = keccak256(
    encodeAbiParameters(
      [{ type: "uint256" }, { type: "address" }, { type: "uint256" }],
      [BigInt(chainId), /** @type {`0x${string}`} */ (contract), BigInt(id)],
    ),
  );
  return `POR-${h.slice(2, 22).toUpperCase()}`;
}
