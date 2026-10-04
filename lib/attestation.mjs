// The notary's attestation: type, digest and signer recovery. The digest must
// stay byte-identical to prover-rs/src/lib.rs `digest` and
// RemittanceEscrow.attestationDigest; test/attestation.test.mjs checks this
// against a signature produced by the Rust notary.
import { encodeAbiParameters, keccak256, recoverMessageAddress, toBytes } from "viem";
import { ATTESTATION_VERSION } from "./constants.mjs";

/**
 * Attestation as written by the `prove` binary to `attestation.json`.
 * @typedef {object} Attestation
 * @property {string} version            always "POR_TLSN_V1"
 * @property {string} server_name        TLS server name the notary authenticated
 * @property {string} endpoint           request line, e.g. "GET /api/v1/accounts/me/credits"
 * @property {string} currency           revealed currency of the credit
 * @property {string} narration          revealed narration, binds the credit to an escrow
 * @property {`0x${string}`} amount_commitment  sha256(amount || blinder)
 * @property {`0x${string}`} ts_commitment      sha256(ts || blinder)
 * @property {number} session_time       notary clock at verification, unix seconds
 * @property {`0x${string}`} signature   65-byte EIP-191 signature over `digest`
 * @property {`0x${string}`} [digest]    attestationDigest of the fields above
 * @property {string} [notary]           notary address (informational, never trusted)
 * @property {number} [amount_len]       byte length of the hidden amount
 * @property {string} [redacted_view]    response body as the notary saw it, `*` = hidden
 */

/**
 * Same struct, shaped for `RemittanceEscrow.release`.
 * @typedef {object} SolidityAttestation
 * @property {string} serverName
 * @property {string} endpoint
 * @property {string} currency
 * @property {string} narration
 * @property {`0x${string}`} amountCommitment
 * @property {`0x${string}`} tsCommitment
 * @property {bigint} sessionTime
 */

/** @param {string} s */
const hashString = (s) => keccak256(toBytes(s));

/**
 * keccak256(abi.encode(...)) digest the notary signs.
 * @param {Attestation} a
 * @returns {`0x${string}`}
 */
export function attestationDigest(a) {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "uint256" },
      ],
      [
        hashString(ATTESTATION_VERSION),
        hashString(a.server_name),
        hashString(a.endpoint),
        hashString(a.currency),
        hashString(a.narration),
        a.amount_commitment,
        a.ts_commitment,
        BigInt(a.session_time),
      ],
    ),
  );
}

/**
 * Address that produced `a.signature` over `attestationDigest(a)`.
 * Throws if the signature is malformed.
 * @param {Attestation} a
 */
export function recoverNotary(a) {
  return recoverMessageAddress({ message: { raw: attestationDigest(a) }, signature: a.signature });
}

/**
 * @param {Attestation} a
 * @returns {SolidityAttestation}
 */
export function toSolidityAttestation(a) {
  return {
    serverName: a.server_name,
    endpoint: a.endpoint,
    currency: a.currency,
    narration: a.narration,
    amountCommitment: a.amount_commitment,
    tsCommitment: a.ts_commitment,
    sessionTime: BigInt(a.session_time),
  };
}
