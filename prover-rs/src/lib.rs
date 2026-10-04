//! Shared types for the Proof of Remittance prover (`prove`) and notary
//! (`notary`) binaries.
//!
//! The notary is a TLSNotary *verifier* that, after a successful MPC-TLS
//! session, signs a compact EVM-friendly attestation over:
//!   - the server name it authenticated (certificate chain checked by the notary)
//!   - the request line the prover revealed
//!   - the revealed `currency` and `narration` of one credit object
//!   - the SHA-256 plaintext commitments to that credit's `amount` and `ts`
//!
//! It never sees the amount, the timestamp, the UTR reference, the account
//! number, the balance or the session token. The amount and timestamp are
//! later proven to satisfy the escrow's predicate in a Noir circuit that opens
//! the commitments in zero knowledge.

use anyhow::{Result, anyhow, bail};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

pub mod template;

/// TLS server name the notary requires (must match the bank certificate SAN).
pub const SERVER_DOMAIN: &str = "netbanking.mockbank.test";
/// Request line (method + path) that the attestation commits to.
pub const ENDPOINT: &str = "GET /api/v1/accounts/me/credits";
/// Path part of [`ENDPOINT`].
pub const ENDPOINT_PATH: &str = "/api/v1/accounts/me/credits";
/// Domain separator, hashed into every attestation digest.
pub const ATTESTATION_VERSION: &str = "POR_TLSN_V1";

/// Upper bound on bytes the prover may send. MPC-TLS preprocesses for a fixed
/// transcript size up front, so smaller limits make the session faster.
pub const MAX_SENT_DATA: usize = 1 << 10;
/// Upper bound on bytes the prover may receive. See [`MAX_SENT_DATA`].
pub const MAX_RECV_DATA: usize = 1 << 12;

/// Width of the `ts` field (unix seconds) the circuit expects.
pub const TS_LEN: usize = 10;

/// Longest `amount` string the Noir circuit accepts (`MAX_AMOUNT_LEN` there).
pub const MAX_AMOUNT_LEN: usize = 16;

/// Longest hidden `ref` (UTR / RRN) the notary accepts. A full credit object
/// is far longer than this, so a hidden run this short cannot cross into a
/// neighbouring credit and splice one credit's amount onto another's `ts`.
pub const MAX_REF_LEN: usize = 32;

/// The notary's signed statement about one credit, as written to
/// `attestation.json`. Field names are snake_case on the wire.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Attestation {
    /// Always [`ATTESTATION_VERSION`].
    pub version: String,
    /// TLS server name the notary authenticated.
    pub server_name: String,
    /// Request line, see [`ENDPOINT`].
    pub endpoint: String,
    /// Revealed `currency` of the credit.
    pub currency: String,
    /// Revealed `narration` of the credit. Binds the credit to an escrow id.
    pub narration: String,
    /// sha256(amount_bytes || blinder), hex 0x-prefixed.
    pub amount_commitment: String,
    /// sha256(ts_bytes || blinder), hex 0x-prefixed.
    pub ts_commitment: String,
    /// Byte length of the hidden amount string (inherent TLSNotary leakage).
    pub amount_len: usize,
    /// Notary wall clock when the session was verified (unix seconds).
    pub session_time: u64,
    /// What the notary actually saw of the response body, redactions as `*`.
    pub redacted_view: String,
    /// keccak256(abi.encode(...)) of the fields above, see [`digest`].
    pub digest: String,
    /// 65-byte r||s||v signature over the EIP-191 hash of `digest`.
    pub signature: String,
    /// Ethereum address of the notary signing key.
    pub notary: String,
}

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn u256_word(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

/// Parses a 0x-prefixed (or bare) 32-byte hex string.
pub fn hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.trim_start_matches("0x"))?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| anyhow!("expected 32 bytes, got {}", b.len()))
}

/// Attestation digest. Mirrors `RemittanceEscrow.attestationDigest` in
/// Solidity and `attestationDigest` in `lib/attestation.mjs`:
///
/// ```text
/// keccak256(abi.encode(
///   keccak256("POR_TLSN_V1"), keccak256(serverName), keccak256(endpoint),
///   keccak256(currency), keccak256(narration),
///   amountCommitment, tsCommitment, uint256(sessionTime)))
/// ```
pub fn digest(a: &Attestation) -> Result<[u8; 32]> {
    let mut enc = Vec::with_capacity(32 * 8);
    enc.extend_from_slice(&keccak(ATTESTATION_VERSION.as_bytes()));
    enc.extend_from_slice(&keccak(a.server_name.as_bytes()));
    enc.extend_from_slice(&keccak(a.endpoint.as_bytes()));
    enc.extend_from_slice(&keccak(a.currency.as_bytes()));
    enc.extend_from_slice(&keccak(a.narration.as_bytes()));
    enc.extend_from_slice(&hex32(&a.amount_commitment)?);
    enc.extend_from_slice(&hex32(&a.ts_commitment)?);
    enc.extend_from_slice(&u256_word(a.session_time));
    Ok(keccak(&enc))
}

/// EIP-191 "personal_sign" hash of a 32-byte digest.
pub fn eth_signed_hash(digest: &[u8; 32]) -> [u8; 32] {
    let mut msg = b"\x19Ethereum Signed Message:\n32".to_vec();
    msg.extend_from_slice(digest);
    keccak(&msg)
}

/// Lowercase 0x-prefixed Ethereum address of a secp256k1 public key.
pub fn eth_address(vk: &VerifyingKey) -> String {
    let point = vk.to_encoded_point(false);
    let hash = keccak(&point.as_bytes()[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

/// Fills `digest`, `signature` and `notary` on `a`, signing with `key`.
pub fn sign(key: &SigningKey, a: &mut Attestation) -> Result<()> {
    let d = digest(a)?;
    // k256 always returns low-s signatures, which the contract requires.
    let (sig, recid): (Signature, RecoveryId) =
        key.sign_prehash_recoverable(&eth_signed_hash(&d))?;
    let mut out = sig.to_bytes().to_vec();
    out.push(27 + recid.to_byte());
    a.digest = format!("0x{}", hex::encode(d));
    a.signature = format!("0x{}", hex::encode(out));
    a.notary = eth_address(key.verifying_key());
    Ok(())
}

/// Recovers the signer address of `a.signature` over [`digest`]`(a)`.
pub fn recover_signer(a: &Attestation) -> Result<String> {
    let sig = hex::decode(a.signature.trim_start_matches("0x"))?;
    if sig.len() != 65 {
        bail!("signature must be 65 bytes, got {}", sig.len());
    }
    let v = sig[64]
        .checked_sub(27)
        .ok_or_else(|| anyhow!("signature v must be 27 or 28"))?;
    let recid = RecoveryId::from_byte(v).ok_or_else(|| anyhow!("signature v must be 27 or 28"))?;
    let signature = Signature::from_slice(&sig[..64])?;
    let vk = VerifyingKey::recover_from_prehash(&eth_signed_hash(&digest(a)?), &signature, recid)?;
    Ok(eth_address(&vk))
}

/// Loads the notary key from the `NOTARY_KEY` env var (32-byte hex).
pub fn load_signing_key() -> Result<SigningKey> {
    let hexkey = std::env::var("NOTARY_KEY").map_err(|_| {
        anyhow!("NOTARY_KEY is not set: export a 32-byte hex secp256k1 key (see .env.example)")
    })?;
    let bytes = hex::decode(hexkey.trim().trim_start_matches("0x"))
        .map_err(|e| anyhow!("NOTARY_KEY is not valid hex: {e}"))?;
    SigningKey::from_slice(&bytes)
        .map_err(|e| anyhow!("NOTARY_KEY is not a valid secp256k1 key: {e}"))
}

/// Reads a DER-encoded CA certificate.
pub fn load_ca(path: &str) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        anyhow!("reading CA cert {path}: {e} (run `npm run certs` to generate test certs)")
    })
}

/// One `--name value` command-line flag.
pub struct Flag {
    /// Flag name without the leading `--`.
    pub name: &'static str,
    /// Default value, or `None` if the flag is required.
    pub default: Option<&'static str>,
    /// One-line description for `--help`.
    pub help: &'static str,
}

/// Parsed `--name value` flags. Unknown flags are an error, so a typo never
/// silently falls back to a default.
pub struct Args {
    values: Vec<(&'static str, Option<String>)>,
}

impl Args {
    /// Parses `std::env::args()` against `flags`. Prints usage and exits on
    /// `--help`.
    pub fn parse(bin: &str, about: &str, flags: &[Flag]) -> Result<Self> {
        Self::parse_from(bin, about, flags, std::env::args().skip(1))
    }

    fn parse_from(
        bin: &str,
        about: &str,
        flags: &[Flag],
        argv: impl IntoIterator<Item = String>,
    ) -> Result<Self> {
        let mut values: Vec<(&'static str, Option<String>)> = flags
            .iter()
            .map(|f| (f.name, f.default.map(str::to_string)))
            .collect();
        let mut argv = argv.into_iter();
        while let Some(arg) = argv.next() {
            if arg == "--help" || arg == "-h" {
                println!("{bin}: {about}\n\nFlags:");
                for f in flags {
                    let dflt = f
                        .default
                        .map_or("required".to_string(), |d| format!("default {d}"));
                    println!("  --{:<10} {} ({dflt})", f.name, f.help);
                }
                std::process::exit(0);
            }
            let name = arg
                .strip_prefix("--")
                .ok_or_else(|| anyhow!("unexpected argument {arg:?}; see --help"))?;
            let slot = values
                .iter_mut()
                .find(|(n, _)| *n == name)
                .ok_or_else(|| anyhow!("unknown flag --{name}; see --help"))?;
            let value = argv
                .next()
                .ok_or_else(|| anyhow!("--{name} needs a value"))?;
            slot.1 = Some(value);
        }
        Ok(Self { values })
    }

    /// Value of flag `name` (its default if not given). Errors if required
    /// and missing.
    pub fn get(&self, name: &str) -> Result<String> {
        self.values
            .iter()
            .find(|(n, _)| *n == name)
            .ok_or_else(|| anyhow!("flag --{name} is not declared"))?
            .1
            .clone()
            .ok_or_else(|| anyhow!("missing required flag --{name}; see --help"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real attestation captured from `npm run demo`, shared with the
    /// Foundry and JS tests.
    fn fixture() -> Attestation {
        let raw = include_str!("../../contracts/test/fixtures/bundle.json");
        let j: serde_json::Value = serde_json::from_str(raw).expect("fixture is JSON");
        let s = |k: &str| j[k].as_str().expect(k).to_string();
        Attestation {
            version: ATTESTATION_VERSION.into(),
            server_name: s("serverName"),
            endpoint: s("endpoint"),
            currency: s("currency"),
            narration: s("narration"),
            amount_commitment: s("amountCommitment"),
            ts_commitment: s("tsCommitment"),
            session_time: j["sessionTime"].as_u64().expect("sessionTime"),
            signature: s("signature"),
            notary: s("notary"),
            ..Default::default()
        }
    }

    #[test]
    fn fixture_signature_recovers_to_notary() {
        let a = fixture();
        // The fixture stores the checksummed address; recover_signer returns lowercase.
        assert!(recover_signer(&a).unwrap().eq_ignore_ascii_case(&a.notary));
    }

    #[test]
    fn any_field_change_breaks_the_signature() {
        let mut a = fixture();
        a.narration = "POR-00000000000000000000".into();
        assert!(
            !recover_signer(&a)
                .unwrap()
                .eq_ignore_ascii_case(&fixture().notary)
        );
        let mut a = fixture();
        a.session_time += 1;
        assert!(
            !recover_signer(&a)
                .unwrap()
                .eq_ignore_ascii_case(&fixture().notary)
        );
    }

    #[test]
    fn sign_then_recover_roundtrip() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let mut a = fixture();
        sign(&key, &mut a).unwrap();
        assert_eq!(
            recover_signer(&a).unwrap(),
            eth_address(key.verifying_key())
        );
        assert_eq!(a.notary, eth_address(key.verifying_key()));
    }

    #[test]
    fn hex32_rejects_wrong_length() {
        assert!(hex32("0x1234").is_err());
        assert!(hex32(&format!("0x{}", "00".repeat(32))).is_ok());
    }

    const FLAGS: &[Flag] = &[
        Flag {
            name: "out",
            default: Some("out"),
            help: "",
        },
        Flag {
            name: "token",
            default: None,
            help: "",
        },
    ];

    fn parse(argv: &[&str]) -> Result<Args> {
        Args::parse_from("t", "", FLAGS, argv.iter().map(|s| s.to_string()))
    }

    #[test]
    fn args_defaults_overrides_and_required() {
        let a = parse(&["--token", "x"]).unwrap();
        assert_eq!(a.get("out").unwrap(), "out");
        assert_eq!(a.get("token").unwrap(), "x");
        assert!(parse(&[]).unwrap().get("token").is_err());
    }

    #[test]
    fn args_reject_typos_and_missing_values() {
        assert!(parse(&["--tokn", "x"]).is_err());
        assert!(parse(&["--token"]).is_err());
        assert!(parse(&["token"]).is_err());
    }
}
