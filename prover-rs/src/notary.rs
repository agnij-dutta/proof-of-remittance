//! Notary: a TLSNotary verifier that co-runs MPC-TLS with a prover, checks
//! the bank's certificate chain against a configured root, validates that the
//! disclosed transcript matches the expected "one credit object" template,
//! and signs an EVM-verifiable attestation.
//!
//! Template enforced on the received bytes (`*` = hidden, A = amount
//! commitment, T = ts commitment), see `por_tlsn::template` for the full rules:
//!
//!   HTTP/1.1 200 OK ...headers incl. Content-Length... (all revealed)
//!   ...{"amount":"AAAAAAAA","currency":"INR","narration":"POR-1A2B...","ref":"****","ts":TTTTTTTTTT}...
//!
//! It refuses (sends nothing and drops the connection) if any check fails.
//!
//! Usage: `NOTARY_KEY=0x... notary [--listen 127.0.0.1:7047] [--ca certs/root_ca.der]`

use std::{
    net::SocketAddr,
    ops::Range,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow, bail};
use futures::io::AsyncWriteExt as _;
use por_tlsn::{
    template::{Commitment, Template, check_request, check_response},
    *,
};
use tlsn::{
    Session,
    config::verifier::VerifierConfig,
    connection::ServerName,
    hash::HashAlgId,
    transcript::{Direction, PartialTranscript, TranscriptCommitment, hash::PlaintextHash},
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::{CertificateDer, RootCertStore},
};
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse(
        "notary",
        "TLSNotary verifier that signs EVM attestations for one bank credit. Needs NOTARY_KEY.",
        &[
            Flag {
                name: "listen",
                default: Some("127.0.0.1:7047"),
                help: "address to accept prover connections on",
            },
            Flag {
                name: "ca",
                default: Some("certs/root_ca.der"),
                help: "DER root CA the bank certificate must chain to",
            },
        ],
    )?;
    let listen: SocketAddr = args
        .get("listen")?
        .parse()
        .map_err(|e| anyhow!("--listen: {e}"))?;
    let ca_path = args.get("ca")?;
    let key = load_signing_key()?;
    let ca = load_ca(&ca_path)?;

    let listener = TcpListener::bind(listen).await?;
    println!(
        "[notary] listening on {listen}, signer {}",
        eth_address(key.verifying_key())
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let key = key.clone();
        let ca = ca.clone();
        tokio::spawn(async move {
            match handle(socket, ca, key).await {
                Ok(a) => println!(
                    "[notary] {peer}: attested narration={} currency={} (amount and ts hidden)",
                    a.narration, a.currency
                ),
                Err(e) => println!("[notary] {peer}: REJECTED: {e:#}"),
            }
        });
    }
}

async fn handle(
    socket: tokio::net::TcpStream,
    ca: Vec<u8>,
    key: k256::ecdsa::SigningKey,
) -> Result<Attestation> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier = handle.new_verifier(
        VerifierConfig::builder()
            .root_store(RootCertStore {
                roots: vec![CertificateDer(ca)],
            })
            .build()?,
    )?;

    let verifier = match verifier.commit().await? {
        VerifierCommitStart::Mpc(v) => {
            let cfg = v.config();
            if cfg.max_sent_data() > MAX_SENT_DATA || cfg.max_recv_data() > MAX_RECV_DATA {
                v.reject(Some("transcript limits too large")).await?;
                bail!("limits too large");
            }
            v.accept().await?.run().await?
        }
        VerifierCommitStart::Proxy(v) => {
            v.reject(Some("MPC-TLS required")).await?;
            bail!("proxy mode not accepted");
        }
    };

    let verifier = verifier.verify().await?;
    if !verifier.request().server_identity() || verifier.request().reveal().is_none() {
        let v = verifier
            .reject(Some("server identity + reveal required"))
            .await?;
        v.close().await?;
        bail!("prover did not reveal server identity");
    }
    let (
        VerifierOutput {
            server_name,
            transcript,
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.accept().await?;
    verifier.close().await?;
    handle.close();
    let mut socket = driver_task.await??;

    // ---- Application checks. A failure here means: no signature.
    let ServerName::Dns(name) = server_name.ok_or_else(|| anyhow!("no server name"))?;
    if name.as_str() != SERVER_DOMAIN {
        bail!("unexpected server {}", name.as_str());
    }
    let t = transcript.ok_or_else(|| anyhow!("no transcript"))?;
    let att = check_template(&t, &transcript_commitments)?;

    let mut att = att;
    att.server_name = name.as_str().to_string();
    att.session_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    sign(&key, &mut att)?;

    socket.write_all(&serde_json::to_vec(&att)?).await?;
    socket.close().await?;
    Ok(att)
}

/// Revealed-byte view: Some(b) for authenticated bytes, None for hidden ones.
fn view(t: &PartialTranscript, dir: Direction) -> Vec<Option<u8>> {
    let (data, authed) = match dir {
        Direction::Sent => (t.sent_unsafe(), t.sent_authed()),
        Direction::Received => (t.received_unsafe(), t.received_authed()),
    };
    data.iter()
        .enumerate()
        .map(|(i, b)| authed.contains(&i).then_some(*b))
        .collect()
}

/// A single contiguous range, or an error. The template reasons about one
/// field per commitment, so a commitment over scattered bytes is refused.
fn single_range(c: &PlaintextHash) -> Result<Range<usize>> {
    let start = c.idx.min().ok_or_else(|| anyhow!("empty commitment"))?;
    let end = c.idx.end().ok_or_else(|| anyhow!("empty commitment"))?;
    if c.idx.len() != end - start {
        bail!("commitment is not contiguous");
    }
    Ok(start..end)
}

/// Runs the request and response template checks (see `por_tlsn::template`)
/// and builds the unsigned attestation.
fn check_template(t: &PartialTranscript, commits: &[TranscriptCommitment]) -> Result<Attestation> {
    let tpl = Template {
        host: SERVER_DOMAIN,
        path: ENDPOINT_PATH,
        ts_len: TS_LEN,
        max_amount_len: MAX_AMOUNT_LEN,
        max_ref_len: MAX_REF_LEN,
    };
    check_request(&view(t, Direction::Sent), &tpl)?;

    // Every commitment must be a received-side SHA-256 hash; anything else is
    // a session shape the template does not know.
    let mut hashes = Vec::new();
    for x in commits {
        match x {
            TranscriptCommitment::Hash(h)
                if h.direction == Direction::Received && h.hash.alg == HashAlgId::SHA256 =>
            {
                let hash: [u8; 32] = h
                    .hash
                    .value
                    .as_bytes()
                    .try_into()
                    .map_err(|_| anyhow!("SHA-256 commitment is not 32 bytes"))?;
                hashes.push(Commitment {
                    range: single_range(h)?,
                    hash,
                });
            }
            _ => bail!("unexpected commitment kind (only received SHA-256 hashes allowed)"),
        }
    }
    let d = check_response(&view(t, Direction::Received), &hashes, &tpl)?;

    Ok(Attestation {
        version: ATTESTATION_VERSION.into(),
        server_name: String::new(),
        endpoint: ENDPOINT.into(),
        currency: d.currency,
        narration: d.narration,
        amount_commitment: format!("0x{}", hex::encode(d.amount_commitment)),
        ts_commitment: format!("0x{}", hex::encode(d.ts_commitment)),
        amount_len: d.amount_len,
        session_time: 0,
        redacted_view: d.redacted_body,
        digest: String::new(),
        signature: String::new(),
        notary: String::new(),
    })
}
