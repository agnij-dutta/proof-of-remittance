//! Prover: runs MPC-TLS with the notary against the (mock) bank, then
//! selectively discloses one credit object:
//!   revealed : request (minus Authorization value), response head,
//!              the credit's keys + `currency` + `narration`
//!   committed: the credit's `amount` and `ts` (SHA-256 hash commitments)
//!   hidden   : everything else (account, holder, balance, UTR ref,
//!              other credits, the session token)
//!
//! Writes `attestation.json` (public, signed by the notary) and
//! `secrets.json` (private: plaintext + blinders needed for the ZK proof),
//! plus `tlsn-metrics.json` with timings.

use std::{future::IntoFuture, net::SocketAddr, ops::Range, time::Instant};

use anyhow::{Result, anyhow};
use futures::io::AsyncReadExt as _;
use http_body_util::Empty;
use hyper::{Request, StatusCode, body::Bytes, header};
use hyper_util::rt::TokioIo;
use k256::sha2::{Digest, Sha256};
use por_tlsn::*;
use serde_json::json;
use spansy::{
    Span,
    http::{BodyContent, Requests, Responses},
    json::JsonValue,
};
use tlsn::{
    Session,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig,
    },
    connection::ServerName,
    hash::HashAlgId,
    rangeset::iter::{IntoRangeIterator, RangeIterator},
    transcript::{
        Direction, TranscriptCommitConfig, TranscriptCommitment, TranscriptCommitmentKind,
        TranscriptSecret,
    },
    webpki::{CertificateDer, RootCertStore},
};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

fn span_range<T: Span<str>>(v: &T) -> Result<Range<usize>> {
    if !v.is_contiguous() {
        return Err(anyhow!("JSON value is not a contiguous byte range"));
    }
    Ok(v.offset()..v.offset() + Span::len(v))
}

const FLAGS: &[Flag] = &[
    Flag {
        name: "notary",
        default: Some("127.0.0.1:7047"),
        help: "notary address",
    },
    Flag {
        name: "bank",
        default: Some("127.0.0.1:8443"),
        help: "bank HTTPS address (TLS name is always the configured SERVER_DOMAIN)",
    },
    Flag {
        name: "ca",
        default: Some("certs/root_ca.der"),
        help: "DER root CA the prover trusts for the bank",
    },
    Flag {
        name: "token",
        default: None,
        help: "bank session token, sent as a Bearer header and never revealed",
    },
    Flag {
        name: "narration",
        default: None,
        help: "narration of the credit to prove, e.g. POR-D030ED06A56D6726B772",
    },
    Flag {
        name: "out",
        default: Some("out"),
        help: "directory for attestation.json, secrets.json, tlsn-metrics.json",
    },
    Flag {
        name: "timeout",
        default: Some("60"),
        help: "seconds before the whole session is abandoned",
    },
];

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse(
        "prove",
        "Notarize one bank credit with TLSNotary and write the attestation + secrets.",
        FLAGS,
    )?;
    // If the notary aborts mid-session (e.g. it rejects the server
    // certificate) the TLS client can otherwise wait forever.
    let secs: u64 = args
        .get("timeout")?
        .parse()
        .map_err(|e| anyhow!("--timeout: {e}"))?;
    tokio::time::timeout(std::time::Duration::from_secs(secs), run(&args))
        .await
        .map_err(|_| anyhow!("session timed out after {secs}s (notary rejected or unreachable)"))?
}

async fn run(args: &Args) -> Result<()> {
    let notary_addr: SocketAddr = args
        .get("notary")?
        .parse()
        .map_err(|e| anyhow!("--notary: {e}"))?;
    let bank_addr: SocketAddr = args
        .get("bank")?
        .parse()
        .map_err(|e| anyhow!("--bank: {e}"))?;
    let ca_path = args.get("ca")?;
    let token = args.get("token")?;
    let narration = args.get("narration")?;
    let out_dir = args.get("out")?;
    std::fs::create_dir_all(&out_dir)?;

    let t_start = Instant::now();

    let notary_socket = tokio::net::TcpStream::connect(notary_addr)
        .await
        .map_err(|e| anyhow!("connecting to notary at {notary_addr}: {e}"))?;
    let session = Session::new(notary_socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    // MPC preprocessing with the notary (independent of the bank).
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            MpcTlsConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?,
        )
        .await?;
    let t_setup = t_start.elapsed();

    let bank_socket = tokio::net::TcpStream::connect(bank_addr)
        .await
        .map_err(|e| anyhow!("connecting to bank at {bank_addr}: {e}"))?;
    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(SERVER_DOMAIN.try_into()?))
            .root_store(RootCertStore {
                roots: vec![CertificateDer(load_ca(&ca_path)?)],
            })
            .build()?,
        bank_socket.compat(),
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());
    let prover_task = tokio::spawn(prover.into_future());

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    let request = Request::builder()
        .uri(ENDPOINT_PATH)
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .method("GET")
        .body(Empty::<Bytes>::new())?;
    let response = request_sender.send_request(request).await?;
    if response.status() != StatusCode::OK {
        return Err(anyhow!("bank returned {}", response.status()));
    }

    let mut prover = prover_task.await??;
    let t_tls = t_start.elapsed();

    let transcript = prover.transcript().clone();
    let sent = transcript.sent().to_vec();
    let received = transcript.received().to_vec();
    tracing::info!(
        "transcript: sent {} B, received {} B",
        sent.len(),
        received.len()
    );

    let mut cfg = ProveConfig::builder(&transcript);
    cfg.server_identity();

    // --- Request: reveal all but the bearer token value.
    let reqs = Requests::new_from_slice(&sent).collect::<Result<Vec<_>, _>>()?;
    let req = reqs.first().ok_or_else(|| anyhow!("no request"))?;
    let auth = req
        .headers_with_name(header::AUTHORIZATION.as_str())
        .next()
        .ok_or_else(|| anyhow!("no authorization header"))?;
    cfg.reveal_sent(req.into_range_iter().difference(&auth.value))?;

    // --- Response: find our credit by narration.
    let resps = Responses::new_from_slice(&received).collect::<Result<Vec<_>, _>>()?;
    let resp = resps.first().ok_or_else(|| anyhow!("no response"))?;
    let body = resp.body.as_ref().ok_or_else(|| anyhow!("no body"))?;
    let BodyContent::Json(doc) = &body.content else {
        return Err(anyhow!("body is not JSON"));
    };
    let Some(JsonValue::Array(credits)) = doc.get("credits") else {
        return Err(anyhow!("no credits array"));
    };

    let mut found = None;
    for (i, c) in credits.elems.iter().enumerate() {
        if let Some(n) = c.get("narration")
            && received[span_range(n)?] == *narration.as_bytes()
        {
            if found.is_some() {
                return Err(anyhow!("more than one credit has narration {narration}"));
            }
            found = Some(i);
        }
    }
    let idx = found.ok_or_else(|| anyhow!("no credit with narration {narration}"))?;
    let credit = &credits.elems[idx];
    let get = |k: &str| {
        credit
            .get(k)
            .ok_or_else(|| anyhow!("credit missing {k}"))
            .and_then(span_range)
    };
    let obj = span_range(credit)?;
    let amount = get("amount")?;
    let ts = get("ts")?;
    let reference = get("ref")?;
    tracing::info!("credit #{idx} at {:?}", obj);

    if ts.len() != TS_LEN {
        return Err(anyhow!("ts must be {TS_LEN} digits"));
    }

    // Response status line + headers (everything before the body).
    let body_start = <_ as Span<[u8]>>::offset(body);
    cfg.reveal_recv(0..body_start)?;
    // The credit object minus the three secret values.
    cfg.reveal_recv(
        obj.clone()
            .into_range_iter()
            .difference(&amount)
            .difference(&reference)
            .difference(&ts),
    )?;

    let mut commit = TranscriptCommitConfig::builder(&transcript);
    commit.default_kind(TranscriptCommitmentKind::Hash {
        alg: HashAlgId::SHA256,
    });
    commit.commit_recv(&amount)?;
    commit.commit_recv(&ts)?;
    cfg.transcript_commit(commit.build()?);

    let out = prover.prove(&cfg.build()?).await?;
    prover.close().await?;
    handle.close();
    let mut socket = driver_task.await??;
    let t_prove = t_start.elapsed();

    // Receive the notary's signed attestation.
    let mut buf = Vec::new();
    socket.read_to_end(&mut buf).await?;
    if buf.is_empty() {
        return Err(anyhow!("notary returned no attestation (rejected?)"));
    }
    let att: Attestation = serde_json::from_slice(&buf)?;

    // Pull our blinders and double check them against the commitments.
    let mut secrets = json!({});
    for (c, s) in out
        .transcript_commitments
        .iter()
        .zip(out.transcript_secrets.iter())
    {
        let (TranscriptCommitment::Hash(c), TranscriptSecret::Hash(s)) = (c, s) else {
            continue;
        };
        if c.direction != Direction::Received {
            return Err(anyhow!("unexpected commitment on sent data"));
        }
        let (Some(start), Some(end)) = (c.idx.min(), c.idx.end()) else {
            return Err(anyhow!("empty commitment"));
        };
        let r = start..end;
        let plain = &received[r.clone()];
        let mut h = Sha256::new();
        h.update(plain);
        h.update(s.blinder.as_bytes());
        if h.finalize().as_slice() != c.hash.value.as_bytes() {
            return Err(anyhow!("local commitment check failed"));
        }
        let name = if r == amount {
            "amount"
        } else if r == ts {
            "ts"
        } else {
            return Err(anyhow!("commitment at {r:?} is neither amount nor ts"));
        };
        secrets[name] = json!({
            "plaintext": String::from_utf8_lossy(plain),
            "blinder": format!("0x{}", hex::encode(s.blinder.as_bytes())),
            "commitment": format!("0x{}", hex::encode(c.hash.value.as_bytes())),
        });
    }
    if secrets["amount"]["commitment"] != json!(att.amount_commitment)
        || secrets["ts"]["commitment"] != json!(att.ts_commitment)
    {
        return Err(anyhow!("notary attested different commitments than ours"));
    }

    let metrics = json!({
        "mpc_setup_ms": t_setup.as_millis(),
        "tls_request_ms": (t_tls - t_setup).as_millis(),
        "selective_disclosure_ms": (t_prove - t_tls).as_millis(),
        "total_ms": t_prove.as_millis(),
        "sent_bytes": sent.len(),
        "recv_bytes": received.len(),
        "max_sent_data": MAX_SENT_DATA,
        "max_recv_data": MAX_RECV_DATA,
    });

    std::fs::write(
        format!("{out_dir}/attestation.json"),
        serde_json::to_vec_pretty(&att)?,
    )?;
    std::fs::write(
        format!("{out_dir}/secrets.json"),
        serde_json::to_vec_pretty(&secrets)?,
    )?;
    std::fs::write(
        format!("{out_dir}/tlsn-metrics.json"),
        serde_json::to_vec_pretty(&metrics)?,
    )?;
    println!("{}", serde_json::to_string(&metrics)?);
    Ok(())
}
