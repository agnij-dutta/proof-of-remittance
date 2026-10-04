//! The notary's application checks over a TLSNotary partial transcript.
//!
//! TLSNotary authenticates bytes; it does not know what they mean. Before the
//! notary signs "these two commitments are the `amount` and `ts` of a credit
//! with narration N", it has to convince itself of that from the bytes the
//! prover chose to reveal. Everything here works on a *view*: one entry per
//! transcript byte, `Some(b)` if the prover revealed it, `None` if hidden.
//!
//! The checks are written to fail closed. Anything the template does not
//! explicitly allow (an extra hidden byte in the request, a second HTTP
//! response, a chunked body, a commitment outside the body) is a rejection.
//!
//! Kept free of TLSNotary types so it can be unit tested with synthetic
//! transcripts, including the malicious ones a real prover could produce.

use std::ops::Range;

use anyhow::{Result, anyhow, bail};

/// What the notary expects the session to look like. One per bank endpoint.
#[derive(Debug, Clone)]
pub struct Template<'a> {
    /// Exact `Host` header value (must equal the TLS server name).
    pub host: &'a str,
    /// Exact request path, e.g. `/api/v1/accounts/me/credits`.
    pub path: &'a str,
    /// Byte width of the committed `ts` field.
    pub ts_len: usize,
    /// Longest committed `amount` string the circuit accepts.
    pub max_amount_len: usize,
    /// Longest hidden `ref` value. Keeps a hidden run from spanning two
    /// credit objects (see `check_response`).
    pub max_ref_len: usize,
}

/// One SHA-256 plaintext commitment over a contiguous range of the received
/// transcript.
#[derive(Debug, Clone)]
pub struct Commitment {
    pub range: Range<usize>,
    pub hash: [u8; 32],
}

/// The facts the notary will sign, extracted from a transcript that passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure {
    pub currency: String,
    pub narration: String,
    pub amount_commitment: [u8; 32],
    pub ts_commitment: [u8; 32],
    pub amount_len: usize,
    /// Response body as the notary saw it, hidden bytes as `*`.
    pub redacted_body: String,
}

/// Header whose value the prover is allowed to hide (the session token).
const SECRET_HEADER: &str = "authorization";

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

struct Cursor<'a> {
    v: &'a [Option<u8>],
    pos: usize,
}

impl Cursor<'_> {
    fn expect(&mut self, lit: &str) -> Result<()> {
        for (k, want) in lit.bytes().enumerate() {
            match self.v.get(self.pos + k) {
                Some(Some(b)) if *b == want => {}
                _ => bail!(
                    "template mismatch at byte {}: expected {lit:?}",
                    self.pos + k
                ),
            }
        }
        self.pos += lit.len();
        Ok(())
    }

    fn peek_is(&self, lit: &str) -> bool {
        lit.bytes()
            .enumerate()
            .all(|(k, want)| self.v.get(self.pos + k) == Some(&Some(want)))
    }

    /// Revealed bytes up to the next `"`, restricted to `[A-Za-z0-9_-]`.
    /// The restriction matters: a narration containing `"` or `\` could
    /// otherwise smuggle JSON structure past the template.
    fn revealed_token(&mut self) -> Result<String> {
        let mut s = String::new();
        loop {
            match self.v.get(self.pos) {
                Some(Some(b'"')) => return Ok(s),
                Some(Some(b)) if b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_' => {
                    s.push(*b as char);
                    self.pos += 1;
                }
                _ => bail!("expected revealed token at byte {}", self.pos),
            }
        }
    }

    /// Revealed bytes up to (not including) the next `\r\n`. Rejects hidden
    /// bytes and bare CR/LF.
    fn revealed_line(&mut self) -> Result<String> {
        let mut s = String::new();
        loop {
            if self.peek_is("\r\n") {
                return Ok(s);
            }
            match self.v.get(self.pos) {
                Some(Some(b)) if *b != b'\r' && *b != b'\n' => {
                    s.push(*b as char);
                    self.pos += 1;
                }
                Some(Some(_)) => bail!("bare CR or LF at byte {}", self.pos),
                Some(None) => bail!(
                    "hidden byte at {} where a revealed line is required",
                    self.pos
                ),
                None => bail!("transcript ended inside a header line"),
            }
        }
    }

    fn hidden_run(&mut self) -> Result<usize> {
        let start = self.pos;
        while matches!(self.v.get(self.pos), Some(None)) {
            self.pos += 1;
        }
        if self.pos == start {
            bail!("expected hidden bytes at {start}");
        }
        Ok(self.pos - start)
    }

    fn exact_hidden_range(&mut self, r: &Range<usize>) -> Result<()> {
        if self.pos != r.start {
            bail!(
                "commitment at {r:?} is not where the template expects it ({})",
                self.pos
            );
        }
        if r.end > self.v.len() || self.v[r.clone()].iter().any(Option::is_some) {
            bail!("committed range {r:?} must be fully hidden");
        }
        self.pos = r.end;
        Ok(())
    }

    /// Header name: revealed token characters up to `:`.
    fn header_name(&mut self) -> Result<String> {
        let start = self.pos;
        let mut s = String::new();
        loop {
            match self.v.get(self.pos) {
                Some(Some(b':')) if self.pos > start => {
                    self.pos += 1;
                    return Ok(s.to_ascii_lowercase());
                }
                Some(Some(b)) if is_token_char(*b) => {
                    s.push(*b as char);
                    self.pos += 1;
                }
                _ => bail!("malformed or hidden header name at byte {}", self.pos),
            }
        }
    }

    fn skip_ows(&mut self) {
        while matches!(self.v.get(self.pos), Some(Some(b' ' | b'\t'))) {
            self.pos += 1;
        }
    }
}

/// Checks the request side. The prover must reveal one complete GET request
/// for exactly `template.path` with `Host: template.host`, and may hide only
/// the value of the `Authorization` header.
///
/// Why this strict: without it a prover can hide a second, pipelined request
/// (say to a debits endpoint whose objects have the same JSON shape) and
/// point the commitments at its response. The response-side framing check in
/// [`check_response`] closes that too; this is the belt to its braces.
pub fn check_request(sent: &[Option<u8>], template: &Template) -> Result<()> {
    let mut c = Cursor { v: sent, pos: 0 };
    c.expect(&format!("GET {} HTTP/1.1\r\n", template.path))?;

    let mut host_seen = 0usize;
    let mut secret_seen = 0usize;
    loop {
        if c.peek_is("\r\n") {
            c.pos += 2;
            break;
        }
        let name = c.header_name()?;
        c.skip_ows();
        if name == SECRET_HEADER && matches!(c.v.get(c.pos), Some(None)) {
            secret_seen += 1;
            c.hidden_run()?;
        } else {
            let value = c.revealed_line()?;
            if name == SECRET_HEADER {
                secret_seen += 1;
            }
            if name == "host" {
                host_seen += 1;
                if value.trim_end() != template.host {
                    bail!("Host header is {value:?}, expected {:?}", template.host);
                }
            }
            if name == "content-length" || name == "transfer-encoding" {
                bail!("request must not carry a body ({name} header present)");
            }
        }
        c.expect("\r\n")?;
    }
    if host_seen != 1 {
        bail!("expected exactly one revealed Host header, found {host_seen}");
    }
    if secret_seen > 1 {
        bail!("more than one Authorization header");
    }
    if c.pos != sent.len() {
        bail!(
            "{} bytes after the end of the request headers (pipelined request or body?)",
            sent.len() - c.pos
        );
    }
    Ok(())
}

/// Checks the response side and extracts the facts to sign.
///
/// 1. Exactly one `HTTP/1.1 200 OK` response whose status line and headers
///    are fully revealed, framed by a single `Content-Length` (no chunked
///    encoding, no compression) that ends exactly at the end of the
///    transcript. So the credit object is in the body of *the* response to
///    the request checked by [`check_request`].
/// 2. Exactly two SHA-256 commitments, both inside the body.
/// 3. Around them, the revealed bytes spell one credit object:
///    `{"amount":"<A>","currency":"<C>","narration":"<N>","ref":"<hidden>","ts":<T>}`
///    with `<A>` and `<T>` hidden and committed, `<A>` at most
///    `max_amount_len` bytes, `<T>` exactly `ts_len` bytes, and the hidden
///    `ref` at most `max_ref_len` bytes.
///
/// What this cannot check: the JSON outside the object is hidden, so the
/// notary does not know *which array* the object sits in. For the mock bank
/// every object of this shape is a credit. For a real bank that must be
/// re-established per endpoint (see SECURITY.md).
pub fn check_response(
    recv: &[Option<u8>],
    commits: &[Commitment],
    template: &Template,
) -> Result<Disclosure> {
    let mut c = Cursor { v: recv, pos: 0 };
    c.expect("HTTP/1.1 200 OK\r\n")?;

    let mut content_length: Option<usize> = None;
    loop {
        if c.peek_is("\r\n") {
            c.pos += 2;
            break;
        }
        let name = c.header_name()?;
        c.skip_ows();
        let value = c.revealed_line()?;
        let value = value.trim_end();
        match name.as_str() {
            "content-length" => {
                if content_length.is_some() {
                    bail!("duplicate Content-Length");
                }
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    bail!("bad Content-Length {value:?}");
                }
                content_length = Some(value.parse().map_err(|e| anyhow!("Content-Length: {e}"))?);
            }
            "transfer-encoding" => bail!("chunked/transfer-encoded responses are not supported"),
            "content-encoding" if !value.eq_ignore_ascii_case("identity") => {
                bail!("compressed responses are not supported ({value})")
            }
            _ => {}
        }
        c.expect("\r\n")?;
    }
    let body_start = c.pos;
    let content_length = content_length.ok_or_else(|| anyhow!("response has no Content-Length"))?;
    if body_start.checked_add(content_length) != Some(recv.len()) {
        bail!(
            "body framing mismatch: headers end at {body_start}, Content-Length {content_length}, transcript {} bytes",
            recv.len()
        );
    }

    if commits.len() != 2 {
        bail!(
            "expected exactly two received commitments, got {}",
            commits.len()
        );
    }
    let mut sorted: Vec<&Commitment> = commits.iter().collect();
    sorted.sort_by_key(|x| x.range.start);
    let (amount, ts) = (sorted[0], sorted[1]);
    for x in [amount, ts] {
        if x.range.start < body_start || x.range.end > recv.len() || x.range.is_empty() {
            bail!("commitment {:?} is not inside the response body", x.range);
        }
    }
    if amount.range.len() > template.max_amount_len {
        bail!(
            "amount commitment is {} bytes, circuit max is {}",
            amount.range.len(),
            template.max_amount_len
        );
    }
    if ts.range.len() != template.ts_len {
        bail!("ts commitment must be {} bytes", template.ts_len);
    }

    let prefix = "{\"amount\":\"";
    let start = amount
        .range
        .start
        .checked_sub(prefix.len())
        .filter(|s| *s >= body_start)
        .ok_or_else(|| anyhow!("amount commitment too close to the start of the body"))?;
    let mut c = Cursor {
        v: recv,
        pos: start,
    };
    c.expect(prefix)?;
    c.exact_hidden_range(&amount.range)?;
    c.expect("\",\"currency\":\"")?;
    let currency = c.revealed_token()?;
    c.expect("\",\"narration\":\"")?;
    let narration = c.revealed_token()?;
    c.expect("\",\"ref\":\"")?;
    // A credit object is far longer than max_ref_len, so this hidden run
    // cannot swallow an object boundary and splice one credit's amount onto
    // another credit's timestamp.
    let ref_len = c.hidden_run()?;
    if ref_len > template.max_ref_len {
        bail!(
            "hidden ref is {ref_len} bytes, max {}",
            template.max_ref_len
        );
    }
    c.expect("\",\"ts\":")?;
    c.exact_hidden_range(&ts.range)?;
    c.expect("}")?;

    let redacted_body = recv[body_start..]
        .iter()
        .map(|b| b.map(|x| x as char).unwrap_or('*'))
        .collect();

    Ok(Disclosure {
        currency,
        narration,
        amount_commitment: amount.hash,
        ts_commitment: ts.hash,
        amount_len: amount.range.len(),
        redacted_body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Template = Template {
        host: "netbanking.mockbank.test",
        path: "/api/v1/accounts/me/credits",
        ts_len: 10,
        max_amount_len: 16,
        max_ref_len: 32,
    };

    /// Builds a view from a string where every byte inside `[` `]` is hidden.
    /// Brackets themselves are dropped. Example: `"Bearer [secret]"`.
    fn view(marked: &str) -> Vec<Option<u8>> {
        let mut out = Vec::new();
        let mut hidden = false;
        for b in marked.bytes() {
            match b {
                b'[' => hidden = true,
                b']' => hidden = false,
                _ => out.push(if hidden { None } else { Some(b) }),
            }
        }
        out
    }

    /// Hidden ranges of a marked string, in order.
    fn hidden_ranges(marked: &str) -> Vec<Range<usize>> {
        let v = view(marked);
        let mut out = Vec::new();
        let mut i = 0;
        while i < v.len() {
            if v[i].is_none() {
                let s = i;
                while i < v.len() && v[i].is_none() {
                    i += 1;
                }
                out.push(s..i);
            } else {
                i += 1;
            }
        }
        out
    }

    const REQ: &str = "GET /api/v1/accounts/me/credits HTTP/1.1\r\nhost: netbanking.mockbank.test\r\nconnection: close\r\nauthorization: [Bearer tok123]\r\n\r\n";

    fn response(body: &str) -> String {
        let plain_len = view(body).len();
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {plain_len}\r\n\r\n{body}"
        )
    }

    const CREDIT: &str = r#"{"amount":"[50000.00]","currency":"INR","narration":"POR-ABC","ref":"[UTR123]","ts":[1791096008]}"#;

    fn commits_for(marked: &str, which: &[usize]) -> Vec<Commitment> {
        let ranges = hidden_ranges(marked);
        which
            .iter()
            .map(|&i| Commitment {
                range: ranges[i].clone(),
                hash: [i as u8; 32],
            })
            .collect()
    }

    /// In `honest()`, hidden runs are:
    /// 0 = JSON before the object, 1 = amount, 2 = ref, 3 = ts.
    fn honest() -> String {
        response(&format!(
            "[{{\"account\":{{...}},\"credits\":[]{CREDIT}[]}}]"
        ))
    }

    /// Error text of a rejection, so tests pin the *reason*, not just failure.
    fn why<T: std::fmt::Debug>(r: Result<T>) -> String {
        format!("{:#}", r.expect_err("expected a rejection"))
    }

    #[test]
    fn honest_request_passes() {
        check_request(&view(REQ), &T).unwrap();
    }

    #[test]
    fn request_with_hidden_second_request_is_rejected() {
        let smuggled = format!("{REQ}[GET /api/v1/accounts/me/debits HTTP/1.1\r\n\r\n]");
        assert!(why(check_request(&view(&smuggled), &T)).contains("after the end of the request"));
    }

    #[test]
    fn request_with_revealed_second_request_is_rejected() {
        let two = format!("{REQ}GET /api/v1/accounts/me/debits HTTP/1.1\r\nhost: x\r\n\r\n");
        assert!(check_request(&view(&two), &T).is_err());
    }

    #[test]
    fn request_hiding_another_header_is_rejected() {
        let r = REQ.replace("connection: close", "x-account: [12345]");
        assert!(why(check_request(&view(&r), &T)).contains("hidden byte"));
    }

    #[test]
    fn request_wrong_path_or_host_is_rejected() {
        assert!(check_request(&view(&REQ.replace("credits", "debits")), &T).is_err());
        assert!(check_request(&view(&REQ.replace("mockbank.test", "evil.test")), &T).is_err());
        let no_host = REQ.replace("host: netbanking.mockbank.test\r\n", "");
        assert!(check_request(&view(&no_host), &T).is_err());
        let two_hosts = REQ.replace("connection: close", "host: netbanking.mockbank.test");
        assert!(check_request(&view(&two_hosts), &T).is_err());
    }

    #[test]
    fn request_with_body_is_rejected() {
        let r = REQ.replace("connection: close", "content-length: 0");
        assert!(check_request(&view(&r), &T).is_err());
    }

    #[test]
    fn honest_response_passes() {
        let r = honest();
        let d = check_response(&view(&r), &commits_for(&r, &[1, 3]), &T).unwrap();
        assert_eq!(d.currency, "INR");
        assert_eq!(d.narration, "POR-ABC");
        assert_eq!(d.amount_len, 8);
        assert_eq!(d.amount_commitment, [1; 32]);
        assert_eq!(d.ts_commitment, [3; 32]);
        assert!(d.redacted_body.contains(r#""narration":"POR-ABC""#));
        assert!(!d.redacted_body.contains("50000"));
    }

    #[test]
    fn commitment_order_in_input_does_not_matter() {
        let r = honest();
        assert!(check_response(&view(&r), &commits_for(&r, &[3, 1]), &T).is_ok());
    }

    #[test]
    fn second_response_in_transcript_is_rejected() {
        // Content-Length frames the first response; anything after it (a
        // pipelined response to a hidden request) must fail framing.
        let first = response("[{}]");
        let second = response(&format!("[{{\"debits\":[]{CREDIT}[]}}]"));
        let both = format!("{first}{second}");
        let ranges = hidden_ranges(&both);
        let commits = vec![
            Commitment {
                range: ranges[2].clone(),
                hash: [1; 32],
            },
            Commitment {
                range: ranges[4].clone(),
                hash: [3; 32],
            },
        ];
        assert!(why(check_response(&view(&both), &commits, &T)).contains("framing mismatch"));
    }

    #[test]
    fn hidden_response_header_is_rejected() {
        let r = honest().replace("application/json", "[application/json]");
        // Header hidden: runs shift by one (0 = header, 2 = amount, 4 = ts).
        assert!(check_response(&view(&r), &commits_for(&r, &[2, 4]), &T).is_err());
    }

    #[test]
    fn chunked_or_compressed_response_is_rejected() {
        let r = honest().replace(
            "content-type: application/json",
            "transfer-encoding: chunked",
        );
        assert!(check_response(&view(&r), &commits_for(&r, &[1, 3]), &T).is_err());
        let r = honest().replace("content-type: application/json", "content-encoding: gzip");
        assert!(check_response(&view(&r), &commits_for(&r, &[1, 3]), &T).is_err());
    }

    #[test]
    fn non_200_is_rejected() {
        let r = honest().replace("200 OK", "404 Not Found");
        assert!(check_response(&view(&r), &commits_for(&r, &[1, 3]), &T).is_err());
    }

    #[test]
    fn wrong_number_of_commitments_is_rejected() {
        let r = honest();
        assert!(check_response(&view(&r), &commits_for(&r, &[1]), &T).is_err());
        assert!(check_response(&view(&r), &commits_for(&r, &[1, 2, 3]), &T).is_err());
    }

    #[test]
    fn commitment_on_ref_instead_of_amount_is_rejected() {
        let r = honest();
        assert!(check_response(&view(&r), &commits_for(&r, &[2, 3]), &T).is_err());
    }

    #[test]
    fn partially_revealed_amount_is_rejected() {
        let r = honest();
        let ranges = hidden_ranges(&r);
        // Commit to a range one byte longer than the hidden amount, so it
        // covers the revealed closing quote.
        let a = ranges[1].clone();
        let commits = vec![
            Commitment {
                range: a.start..a.end + 1,
                hash: [1; 32],
            },
            Commitment {
                range: ranges[3].clone(),
                hash: [3; 32],
            },
        ];
        assert!(why(check_response(&view(&r), &commits, &T)).contains("fully hidden"));
    }

    #[test]
    fn overlong_amount_or_ts_is_rejected() {
        let r = response(&CREDIT.replace("50000.00", "1234567890123456.00"));
        assert!(check_response(&view(&r), &commits_for(&r, &[0, 2]), &T).is_err());
        let r = response(&CREDIT.replace("1791096008", "17910960080"));
        assert!(check_response(&view(&r), &commits_for(&r, &[0, 2]), &T).is_err());
    }

    #[test]
    fn long_hidden_ref_cannot_splice_two_credits() {
        // Amount of credit A, ts of credit B: the hidden run between them
        // swallows the end of A and the start of B and is far over 32 bytes.
        let spliced = r#"{"amount":"[99999.99]","currency":"INR","narration":"POR-ABC","ref":"[UTR1","ts":1700000000},{"amount":"1.00","currency":"INR","narration":"X","ref":"UTR2]","ts":[1791096008]}"#;
        let r = response(spliced);
        assert!(
            why(check_response(&view(&r), &commits_for(&r, &[0, 2]), &T)).contains("hidden ref")
        );
    }

    #[test]
    fn narration_with_json_metacharacters_is_rejected() {
        let r = response(&CREDIT.replace("POR-ABC", r#"POR\"x"#));
        assert!(check_response(&view(&r), &commits_for(&r, &[0, 2]), &T).is_err());
    }

    #[test]
    fn commitment_in_headers_is_rejected() {
        // Commitment range inside the (hidden) header block.
        let r = honest().replace("application/json", "[application/json]");
        let ranges = hidden_ranges(&r);
        let commits = vec![
            Commitment {
                range: ranges[0].clone(),
                hash: [1; 32],
            },
            Commitment {
                range: ranges[4].clone(),
                hash: [3; 32],
            },
        ];
        assert!(why(check_response(&view(&r), &commits, &T)).contains("hidden byte"));
    }
}
