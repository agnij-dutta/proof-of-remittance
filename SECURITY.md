# Security

Proof of Remittance is an **alpha, unaudited research prototype** that runs against a mock bank. It has not been reviewed by a third party. Do not use it to move real money.

## Reporting a vulnerability

Please report privately through GitHub's **private vulnerability reporting**: the "Report a vulnerability" button under the repository's Security tab (`https://github.com/agnij-dutta/proof-of-remittance/security/advisories/new`). Do not open a public issue for a soundness or fund-loss bug.

Include what an attacker controls, what they gain, and a reproduction if you have one (a modified prover, a transcript, a failing Foundry test). Expect an acknowledgement within a week. This is a personal project, so there is no bounty.

## In scope

- **Soundness:** any way to get `RemittanceEscrow.release` or `verifyBundle` to accept a credit that the bank did not return, that is below the threshold, that predates the escrow, or that belongs to a different escrow.
- The notary's template check (`prover-rs/src/template.rs`): any transcript shape it signs where the committed bytes are not the `amount` and `ts` of one credit in the response to the expected request.
- The Noir circuit (`circuit/src/main.nr`): a witness that satisfies it for an amount or timestamp that does not satisfy the predicate, or for bytes other than the committed ones.
- Escrow accounting and access control: paying the wrong party, paying twice, locking funds.
- Privacy leaks beyond the ones listed under "Known leakage".

## Known non-goals and accepted risks

These are documented design limits, not bugs:

- **A colluding or compromised notary can forge anything.** In MPC-TLS the notary and prover together hold the full TLS keys. The contract trusts one immutable notary key. Mitigations (k-of-n notaries, a TEE notary, having the escrow's counterparty run the notary) are future work.
- **The notary is trusted for the template check.** It decides which hidden bytes are the amount. There is no on-chain transcript verifier.
- **Bank truthfulness and endpoint semantics.** zkTLS proves what the server said, not that it is true, settled or irreversible. The template assumes every `{"amount","currency","narration","ref","ts"}` object in this endpoint's response is a settled credit to the account. The notary cannot see the JSON around the object, so it cannot tell which array the object sits in. Each real endpoint needs that assumption re-established.
- **Hidden header value.** The prover may hide the `Authorization` header value. The notary cannot see inside it, so a malicious prover could put extra header lines inside that hidden range. Anything after the first response is cut off by the framing check, so this cannot add a second request's response. But if a real bank changes *which account's* data an endpoint returns based on some request header, a per-bank provider must account for it.
- **Web PKI.** A mis-issued certificate for the bank's domain breaks the model, as it does for browsers.
- **Identity.** A proof shows that someone with a session token for the account saw the credit, not who they are.
- **TLSNotary itself** (`v0.1.0-alpha.15`) is alpha and unaudited. This repo relies on its MPC-TLS and on its hash commitments being computed over the authenticated transcript.

### Known leakage

To the notary and on-chain: the byte length of the amount and of the hidden UTR, all response headers (including `Content-Length` and `Date`), the narration, the currency, the session time. Length leakage is inherent to TLSNotary byte-range commitments.

## Review log: 2026-10-05

A review of the prototype before open-sourcing, by a second pass over the code. Findings, ranked:

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | High | **Cross-deployment replay.** The narration was `POR-ESCROW-<id>`, and the notary's signed digest has no chain id or contract address. One bank credit could release escrow #1 on every deployment, on every chain, that trusts the same notary. | **Fixed.** `narrationFor(id)` is now `POR-` plus 80 bits of `keccak256(chainid, contract, id)`. Tested in Foundry, JS and in the demo (attack "replay on another deployment"). |
| 2 | High | **Hidden pipelined request.** The notary only checked the request line and that a `Host` header appeared somewhere. A prover could hide a second request (for example to a debits endpoint with the same JSON shape) and point the commitments at its response. | **Fixed.** The notary now requires exactly one fully revealed `GET` with only the `Authorization` value hidden and nothing after the headers, and exactly one fully revealed `200` response whose `Content-Length` ends at the end of the transcript, with both commitments inside its body. Chunked and compressed responses are refused. 19 unit tests over malicious transcripts in `template.rs`. |
| 3 | Medium | **Verifier service trusted caller-supplied terms** without saying so loudly, and was stateless. A prover choosing its own `thresholdPaise` gets `ok: true`. | **Documented and hardened.** The terms now include chain id and contract (for the narration), the API and README state that terms must come from the relying party, input is strictly validated and bodies are size-limited. Replay protection remains the caller's job. |
| 4 | Low | **Zero notary address.** `_recover` returns `address(0)` for any malformed signature, so a contract deployed with `notary = 0` would accept garbage signatures (and the prover can always build a ZK proof for commitments it chooses). | **Fixed.** Constructor rejects zero addresses; `release` also rejects a zero signer. Tested. |
| 5 | Low | `createEscrow` accepted a zero beneficiary, amount, threshold or ttl. | **Fixed.** Reverts `InvalidEscrowParams`. Tested. |
| 6 | Info | **Signature malleability and domain separation.** The contract already rejects high-s and `v ∉ {27, 28}`; replay protection does not depend on signature uniqueness anyway (the `settled` flag does). The digest is EIP-191 over `keccak256(abi.encode("POR_TLSN_V1" hash, ...))`, with no chain or contract binding by design (it is a statement of fact about a TLS session); escrow binding comes from the narration (see 1). The notary key must be dedicated to this purpose, since any EIP-191 signature it makes over a 32-byte value is a candidate attestation digest. | Tested (high-s, bad `v`, short signature, other key). EIP-712 is on the roadmap. |
| 7 | Info | **Per-credit nullifier.** There is none. With finding 1 fixed, each escrow has a unique narration, so one credit satisfies at most one escrow. A nullifier on the UTR is still needed for rails that drop remarks. | Roadmap. |
| 8 | Info | **Circuit range handling** reviewed: `amount_len` is private but pinned by the SHA-256 length padding and the fixed 16-byte blinder, so the amount/blinder split cannot move; at most 16 bytes means at most 15 digits, which cannot overflow `u64`; leading zeros are harmless; signs, separators and wrong decimal places fail. | No change to `main`. 15 end-to-end circuit tests added. |
| 9 | Info | Compiled circuit artifact `circuit/target/remittance.json` was committed with absolute local paths in its debug file map. | Untracked; rebuilt by `npm run build:circuit`. Still present in early history (not a secret). |

### History scrub

`gitleaks` over the full history finds four PEM private keys in the first commit (`certs/root_ca.key`, `bank.key`, `evil_ca.key`, `evil.key`). They were checked: each is the key of a self-signed, local-only test certificate (`MockBank Root CA (TEST ONLY)`, `Impostor Root (TEST ONLY)`, and two leaves for `netbanking.mockbank.test`, a name under the reserved `.test` TLD that no public CA will issue for). They protect nothing and are not trusted anywhere outside this demo. They are no longer tracked; `scripts/gen-certs.sh` generates fresh ones locally. History was not rewritten.

Other key-shaped strings in the repo are the well-known Anvil/Hardhat dev keys (in `scripts/demo.mjs` and vendored `forge-std`), which hold nothing on any real chain. The demo's notary key is random per run.
