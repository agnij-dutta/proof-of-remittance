# zkTLS / web proofs for "proof of remittance": which stack, and why

*Written 2026-10-04 for a solo builder who wants to prove a fiat fact from an HTTPS response (an INR credit landed, a Stripe invoice is paid) and use it to move USDC or change an agent's spend mandate on-chain.*

Selection criteria, in priority order:

1. **Testable today with no paid account, no API key, no hosted dependency.**
2. **Open source**, with a licence that doesn't contaminate a product.
3. **Selective disclosure** strong enough to hide the account number, balance, UTR and session token.
4. **A path to on-chain verification** (EVM first; Solana is a nice-to-have).
5. **An honest trust model** I can explain in one paragraph.

Facts below were gathered on 2026-10-04 from project docs, release pages and GitHub. Anything I could not confirm is marked *(unverified)*. The TLSNotary facts marked **[ran it]** were confirmed by building this prototype against `tlsn v0.1.0-alpha.15`.

## The three trust models

| Model | Who sees what | What you must trust | Who uses it |
|---|---|---|---|
| **MPC-TLS (2PC notary)** | Prover and notary jointly hold the TLS session keys. The notary never sees plaintext unless the prover reveals it. | That the notary doesn't collude with the prover. The notary can't forge server data alone, and the prover can't either. | TLSNotary (MPC mode), zkPass (3P-TLS + VOLE ZK), Primus (MPC mode) |
| **Proxy / witness** | An attestor relays the ciphertext between prover and server. The prover then proves in ZK that the redacted plaintext matches it. | That the attestor doesn't collude with the prover, **and** that the network path between the attestor and the server is honest. An attacker who controls both the prover and that path (DNS or BGP) can forge. | Reclaim, TLSNotary Proxy mode (new in alpha.15), Primus (proxy mode) |
| **TEE** | A notary or attestor runs inside SGX or TDX and re-signs results. | The hardware vendor, the enclave code, and attestation freshness. Side channels are a known risk. | Opacity (SGX notaries on EigenLayer), vlayer "vouch" (TDX), Pluto (TDX mode), zkp2p v3's attestation service |

On-chain, **almost every stack ends in an ECDSA signature check** (a notary, attestor or TEE key, recovered with `ecrecover`). No vendor publishes a routinely used on-chain verifier that checks the TLS session itself. vlayer's RISC Zero path was the exception, and it is currently turned off. That is why this prototype puts a ZK proof on-chain only for the *predicate* (amount ≥ X), and trusts a notary signature for the *TLS session*.

## Stack by stack

### TLSNotary (Ethereum Foundation PSE): **chosen**

- **Trust model.** MPC-TLS: the prover and the verifier/notary run 2PC over the TLS session keys, and the notary authenticates the transcript without seeing it. If you run the verifier yourself, you trust nobody. If someone else runs it, you trust them not to collude with the prover. alpha.15 adds a much faster **Proxy mode**, which carries the network-path assumption above. [FAQ](https://tlsnotary.org/docs/faq/), [Proxy mode post](https://tlsnotary.org/blog/2026/04/22/proxy-mode/)
- **Maturity.** `v0.1.0-alpha.15` (May 2026), still labelled "not for production". It is very active, with a release about every 4 months. [releases](https://github.com/tlsnotary/tlsn/releases)
  - **[ran it]** The tag builds cleanly with Rust 1.96. Our two binaries took about 3 minutes for a cold release build.
- **SDKs.** The Rust core, WASM for the browser (`tlsn-wasm`/`tlsn-sdk-core`; `tlsn-js` is deprecated), and a browser extension. Native mobile is future work.
- **Local / keyless.** Yes, fully. **[ran it]** The prover and notary are two local processes, the "server" is any HTTPS endpoint, and you choose the root CA. There is no portal, no app ID and no hosted notary.
- **Selective disclosure.** Byte-range reveal, plus **SHA-256 plaintext-hash commitments with blinders**, which can be opened inside a ZK circuit. The repo ships a Noir example that proves age ≥ 18 from a committed date of birth. **[ran it]** We use the same mechanism for amount ≥ threshold.
- **On-chain.** No native verifier. The FAQ says to use an application-specific verifier, with on-chain verification "planned". Production users wrap it:
  - zkp2p re-signs with EIP-712 from a TEE.
  - vlayer compressed it with RISC Zero.
- **TLS version.** **TLS 1.2 only.** 1.3 is "on the roadmap" with no immediate plans. alpha.15 adds EMS. This is the single biggest real-world constraint (see README).
- **Performance.**
  - The project's own numbers for a 1 KB request / 2 KB response: MPC takes about 4 s native on fiber and about 14.5 s on cable. Proxy mode takes about 1.6 s on cable. The browser is 10 to 40% slower. [alpha.14 perf](https://tlsnotary.org/blog/2026/01/19/alpha14-performance/), [proxy perf](https://tlsnotary.org/blog/2026/05/10/blog-proxy-mode/)
  - **[ran it]** On loopback (no network latency), a full MPC-TLS session plus selective disclosure for a 143 B request and 705 B response takes about 1 to 2 s.
- **Licence.** MIT or Apache-2.0.

### Reclaim Protocol

- **Trust model.** Proxy/witness. An "attestor" relays the TLS traffic and signs the claim. The client proves in ZK that the redacted plaintext matches the ciphertext.
  - On-chain, the contract keeps per-epoch witness sets that the contract owner manages. [reclaim-solidity-sdk](https://github.com/reclaimprotocol/reclaim-solidity-sdk)
  - A Sept 2026 paper claims a UC-security proof for a three-party variant. [ePrint 2026/2187](https://eprint.iacr.org/2026/2187) *(read via summary only)*
- **Maturity.** In production, with broad SDK coverage: JS, React Native, Flutter, Kotlin, Swift, Python. The circuits moved to gnark, with about 4 to 5 s proofs on phones. [blog](https://blog.reclaimprotocol.org/posts/gnark-migration)
- **Local / keyless.** **Partly.**
  - The app SDK needs `APP_ID`/`APP_SECRET` from the dev portal.
  - `attestor-core` can run a local attestor. That is useful for development, but you are then trusting your own attestor, which proves nothing to a third party.
  - **Licence is AGPL-3.0** for attestor-core. [repo](https://github.com/reclaimprotocol/attestor-core)
- **On-chain.** The best story of the group: `verifyProof()` recovers the witness signatures and checks them against the epoch set. It is deployed on many EVM chains, and there are Solana and NEAR examples. Gas is not published; I would estimate 50k to 150k *(estimate, unverified)*.
- **TLS version.** TLS 1.2 **and 1.3**. That is a real advantage for modern bank sites.
- **Why not chosen.** It needs a portal key for the real network, and attestor-core is AGPL. Self-hosting the attestor removes the decentralisation that is the whole point. Proxy-model assumptions are also weaker than MPC.

### zkPass

- **Trust model.** "3P-TLS": a three-party handshake with an MPC validator node, plus VOLE-based interactive ZK. You trust that the validator, picked by an "allocator", doesn't collude with you.
  - Verification is two ECDSA signatures: one from the allocator and one from the validator. [docs](https://docs.zkpass.org/developer-guides/js-sdk/generate-proof-and-verify-the-result.md)
- **Local / keyless.** **No.** It needs an `appid` and schemas from the Dev Center, plus the TransGate extension or mobile app. The network is hosted.
- **On-chain.** ecrecover-style checks, documented for EVM, Solana and TON. You write the verifier contract yourself.
- **Licence.** Examples are Apache-2.0. The JS SDK repo has no licence file.
- **Why not chosen.** It is not runnable without an account, and the core is not self-hostable.

### Opacity Network

- **Trust model.** TLSNotary-derived notaries inside Intel SGX, run as an EigenLayer AVS with slashing. Attestations are EIP-191 signatures.
- **Status.** It appears to have pivoted toward compliance/investor credentials for tokenized-securities venues *(inferred from the site; unverified)*. It has mobile SDKs and needs an API key.
- **Why not chosen.** API key, a hardware-trust model, and an unclear developer focus in 2026.

### vlayer (Web Proofs)

- **Status.** Mainnet v1 shipped in May 2025. In 2026 it moved to a hosted Web Prover API plus "vouch" (TDX). **The ZK Prover Server that made proofs verifiable on-chain is "currently turned off".** [docs 2.0](https://github.com/vlayer-xyz/vlayer-docs-2.0)
- **Licence.** **BUSL** from 0.3 onward. It needs an API key, and the free plan lasts one month.
- **Why not chosen.** Hosted, key-gated, BUSL, and the on-chain path is disabled.

### Also checked briefly

- **Pluto** (MPC, Origo proxy and TDX modes): `web-prover` (Apache-2.0) has had no pushes since March 2025. Treat it as dormant *(inferred)*.
- **Primus (ex-PADO)**: proxy and MPC modes, with attestor signatures checked on-chain by `PrimusZKTLS.verifyAttestation`. It needs an appID/secret from its Developer Hub.
- **zkp2p / Peer v3**: the production reference pattern.
  - It accepts TLSNotary, Primus or Reclaim proofs.
  - A TEE service validates them and emits an EIP-712 payment attestation.
  - The contract checks the signature, the amount and replay. [blog](https://docs.peer.xyz/blog/intro-zkp2p-v3)
  - No India/UPI rail was found *(unverified)*.

## Side-by-side

| | TLSNotary | Reclaim | zkPass | Opacity | vlayer |
|---|---|---|---|---|---|
| Trust | MPC 2PC (or proxy) | Proxy witness | 3P MPC + VOLE ZK | SGX notary + restaking | TLSN notary in TDX |
| Runs fully local, no account | **Yes** | Dev-only (self attestor) | No | No | No |
| Licence | MIT / Apache-2.0 | AGPL-3.0 (attestor) | Mixed / unclear | MIT SDKs | BUSL |
| SDK | Rust, WASM, extension | JS, RN, Flutter, mobile, Python | JS + extension/app | Mobile | REST + mobile |
| TLS 1.3 | No | Yes | (unverified) | (unverified) | (as TLSN) |
| On-chain | DIY (sign, or ZK-wrap) | ecrecover of witness set, EVM + Solana | ecrecover, EVM/Solana/TON | EIP-191 sig | RISC Zero (disabled) |
| Hiding a value but proving a predicate | Hash commitments + your own circuit | Regex/JSONPath redaction, no numeric predicates *(unverified)* | Schema-defined | (unverified) | Solidity-side checks |

## Decision

**TLSNotary alpha.15, MPC mode, with a local notary, plus a Noir circuit over its SHA-256 commitments.**

- It is the only option that satisfies criterion 1 without caveats. The whole round trip ran on one laptop, against a mock bank I control, with no account anywhere.
- Hash commitments with blinders are the right primitive for *"prove amount ≥ X without revealing the amount"*. Plain redaction either reveals the number or hides it, and it can't compare. I did not find numeric-predicate support in Reclaim's public docs *(unverified)*. TLSNotary commits to the exact bytes, and a ~36k-gate Noir circuit opens the commitment and checks the comparison.
- The licence is permissive, so it can go into Capline (MIT) without friction.
- **Cost of the choice:**
  - TLS 1.2 only.
  - No canonical on-chain verifier, so we bridge with a notary signature, exactly as zkp2p does.
  - Alpha APIs churn between releases. alpha.15 changed the Session API.

### On-chain design that follows from the decision

- **TLS-session facts** (server name, endpoint, currency, narration, the two commitments) are signed by the notary key (secp256k1, EIP-191). The contract checks them with `ecrecover`: about 3k gas plus string hashing.
- **The predicate** over the hidden values (amount ≥ threshold, timestamp ≥ escrow creation) is an **UltraHonk proof verified on-chain** by a Solidity verifier that `bb` generated. It costs **about 2.73M gas** and takes a 9,024-byte proof.
- Because of this split, the notary is trusted **only for "these bytes came from the bank's TLS session"**. It never learns the amount, and the contract doesn't trust it for the comparison at all.

### What would change the decision

- **TLSNotary ships TLS 1.3** → the main blocker for real bank sites goes away.
- **Production plus a mobile UX outweighs self-hostability** → Reclaim: it has TLS 1.3, mobile SDKs and the cheapest on-chain check. The cost is AGPL and a portal key.
- **Someone ships a canonical TLSNotary attestation verifier in Solidity or a zkVM** → the contract could check the notary's generic attestation and run the "which bytes are the amount" template itself. Today our notary does that template check before it signs. You would still trust the notary not to collude with the prover; that is inherent to MPC-TLS.
