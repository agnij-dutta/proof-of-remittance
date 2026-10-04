# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-05

First public version. Alpha, unaudited, mock bank only.

### Added
- Mock HTTPS bank (TLS 1.2) with a credit simulator, and an impostor bank for the untrusted-certificate attack.
- TLSNotary `v0.1.0-alpha.15` prover and notary (MPC-TLS). The notary checks the certificate chain and a request/response template, then signs an EIP-191 attestation over the session facts and SHA-256 commitments to the hidden amount and timestamp.
- Noir circuit (UltraHonk, keccak transcript) proving the committed amount is at least a threshold and the committed timestamp is at least the escrow creation time.
- `RemittanceEscrow` with a `bb`-generated Solidity verifier, plus `MockUSDC`.
- Off-chain verifier library and HTTP service running the same checks as the contract.
- `npm run demo`: end-to-end run plus attack checks (replay, tampered proof, under-threshold credit, forged commitment, cross-escrow reuse, cross-deployment replay, impostor bank).
- Test suites: JS (node:test), Rust unit tests, Noir tests, Foundry tests over a captured real bundle.
- README with trust model, SECURITY.md with review findings, CONTRIBUTING, CI workflow.

### Security
- Escrow narration is domain-separated by chain id and contract address, so one credit cannot release the same escrow id on another deployment.
- The notary refuses transcripts with a hidden or pipelined second request, hidden response headers, missing or mismatched `Content-Length`, chunked or compressed bodies, or commitments outside the response body.
- The escrow rejects zero addresses at construction and zero-value escrow parameters.

[Unreleased]: https://github.com/agnij-dutta/proof-of-remittance/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/agnij-dutta/proof-of-remittance/releases/tag/v0.1.0
