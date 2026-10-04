# Contributing

Thanks for looking. This is an alpha research prototype, so the most useful contributions are attacks (a transcript the notary should refuse, a witness the circuit should reject), a real-endpoint provider, and fixes to the trust-model docs. Security issues go through private reporting, see [SECURITY.md](SECURITY.md).

## Dev setup

Install the toolchain listed in the README (Node 22, Rust stable, Foundry, `nargo 1.0.0-beta.19`, `bb 4.0.0-nightly.20260120`, `openssl`), then:

```bash
npm ci
npm run build      # certs, Rust (release), circuit + vk, contracts
```

The first Rust build compiles TLSNotary and takes about 3 minutes.

## Test, lint, format

```bash
npm test                 # all four suites
npm run test:js          # node:test (needs bb on PATH: one suite shells out to bb verify)
npm run test:rust        # notary template rules, attestation digest and signing
npm run test:circuit     # nargo test: parsing and end-to-end main() over real SHA-256 commitments
npm run test:contracts   # forge test: replays a captured real bundle, plus fuzz tests
npm run demo             # end-to-end run plus attack checks; exits non-zero on any failure

npm run lint             # Biome, tsc strict, cargo fmt + clippy -D warnings, forge fmt, nargo fmt
npm run format           # apply all formatters
npm run check:verifier   # HonkVerifier.sol matches a fresh bb output for circuit/target/vk
```

CI (`.github/workflows/ci.yml`) runs lint, build, the verifier sync check, all tests and the demo.

## Project layout

| Path | What lives there |
|---|---|
| `bank/` | Mock bank (HTTPS statement API + credit simulator) |
| `prover-rs/src/` | `prove` and `notary` binaries, `lib.rs` (attestation, digest, signing, flags), `template.rs` (the notary's transcript rules) |
| `circuit/` | Noir predicate circuit |
| `contracts/` | `RemittanceEscrow`, `MockUSDC`, generated `HonkVerifier`, Foundry tests and fixture |
| `lib/` | Shared JS: constants and `narrationFor`, attestation digest, ZK proving/verifying via nargo and bb |
| `verifier/` | Off-chain verifier (`verify.mjs`) and its HTTP wrapper (`server.mjs`) |
| `scripts/` | `demo.mjs` and helpers, `gen-certs.sh` |
| `test/` | JS tests |

## Things that must stay in sync

- **The attestation digest** is computed in three places: `prover-rs/src/lib.rs` (`digest`), `lib/attestation.mjs` and `RemittanceEscrow.attestationDigest`. The fixture tests in all three suites catch drift.
- **`narrationFor`** exists in `RemittanceEscrow.sol` and `lib/constants.mjs`. The demo aborts if they disagree.
- **Circuit, `vk` and `HonkVerifier.sol`.** If you change `circuit/src/main.nr` or the `bb` version:
  ```bash
  npm run build:circuit
  bb write_solidity_verifier -k circuit/target/vk -o contracts/src/HonkVerifier.sol -t evm
  npm run demo && npm run fixture   # regenerate the Foundry/JS/Rust fixture
  ```
  `forge fmt` skips `HonkVerifier.sol` on purpose, so it stays byte-identical to `bb` output.
- **The fixture** (`contracts/test/fixtures/bundle.json`) is a real bundle from a demo run, deployed in Foundry at the same address and chain id the demo used. After changing the notary, circuit or escrow, rerun `npm run demo && npm run fixture`.

## Adding an attack

Attacks are the main extension point.

1. **Notary-level** (a transcript shape): add a unit test in `prover-rs/src/template.rs`. The `view("...[hidden]...")` helper builds a transcript where bytes inside `[` `]` are hidden. Assert on the rejection *reason* with `why(...)`, not just `is_err()`, so the test cannot pass for the wrong reason.
2. **Circuit-level** (a witness): add a `#[test(should_fail_with = "...")]` in `circuit/src/main.nr` using `run_honest` or a direct `main(...)` call.
3. **Contract-level** (a bundle): add a Foundry test in `contracts/test/RemittanceEscrow.t.sol` that mutates the fixture bundle.
4. **End-to-end**: add a step under `[8] Attacks` in `scripts/demo.mjs` using `expect(...)`.

## Adding a real endpoint (a "provider")

Today the endpoint is fixed by constants (`SERVER_DOMAIN`, `ENDPOINT_PATH` in `prover-rs/src/lib.rs` and `lib/constants.mjs`) and by the credit object shape in `template.rs`. A new provider needs: the host and path, which request header carries the secret, the JSON shape of one credit, the commitment fields, and an argument (written in SECURITY.md) for why every object of that shape in the response is a settled credit to the prover's account. Start with a Stripe test-mode key, never a live credential.

## Style

- No em dashes in docs or comments. Plain words, no hype.
- Comments explain why: the decision, the attack it stops, the spec it follows.
- Commits: short imperative subject ("Notary: refuse chunked responses"), body says why.
