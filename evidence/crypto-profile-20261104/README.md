# Bound cryptographic configuration and parameter observations

This directory contains the compact reproduction record and an independent
data reader for the implementation described by
[the security contract](../../docs/security/CRYPTO_PROFILE_V1_20261104.md).
Parent: PR #698, `5a5ddbd4577207af7f7771a4a50c76620f32940f`.
The current delivery must be read at its exact Git commit, not inferred from
that parent's historical results. All six whole-chain gates remain UNQUALIFIED.

## Reproduction

Use the repository's pinned Rust 1.95.0 and unchanged `Cargo.lock`. Default
RustCrypto candidate tests need no OpenSSL provider. The full original feature
set also needs the existing pinned OpenSSL 3.5.9 installation and its environment
contract. Preserve the original profile, debug assertions and overflow settings;
do not override optimization or enlarge any runtime budget to obtain a pass.

```bash
bash scripts/project-preflight.sh
cargo metadata --locked --offline --all-features --manifest-path trillionnium/Cargo.toml --format-version 1
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-protocol -p trnm-crypto-primitives --all-features --lib
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-protocol --doc
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib ingress::pq_network
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-mvcc-fee --all-features --lib pq_accounts_v2
cargo clippy --locked --offline --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings
python3 evidence/crypto-profile-20261104/recompute_profile_ids.py
python3 scripts/refresh_distributed_source_inventory.py --check
python3 scripts/ci/check_pq_research_integration.py
python3 -m unittest discover -s scripts/ci -p 'test_pq_research_integration.py' -v
python3 -m unittest discover -s scripts/ci -p 'test_ci_source_integrity.py' -v
python3 -m unittest discover -s scripts/ci -p 'test_pq_chain_claim_guard.py' -v
python3 scripts/ci/check_repository.py
```

The independent Python profile encoder uses explicit grammar values and hashlib;
it imports no Rust implementation and reproduces the fixed profile/message
vectors asserted by the native tests.

The original 45 PQ required selectors are preserved separately. These commands
do not claim the complete Node runtime suite, four-second business confirmation,
4,105-block History or independent WAN/production acceptance.

## Bounded parameter comparison

Record the exact source HEAD/tree, clean tracked bytes, Rust/Cargo versions,
dependency graph/lock digest, binary digest, CPU/memory/kernel and other load.
Run once under those recorded conditions and retain the full stdout, stderr
and actual exit status, including an incomplete run or refusal:

```bash
cargo run --locked --offline --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --example pq_parameter_bench -- --samples 64 \
  > pq-parameter-bench.jsonl
python3 evidence/crypto-profile-20261104/recompute_benchmark.py pq-parameter-bench.jsonl
```

The observer uses fixed explicit seeds and messages, two algorithms, message
lengths 0/176/4,096/65,536, signer groups 1/2/4/8, and nine separately measured
stages. Its 288 measured distributions retain all 18,432 sample values and a
completion sentinel. The independent reader rejects missing populations,
duplicates, altered statistics, inconsistent complete-frame lengths and missing
completion. A reader PASS validates the recorded numbers, not a production gate.

`TRNMCPB1` is a measurement frame with an actual serializer/parser; it is not the
CPQ1 protocol, PNQ2 transport or NPQ6 business transaction. Sign timing includes
canonical self-verification; key construction/import and verifier reuse are
separate stages. Group durations are not individual-request latency. A 64-sample
p99 is the maximum of these fixed-input samples, not an established production
tail. No run changes profile activation, proof relation or work/hash parameters.

The compact `reproduction.json` records the observed source, commands, outcomes,
measurement digest and selected summaries. Large binaries/build caches are not
repository deliverables. Prior failures and interrupted attempts are retained
as distinct observations; final-source acceptance is never inferred from them.
