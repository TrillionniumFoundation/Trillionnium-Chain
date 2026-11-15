# Current-source closure work, 2026-11-04

Continue integration PR #688 from `40a5ba25e40fd5eda5b04fc1c3811320d438de11`.
This directory retains small reproduction instructions and observations. It does
not turn component tests, metadata consistency, or historical runtime reports
into acceptance of the complete Chain/Hepta pair.

## Changes and actual controls

- **W1 collision:** an explicit `WorkFactCache` request for a different key no
  longer waits behind the in-flight owner of its direct-mapped slot. It performs
  the original complete replay without retaining or evicting that owner's
  result. Same-key single-flight remains. The exact old runtime fails the new
  collision control; the changed crypto library passes all 133 unit tests,
  4 task-lifecycle tests, 5 work-task tests and 2 compile-fail documentation
  controls. Public V3 uses a different completed-fact cache: its 21 controls
  pass unchanged, including 65 challenges in 64 slots, 130 full transcripts,
  66,560 tiles and zero cache hits under churn.
- **Cell repair deadline:** three repair writer boundaries use the remaining
  original operation deadline. Four real SQLite writer-contention controls
  fail against the original runtime and pass against the fix. The initial
  complete M09 suite passes 183 tests. The separate [repair manifest](../cell-repair-writer-deadline-20261104/README.md)
  retains exact source hashes and original 100-ms deadline measurements.
  Three additional controls then observe actual committed repair rows through
  a second connection and cancel before successful return. Cold exact retry
  preserves charge/identity and performs no duplicate payload write. The final
  M09 test source passes **186/186** with strict all-target Clippy.
- **Architecture observations:** the reader now binds 32 distinct confirmations
  to the actual eight cells, seven packets, context, inclusion/tip, one observed
  batch view and six-depth plus required-work policy. The three retained
  counterexamples are duplicate transaction identities, foreign network and
  zero work. Original and candidate readers are evaluated on identical
  synthetic bytes; these controls are not native signatures or W1 results.
  The shared public Host launcher continues to import with Python's standard
  library only. All 14 reader and 17 Host controls pass.
- **Fuzz dependency closure:** the current Linux SHA-2 backend required
  `sha2-asm` in the separate fuzz graph. Its missing lock entry stopped both
  fuzz-smoke and supply-chain jobs before their actual checks. Cargo regenerated
  only this missing `sha2-asm 0.6.4` entry and its `sha2` edge; every previously
  pinned package version and checksum remains. A second locked offline graph
  resolution reports zero changes. The main workspace lock and all manifests
  remain the original inputs.
- **PQ cold recovery:** reopening now audits the complete resource table,
  pinned peer cardinality and request-to-peer relationship before checking
  individual signed records. SQLite's re-enabled foreign-key and CHECK rules
  do not retroactively audit imported rows. Both new real restored-database
  controls fail on the old runtime; the changed native PQ ingress suite passes
  17 controls with `pq-native-openssl`. The related witness suite has 52 passes
  and three failures where an independent child cannot bind its Unix socket
  (`EPERM`) in this environment. Those three are not counted as passes and
  still require the original CI environment and unchanged deadline.

Strict package Clippy, formatting and source controls are recorded with their
actual scope in `reproduction.json`. Component-source hashes identify what was
executed. A later composed commit needs its own clean-source CI execution.

## Reproduce on the complete checkout

Use the repository's pinned Rust 1.95.0 toolchain, original Cargo profiles and
canonical dependency graph. Dependencies must already be present for offline
commands. These commands preserve all original verification and resource rules.

```sh
bash scripts/project-preflight.sh
cargo metadata --locked --offline --manifest-path trillionnium/Cargo.toml --format-version 1 --no-deps
cargo update --locked --offline --workspace --manifest-path tests/fuzz/Cargo.toml
cargo metadata --locked --offline --manifest-path tests/fuzz/Cargo.toml --format-version 1 --no-deps
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-crypto-primitives
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --lib -- --test-threads=1
cargo clippy --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-crypto-primitives -p trnm-data-availability --all-targets -- -D warnings
cargo fmt --manifest-path trillionnium/Cargo.toml --all --check
python -m unittest discover -s formal/pon-nakamoto-v1/experiments -p test_architecture_compare.py -v
python scripts/ci/test_architecture_host_ci.py
python -S scripts/ci/run_public_fixture_native.py --help
python scripts/ci/test_ci_source_integrity.py
python scripts/ci/test_pq_chain_claim_guard.py
python scripts/ci/check_pq_research_integration.py
python scripts/ci/check_repository.py
```

The PQ controls additionally require the original pinned OpenSSL 3.5.9 provider
environment prepared by `scripts/ci/prepare_pq_provider.sh`:

```sh
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --features pq-native-openssl --lib ingress::pq_network::tests:: -- --test-threads=1
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --features pq-native-openssl --lib store::pq_rollback_witness:: -- --test-threads=1
cargo clippy --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --features pq-native-openssl --all-targets -- -D warnings
```

To reproduce a runtime red control, use a separate checkout of the base commit,
apply only the new control and its test helpers, and keep its original runtime
file. The W1 collision control must fail; the four Cell writer-wait controls
must fail without changing their 100-ms operation deadline. The fixed runtime
must pass the same control bytes. Raw native logs remain local or in original
Actions artifacts; their hashes and exact commands are sufficient for this
small publication.

## Existing business failure remains visible

The base commit's [original 16-attacker, four-second run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41785836318)
used native independent replay and confirmation. Its attack-free baseline
confirmed one transaction at 3,101,306,684 ns from the original traffic epoch
(3,101,156,294 ns after business start). The pressure phase confirmed zero
transactions before 4,000,000,000 ns. Both used identical signed packets and the
original budget; all five named native controls passing did not satisfy the
business gate. Artifact `13301873260`, path
`from-zero-native/confirmation/report.json`, is the source of these values.

The [24-process, three-run campaign](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41785836386)
and [fixed-Host ROOT F0 diagnostic](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41785836093)
are different experiments. Their 30-second phase outcomes cannot replace the
original 16-attacker four-second acceptance. Each still fails its own complete
business criteria. The 24-process campaign has six baseline confirmations out
of nine scheduled baseline rounds and zero pressure confirmations out of
eighteen scheduled pressure rounds; the failed and unobserved rounds remain
in those denominators.

## Acceptance boundaries

The whole-effect external root still needs CURRENT, FinalUse, balances,
settlement, task and active-history relationships plus uncertain-CAS and writer
reconciliation. Local PNQ2 cold audits cannot supply that external root.
The W1 measurements are finite upper observations of particular legal methods,
not proof of the globally lowest cost or a physical-work lower bound. Complete
current SQL graph validation remains linear. Independent Cell fault domains
and prospective held-out model evaluation remain required; long `no-update`
remains legitimate. Serial/concurrent/reference-DAG dissemination uses the same
PoN consensus and is not a measured Bitcoin-NG, Prism or DAG-BFT implementation.
All production, public-network and cross-protocol qualification flags remain
unaccepted.
