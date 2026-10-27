# Complete W1 succinct-proof experiment

This isolated workspace proves the existing PNH1/PNW1 verifier with a local
RISC Zero recursive STARK. It is not a Node dependency, activation profile,
hardness proof, quantum-security claim or replacement consensus. The
[frozen statement](../../../docs/protocol/pon-nakamoto-v1/details/PURE_PON_WORK_SECURITY_MODEL_V1.md)
specifies the authority boundaries.

`relation` calls the original `pon_work::verify`, including canonical field
decoding, task/ticket, bounded noise rejection, every transcript prefix and
product reconstruction. There is no sampled matrix/transcript relation.
`methods/guest` reads exactly one fixed 49,506-byte input. The public journal
contains the full 318-byte header, trace, ticket, original block identity
and all 16,384 bytes of C. This intentionally retains the original useful
output rather than hiding part of the output behind an unchecked claim.

The host uses an explicitly selected, SHA-256 pinned local `r0vm` 3.0.3
process for the actual prover, requires a
succinct STARK, verifies the image ID and exact expected journal, and
rejects altered header, product journal and seal. Both host and guest enable
`disable-dev-mode`; the host also refuses proof-selection environment
variables. No remote prover, dev receipt, Groth16 or successful stub is an
alternative. Recursive proof-system internals never alter the PoN lottery
or add chainwork. These dependencies do not establish post-quantum
Fiat-Shamir soundness.

## Reproduction

Install the repository's native Rust 1.95.0, an official RISC Zero Rust
1.88.0 guest toolchain and the pinned Cargo dependencies. This experiment
pins SDK/build 3.0.3 and commits host and guest lockfiles. All native crate
sources are path dependencies inside this repository. Preserve the complete
build and failed-run logs, source/tree, ELF and binary hashes with a run.
The guest uses the official SHA-256 extension circuit through the pinned
RustCrypto-hashes commit `244dc3b08788f7a4ccce14c66896ae3b4f24c166`.
The native comparison uses the ordinary SHA-256 implementation; their full
public outputs must match. This optimization retains every transcript byte.

The official x86_64 Linux release archive is
`https://github.com/risc0/risc0/releases/download/v3.0.3/cargo-risczero-x86_64-unknown-linux-gnu.tgz`,
SHA-256 `71a0adaa64235be13e9b8471bea5c4ded64bf97c6bd1eb9c2285b966c0b62fee`.
The extracted `r0vm` must have SHA-256
`2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6`;
the host rejects any other binary. Pinning the backend supplies executable
identity, not trust in its output: the independent SDK verifier still checks
every receipt cryptographically and enforces the exact guest image and journal.
There is no automatic backend selection or remote proving fallback. This
replaces the initial source-build setup, whose guest dependency failure and
explicitly stopped C++ build are retained separately from proof measurements.

```sh
bash scripts/project-preflight.sh
cargo test --locked --release --manifest-path formal/pon-nakamoto-v1/w1_zkvm/Cargo.toml -p trnm-w1-zk-relation
cargo build --locked --release --manifest-path formal/pon-nakamoto-v1/w1_zkvm/Cargo.toml -p trnm-w1-zk-host
target/release/trnm-w1-zk-host --r0vm /absolute/pinned/r0vm /absolute/new/output 3
target/release/trnm-w1-zk-host verify /absolute/new/output/header-0.bin /absolute/new/output/receipt-0.bin
```

Use the actual `CARGO_TARGET_DIR` if overridden. The host refuses existing
output directories. Each completed/failed proof attempt is appended and
fsynced; successful receipts and exact inputs are retained. An external
runner must record killed/timeout processes and peak RSS, since SIGKILL
cannot write its own terminal observation. Do not infer omitted failures
from the completed summary.
The committed `../experiments/w1_proof_cost.py` runner records actual kernel
child CPU/RSS, timeout and process exit, retains incomplete trials, and runs
the saved-receipt verifier in a fresh process for every successful trial.

For each full input the host measures 100 native verifications, one actual
proof generation, proof bytes and 100 proof verifications. Multiple proof
trials expose run variation; three trials do not estimate a reliable p99
prover tail. Fixture construction is timed separately and not claimed to be
the complete mining search distribution. The maximum-target fixture is a
controlled cost sample; it does not qualify the production lottery or
structured-input hardness.
Matrix entries use domain-separated deterministic SHA-256 and canonical
rejection. The initial native smoke test used affine, rank-at-most-two
matrices; it was a correctness test and was replaced before proof costing.

The caller compares the original header to the proven header and keeps
original task eligibility, required branch target, timestamp, transaction
execution, DA and State/receipt-root admission. `check_public_journal` is
only a public-binding helper **after** cryptographic verification. It is
not a cheaper substitute for that verification.

## Acceptance

Correctness and actual benefit have separate outcomes. A real complete
proof can still fail 2A if generation, verifier cost, proof size or tail
latency are worse than the existing 49,188-byte full verification path.
No empirical cost, native integration or cryptographic qualification is
asserted merely because this directory builds. See the source-bound
work-package evidence for actual outcomes.
