# Useful Cell v2 validation record

Date: 2026-11-06. Initial base source:
`b173c1f52d927522af67df30dd08ecfb2e3a1bb0`. Candidate branch:
`feature/chain-w1-cell-proof-20261106`. This record covers only the new
`useful_cell_v2` research extension and its
[specification](../../../docs/development/specs/pon/USEFUL_CELL_NATIVE_POSTPROCESS_V2.md).
The repository-level combined gates and publication remain the integration
owner's responsibility.

## Successful checks

The following actually ran in the shared isolated checkout. Environment:
Rust 1.95.0, existing complete cache
`CARGO_HOME=/workspace/scratch/2e04527a60e8/cargo`,
`RUSTUP_HOME=/workspace/scratch/1eed767ad985/rustup`, and separate build output
`CARGO_TARGET_DIR=/workspace/scratch/39ce077f3480/cell-v2-target`.
No dependency version was relaxed to complete the build.

| Check | Observed result |
| --- | --- |
| `bash scripts/project-preflight.sh` | PASS, approved development branch, 26 main-workspace packages, remote policy unchanged |
| `cargo generate-lockfile --offline` with this manifest | PASS; lockfile includes the actual `trnm-crypto-primitives` dependency graph |
| `cargo test --offline --locked --manifest-path formal/pon-nakamoto-v1/useful_cell_v2/Cargo.toml` | 19 integration tests passed, zero failures |
| `cargo fmt --check --manifest-path formal/pon-nakamoto-v1/useful_cell_v2/Cargo.toml` | PASS |
| `cargo clippy --offline --locked --manifest-path formal/pon-nakamoto-v1/useful_cell_v2/Cargo.toml --all-targets -- -D warnings` | PASS |
| `cargo build --release --offline --locked --manifest-path formal/pon-nakamoto-v1/useful_cell_v2/Cargo.toml` | PASS |
| Independent Python known-answer reconstruction | Full 817-byte frame and all three v2 hashes match the Rust four-request fixture |
| `reproduce.py` against the release binary | Eight direct/grouped producer runs and eight separate verifier runs at batch sizes 1, 4, 16 and 64 passed; every output byte matched the independent Python encoding |
| Rehashed false STOP binary | Rejected with `POSTPROCESS_RELATION`, process exit 1 |
| Different independently supplied consumer task | Rejected with `EXPECTED_CONTRACT`, process exit 1 |

Exact replay command:

```sh
python3 formal/pon-nakamoto-v1/useful_cell_v2/reproduce.py \
  --runner /workspace/scratch/39ce077f3480/cell-v2-target/release/trnm-useful-cell-v2-reference \
  --out /workspace/scratch/39ce077f3480/cell-v2-replay-file-boundary-20261106
```

The scratch output holds all canonical task JSON and binary claims, including
negative controls. The retained
[replay result](evidence/replay-result.json) preserves source hashes, release
binary hash, every run's contract/statement commitment and negative outcomes.
The full [Cargo tree](evidence/cargo-tree.txt) and
[compiler identity](evidence/rustc.txt) are retained.

| Batch | Group sizes | Claim bytes | STOP decisions in fixture |
| ---: | --- | ---: | ---: |
| 1 | 1, 0, 0 | 427 | 1 |
| 4 | 2, 1, 1 | 817 | 3 |
| 16 | 6, 5, 5 | 2,377 | 10 |
| 64 | 22, 21, 21 | 8,617 | 44 |

Direct and grouped producers agreed exactly in every row above. These are
synthetic correctness fixtures in the existing model's operator shapes. The
request intervals and provenance hashes are test labels. No source-corpus
replay, real demand, model quality or performance conclusion is derived from
this table. No normal/native elapsed time is presented as cryptographic prover
or verifier performance.

## Retained unsuccessful setup observations

Before source edits, the first preflight on the supplied branch
`feat/w1-cell-proof-20261106` failed with `not an allowed development branch`.
The isolated candidate branch was renamed to the repository-required
`feature/chain-w1-cell-proof-20261106`; the boundary rules and remote policy were
not changed, and preflight then passed.

The first offline lockfile generation using
`CARGO_HOME=/workspace/scratch/1eed767ad985/cargo` failed because that cache only
contained `zeroize 1.9.1`, while the existing native package pins `=1.8.2`.
An online attempt with zero retries and a short timeout then failed downloading
`https://index.crates.io/config.json` with a connection timeout. The already
available complete cache at `/workspace/scratch/2e04527a60e8/cargo` contained the
required original version; offline locked builds then succeeded. No local path
patch, substitute crate, source-copy fallback or version relaxation was used.

The first relation-only test run had 17 passing tests. Two canonical JSON/task
negative tests were added with the executable transport, yielding the recorded
final 19-test run. No failed arithmetic or verification test was suppressed.

## File-boundary follow-up

Independent review found a real blocking path in the original CLI's
`File::open` / `read_to_end` sequence. The old release binary was run against an
actual writerless FIFO; it did not return within 2 seconds, and the experiment's
outer timeout killed and reaped it. The old source/binary hashes and this failed
observation are retained in
[file-boundary-before.json](evidence/file-boundary-before.json).

The CLI now uses nonblocking/no-follow Unix open flags and checks the type and
length of that same open descriptor before reading. It also rejects detected
length changes. The added
[file-boundary regression](tests/file_boundary.rs) launches real CLI processes
and independently tests both task and claim paths with writerless FIFOs,
symlinks, directories and oversized regular files. A 3-second watchdog kills
and reaps a blocked regression instead of allowing the test suite to hang.
The targeted regression passed in debug and release profiles. The final full
release suite passed all 20 integration tests. Formatting,
release strict Clippy (`--all-targets -- -D warnings`) and the release build were
rerun. The replay result and Cargo graph were refreshed against the corrected
binary; the complete arithmetic bytes remain identical to the original known
answer. The original 19 relation/task tests remain in place, with one additional
process-level file-boundary test. Final commands, exit codes and log filenames
are retained in [validation-final.json](evidence/validation-final.json).

These checks remove special-file blocking at this CLI entry. They do not impose
a hard deadline on arbitrary regular-file filesystem/kernel waits; an outer
process owner is still needed for a hard service budget.

## Exact boundaries

The producer and verifier use the original Cell's `3 x 257` matrices and actual
`257 x b_e` packed request groups. The new relation adds fully checked integer
postprocessing, policy and use/state/input bindings. It returns a typed verified
one-step result only after checking the completion clock. STOP is an output for
this step, and after state is exactly read-only; no subsequent Cell step or
mutable-state continuation is proven.

This is full native recomputation with a complete witness, not a dedicated AIR,
sumcheck/GKR backend, polynomial commitment or succinct proof. The binary frame
bound and loader limits cover this transport; they do not establish a global
malicious-input CPU budget, preempt a cryptographic worker or authenticate a
clock origin. Source replay, owner permissions, currentness/revocation,
continuation semantics, protocol work registration, minimum attacker work,
ordinary Hepta consumption and beneficial model adoption remain separate gates.
