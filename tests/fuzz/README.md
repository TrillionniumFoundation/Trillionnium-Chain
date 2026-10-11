# Bounded coverage-guided development fuzzing

This independent Cargo workspace instruments the actual protocol, work and explicit research state libraries
with LLVM libFuzzer and AddressSanitizer. Its lockfile preserves the versions shared
with the ordinary native workspace; the repository checker rejects silent dependency
drift. Fuzz tooling is not a dependency of the 25-package normal workspace.

The pinned tool installer and runner are:

```bash
bash scripts/ci/install_ci_tools.sh fuzz
python3 scripts/ci/run_fuzz_smoke.py
```

Run from the repository root with an isolated `CARGO_HOME`, `CARGO_TARGET_DIR`,
`TRNM_CI_TOOL_ROOT` and a fresh `TRNM_CI_RECEIPT_DIR`. The runner defaults to
60 seconds of mutations per target after compilation. A local `--seconds N` or
`--target canonical_wire` is an explicitly narrower observation. Every invocation
requires a new receipt directory; a prior corpus or failed log is never overwritten.

- `canonical_wire` sends mutated complete inputs to the real Header, Envelope,
  QualifiedWorkTask and SignedQualifiedWorkTask decoders. Every accepted object
  must encode to the exact original bytes, including canonical length and ordering.
- `work_certificate` compares the production, independent scalar and explicit
  limb work verifiers on raw mutated certificates. It still binds the expected
  task to supplied matrices where possible. Every input also supplies at most
  four control bytes to a separate mutation of the retained valid certificate:
  exact-ticket acceptance, predecessor-target rejection, task/challenge mismatch,
  canonical-field product mutation, transcript mutation, arbitrary checkpoint
  cancellation and cancellation immediately before constructing `VerifiedWork`.
  This second arm reaches late rejection without discovering a new transcript
  preimage; it never replaces raw decoding or performs producer work. All three
  kernels must agree on the complete progress sequence, typed cancellation index,
  relation error and successful challenge/task/ticket/product. The shared helper
  is also exercised by `trnm-pon-node/tests/work_fuzz_semantics.rs` in the ordinary
  native test lane and is included in the fuzz source receipt. Fixed regressions
  do not establish mutation execution, and finite fuzzing does not prove hardness.

- `authenticated_state` constructs bounded synthetic complete states and in-memory
  account archives from mutation descriptors. A separate bottom-up sparse-root
  implementation and hand-applied expiry/maturity/reward rules check full native
  execution, all three commitment phases, balances, retained nonces and present-null
  rows. Mutations also exercise rehashed false aggregates, missing/duplicate/altered
  proofs, omitted or reordered partitions, changed parent bytes, strict AAW1/AAM1
  bytes and cancellation. The compact branch directly constructs and executes
  AAM1 proofs, compares all three commitment phases with the separate full-state
  relation, and checks that no expanded individual witnesses were allocated.
  The monetary-range branch anchors an actual complete parent and exercises all
  four prefixes, including future and zero-valued obligations. Sixteen retained
  mutation descriptors cover valid inputs, omission, rank/key/value/order,
  frontier/content/context, JSON encoding and cancellation. Successful range
  execution must equal the complete reference State and monetary projection.
  It does not mine blocks, validate signed transactions, reopen
  persistent databases or establish coverage of every application transaction kind.

The runner copies retained vectors into a separate mutable corpus, records their
hashes, and preserves generated inputs, crash artifacts, sanitizer logs and final
libFuzzer counters. Success requires actual coverage instrumentation and more
executed units than the seed corpus. Limits include maximum input length, a
10-second single-input timeout, 2 GiB RSS and a bounded process lifetime. Timeouts,
crashes, verifier disagreement, missing instrumentation and changed lockfiles fail.

Normal head checks and the separate prospective-merge matrix execute these targets.
The merge identity check binds both event parents before running the same five lanes.
Neither an identity check nor a finite fuzz run grants public-network qualification.

Primary tooling references: [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz/ci.html),
[cargo-fuzz 0.13.2](https://github.com/rust-fuzz/cargo-fuzz/releases/tag/0.13.2),
[libfuzzer-sys](https://docs.rs/libfuzzer-sys/0.4.10/libfuzzer_sys/).
