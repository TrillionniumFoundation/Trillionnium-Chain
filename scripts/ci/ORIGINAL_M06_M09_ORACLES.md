# Original M06 and M09 reference provisioning

This standalone step is intended to run after the existing General
`original-rust-build.jsonl` / `original-rust-values` Cargo build and its
locked fetch, before unittest discovery (the decorators read environment
at import). It does not change a workflow, shard or test acceptance.

```bash
python3 -B -m scripts.ci.prepare_original_m06_m09_oracles \
  --general-cargo-events "$RUNNER_TEMP/original-rust-build.jsonl" \
  --general-target "$RUNNER_TEMP/original-rust-values" \
  --output "$RUNNER_TEMP/m06-m09-original-oracles" \
  --github-env "$GITHUB_ENV"
```

M06 consumes only the actual existing General Cargo success and
compiler-artifact events plus the checkpointed native target paths. It
binds the exact sole `serde_json 1.0.149` ordinary `default,std` and
`hex 0.4.3` default profile, actual `serde_core`, `itoa`, `memchr` and
`zmij` linkage, the original workspace lock/archive checksums and the
pinned rustc native target evidence. Nothing is rebuilt for M06.
`HIA_M06_LOCKED_CARGO_ORACLE=1` is insufficient for the named caller,
selector or projector; the prebuilt target is required.

On Linux, the General workspace build unifies trnm-protocol's feature
`sha2/asm` into SHA2 0.10.9. It cannot be reused for M09, whose existing
reference strictly requires `default,std`. A separate SHA2-only dependency
carrier uses the unchanged original workspace lock identities and active
transitive graph (retaining the target-specific locked libc edge),
without the optional `sha2-asm` feature. This is a small separate regular
Cargo `--offline --locked` build, not a rebuild of the original workspace
or an oracle with substitute algorithms. The existing M09 verifier
rechecks the live linkage/fingerprints and toolchain. Both consumer suites
still compile and run their existing original Rust references.

Only after both profiles validate does this write the two actual paths
to the job environment. Retain `report.json`, the Cargo stdout/stderr and
the projected Cargo.lock with the existing exact-source CI evidence.
Leave `--require-rust-oracle`, SKIP detection, all execution budgets,
source binding and stock test methods unchanged. A normal exact-source
hosted General run must still prove that the new preparation and all
original methods execute.
