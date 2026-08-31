# G1-R2A evidence requirements v1

Required evidence before review promotion:

```text
exact source commit/tree
exact G1-R1 parent commit/tree
Rust toolchain and Cargo.lock hash
rustfmt output and exit code
focused unit-test output and count
strict Clippy output and exit code
parent G1-R1 gate output
canonical-plan and pre-cutover truth outputs
retained crash/failure artifacts
independent reviewer replay
```

A skipped workflow is recorded as `not-run`, never as success.
