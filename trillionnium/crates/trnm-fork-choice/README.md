# trnm-fork-choice

Owner: M02. Pure PoN branch-choice candidate; no node, network or consensus activation.

This crate selects among caller-supplied persisted, fully validated branch tips by
strictly greater cumulative required work. It does not decode blocks, verify work,
execute state, persist data or decide production readiness. Callers must obtain the
validation and availability facts from their owning M01/M06/M07/M09 components.

```bash
cargo test --locked -p trnm-fork-choice --all-targets --all-features
```
