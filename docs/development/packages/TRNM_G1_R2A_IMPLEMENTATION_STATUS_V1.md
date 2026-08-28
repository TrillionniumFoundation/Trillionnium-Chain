# G1-R2A implementation status v1

Status: `candidate-implemented-unverified`

Implemented candidate surfaces:

- exact replay target/input/predecessor/idempotency binding;
- pending-before-Core durable ordering;
- one unresolved target per coordinator root;
- sealed Core authority and non-public Core receipt construction;
- G1-R1 publication recovery and acknowledgement consumption;
- completion publication and exact pending-residue reconciliation;
- candidate failure-matrix tests;
- dedicated gate and trusted-runner workflow.

Not implemented or not proven:

- real Core adapter;
- real SafetyState/Core durable revision extraction;
- atomicity with Core;
- default-node/process integration;
- process/SIGKILL evidence;
- external anti-rollback;
- authorized Rust/Cargo/rustfmt/Clippy execution;
- independent review;
- any production or activation condition.
