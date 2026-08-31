# G1-R2A promotion blockers v1

Open blockers:

- G1-R1 has no authorized green clean-clone evidence;
- R2-A has no authorized Rust/rustfmt/Clippy execution;
- the sealed real Core adapter is absent;
- Core/SafetyState durable revision extraction is absent;
- whole-node predecessor CAS integration is absent;
- process/SIGKILL evidence is absent;
- external anti-rollback is absent;
- independent review is absent.

Therefore `g1_r2_exit`, `production_candidate` and activation remain false.
