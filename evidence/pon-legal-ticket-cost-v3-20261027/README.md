# First legal native ticket cost successor

The source descends from published solver evidence `c59b5ddc4c37a56a0b7f814eabb5805afbab4a5b`.
The [experiment definition](../../docs/protocol/pon-nakamoto-v1/details/LEGAL_TICKET_FIRST_ADMISSION_COST_V3.md)
explains exact denominators, preparation/reuse, failed searches, first native
admission, original cold recovery and byte readback. No production code or
consensus semantics change. No new invalid-transcript/adversarial solver
experiment is added.

Eight actual local Python reader controls pass. They are synthetic accounting
fixtures and do not execute a miner. Matched 26-package locked metadata,
formatting, source-integrity tests and workflow source checks are retained with
their actual exit codes in this directory. The local checkout omits historical
evidence, so its whole Markdown/source checker preserves the inherited
missing-evidence failure; it is not a full-source-qualified checkout. Native
build, strict Clippy, x86_64/ARM campaign and cost advantages remain **NOT_RUN**
at source freeze. CI requires a full exact source checkout and may only report
measured completed observations.

The first formatting check refused a Rust 2024-only let-chain. The correction
keeps the original Rust 2021 edition and uses `Option::is_some_and`; full
formatting then passed. The original refusal and corrected receipt both remain.

The first actual hosted [run 40609116618](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40609116618)
on source `409cc73ac01d74e0ca14c010df40a154b926e2e4` failed on both architectures
at the full repository link check, before native compilation. Three new
relative links ascended one directory too far. The successor corrects those
links and explicitly checks every link in the two new documents. The original
full job logs are retained. No Rust source, algorithm, workload, runtime budget,
test assertion or source checker changes for this repair.
