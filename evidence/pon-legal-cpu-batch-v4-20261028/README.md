# Legal CPU batch V4: local source checks

This is the source-check record for the new explicit CPU batch experiment. The
original V3 driver and its real x86-64/ARM measurements remain unchanged. V4 adds
actual 1/2/4-thread generation, one non-overlapping process-clock interval for
each batch, and archived winning packet bytes. It does not change W1, targets,
native Node admission, consensus, the 240-second campaign or 250-second capture.

## Observed local results

`local-checks.json` records the actual command, exit code, duration and raw-log
SHA-256 for every check. The reader's eight controls passed. They use synthetic
reports and payloads to test accounting and file checks; they are not native
mining results. All 34 retained source-integrity controls passed. Full-workspace
formatting and the distributed inventory check passed. The locked offline Cargo
graph resolved 26 workspace members and 173 packages.

The first formatting check of the draft failed and printed a formatting diff in
the session. Running the original workspace formatter corrected it; the retained
`fmt.log` and exit status refer to the subsequent successful check. This record
does not claim that the original draft passed.

The full repository checker returned **2**, with the inherited sparse-checkout
missing link `docs/README.md -> ../evidence/pon-v1/README.md`. Its actual failure
is retained in `repository.log`. A separate local check verifies new Markdown
targets against the Git index. Complete-source hosted CI must still run the
unchanged repository checker before native execution.

Native compilation, strict Clippy and the actual V4 campaign were **NOT RUN**
locally. No V4 timing or throughput result is asserted by these local checks.
The exact-source workflow must build and execute on both actual architectures,
retain the executable and all packet payloads, verify source before/after, and
run the independent reader to earn a native result.

## Source and reproduction

- [Experiment](../../docs/protocol/pon-nakamoto-v1/details/LEGAL_CPU_BATCH_COST_V4.md)
- [Native driver](../../trillionnium/crates/trnm-pon-node/examples/pon_legal_ticket_batch_v4.rs)
- [Hosted workflow](../../.github/workflows/pon-legal-ticket-batch-v4.yml)
- [Independent reader](../../scripts/ci/check_legal_ticket_batch_v4.py)
- [Reader controls](../../scripts/ci/test_legal_ticket_batch_v4.py)

Distinct first admissions in fresh stores are the denominator. Paired repetitions
are not distinct live-chain rewards. Full costs include failed attempts, shared
preparation, native verification/admission, ordinary cold recovery, exact byte
readback and a separately identified archive-I/O phase. GPU, ASIC, energy,
exclusive hardware and global optimality remain unmeasured.
