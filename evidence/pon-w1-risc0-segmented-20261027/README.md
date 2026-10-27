# Complete W1 proving: preserved failure and bounded successor controls

The exact original CI attempt is permanently retained in
[`original-attempt.json`](original-attempt.json) and its
[unchanged ZIP](original-d961-run40482711995-attempt1.zip). The 256,973-byte ZIP
SHA-256 is `faf9159385f77d02f1c01b493a04195092d82d7242d6c6250990c1af008dddb9`.
The manifest inventories all 47 original files, including the real full guest,
input, compiler/build observations, execution and failed prove phase. It has
no receipt, independent verification, audit or checked-proof result.

Original run 40482711995 attempt 1 used source
`d96138532b656d767d1ef46f6db86e7effae485e`. Complete actual guest execution matched
the native journal with 13,364,385 user cycles and 62 segments at po2 limit 18.
Actual proving timed out after 5,400.001653586 seconds. Its v1 wrapper omitted
reliable orphan-r0vm reaping, so its small recorded CPU/RSS cannot be treated as
real prover resource use. Its stall/failure root cause is **UNKNOWN**. The build
already used the official SHA-256 syscall patch and the complete relation's
bounded pseudo-Mersenne reduction. These observations do not establish a proof,
work hardness, a usable public verifier or quantum security.

The subsequent upstream four-thread attempt on exact `9e05ad5d` also timed out
after 5,400.004265402 seconds with no receipt. Its complete original 54-file ZIP,
source checks, substantial sampled CPU use and skipped verification/attack
steps are retained separately in the [9e05 observation](upstream-9e05/README.md).
The original attempt is terminal before the bounded segmented successor is
published; it is not cancelled or overlapped with another full proof run.

## Real small controls, with their original source scopes

`earlier-controls-001/` retains five actual process-cleanup controls and six
explicit receipt-policy metadata controls, their raw logs and source hashes.
Its original-wrapper RED demonstrates a parent returning zero while leaving a
live child; that control's supervisor subsequently terminated and reaped the
child. Policy fixture bytes are explicitly not cryptographic receipts.

`controls/` retains the first four actual scheduler process/resource controls.
They exercised a worker's real nonzero exit, cancellation with terminal output,
real per-worker timeout/SIGKILL, cgroup ancestry and refusal of unknown/insufficient
resource limits. The precise Python source bytes used by that earlier run are
under `controls/sources/`; this observation predates the sampling fix below.

`namespace-control/original-red.json` and `original_process_samples.py` retain
the independent reviewer's real PID-namespace failure. Local PID/group 9 appeared
as group 206283 through the mounted proc filesystem. The old sampler falsely
reported no process and zero RSS. That diagnostic bug does not change the
signal/wait ownership used by the separate process wrapper.

`namespace-control/fixed-green.json` is the new real owned-session observation.
The corrected sampler verifies local/proc-visible NSpid and NSpgid mappings and
requires the live caller to appear. Missing, inconsistent or empty sampling now
produces UNKNOWN and null RSS. It never uses proc-visible IDs for kill or wait.
`controls-002/` retains six successor controls, including that actual namespace
path and missing-map refusal, plus fresh five-process and six-policy controls
against the current exact helper-file hashes (17 controls in total). Both runs explicitly identify an uncommitted source
snapshot by file SHA-256; they are not exact-head native Rust build results.

All these controls are small subprocess/metadata observations. They generate
no mock successful proof and do not replace a real complete Composite receipt.
The successor host's locked build, strict Clippy, SDK-shape/negative checks and
one full 3,600-second proving attempt must run on the frozen CI source. Its
fixed guest, parameters, two-worker schedule and refusal conditions are
documented in the [research owner](../../trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/README.md).

No signing keys, user credentials or secret inputs are included. The retained
PWG1 fixture is the original public all-`ff` research target and synthetic
context, not a production-eligible block or a neural-benefit observation.

The root review of this successor passed source inventory, CI contract, changed
Markdown target existence, staged preflight and diff checks. The full repository
checker remains failed in this sparse checkout because the historical
`docs/README.md` link to `evidence/pon-v1/README.md` is not materialized. Its exact
[exit record](root-review/repository-result.json) and raw streams are retained;
the focused checks do not substitute for a complete-checkout repository gate.
