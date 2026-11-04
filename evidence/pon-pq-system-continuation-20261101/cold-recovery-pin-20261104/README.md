# Native cold-recovery checkpoint controls — 2026-11-04

Status: **component evidence only; HOLD_NO_GO**. All system, financial-effect,
physical-monotonic-root and business-performance qualification flags remain false.
The [machine-readable summary](summary.json) preserves failed observations and
exact test names. This evidence does not turn a caller-supplied checkpoint into
an independently administered root.

## Source and scope

Runtime/docs commit: `618d1bd225db4df8fb7c1d0fc53af991d7f7fdf7`.
Parent candidate: `6f458c4fbf07a0a44d7d7a6f451aa960c1b0a029`.
The seven-file runtime change requires an explicit independently retained
checkpoint for `DurableWitness::open_existing`, updates all retained callers,
and imports the retained admission transaction plus its two native controls
from #698 (`5a5ddbd4577207af7f7771a4a50c76620f32940f`). Cargo manifests and the
lockfile were not edited by this change.

The test checkout used the committed runtime source plus the transparent
[local derived overlay](local-derived-overlay.patch): four added selectors,
47-control registry count and refreshed source hashes. The integration owner
must derive these files for the final composed candidate. These local results
do not certify a later composed commit.

## Actual results

| Observation | Result | Receipt |
| --- | --- | --- |
| Native witness/store filter | 52 passed, 3 failed before independent child readiness | [native run](runs/pq-recovery-pin-native-1/result.json) |
| Five retained live-admission controls | 5 passed | [admission run](runs/pq-recovery-pin-live-admission-1/result.json) |
| Exact 47 required selectors across those two runs | 46 passed, 1 blocked; no missing selector | [registry](tested-required-registry.json) and [summary](summary.json) |
| Exact legacy cold-open method against new rollback control | Expected failure: legacy method accepts the old coherent SQLite image | [red receipt](runs/pq-recovery-legacy-cold-open-red-1/result.json) |
| Exact legacy method against invalid-checkpoint control | Expected failure: `IO: No such file or directory` instead of `PQ_WITNESS_CHECKPOINT` | [red receipt](runs/pq-recovery-legacy-invalid-checkpoint-red-1/result.json) |
| Fixed rollback control, rerun after the red control | Passed | [green receipt](runs/pq-recovery-fixed-cold-open-green-2/result.json) |
| Fixed invalid-checkpoint control, rerun after the red control | Passed | [green receipt](runs/pq-recovery-fixed-invalid-checkpoint-green-2/result.json) |
| Negative source-integrity unit suite, with local derived overlay | 34 passed | [integrity receipt](runs/pq-recovery-pin-source-integrity-1/result.json) |
| Locked, offline Cargo graph | Exit 0 | [graph receipt](runs/pq-recovery-locked-graph-1/result.json) |
| Node all-targets/all-features strict Clippy | Exit 0 with `-D warnings` | [Clippy receipt](runs/pq-recovery-final-clippy-1/result.json) |
| Node formatting check | Exit 0 | [format receipt](runs/pq-recovery-final-fmt-1/result.json) |

The 52 + 5 raw pass counts include diagnostic controls and a child harness;
they must not replace the 46/47 meaningful-control count. All three failed
combined tests reached `UnixListener::bind` in the independent child and received
`EPERM (Operation not permitted)`, before business execution. One is mandatory:
`guarded_npq6_submit_recovers_after_invalid_signature_and_independent_process_restart`.
The two additional blocked tests are listed verbatim in the summary. Their raw
stdout and stderr are preserved losslessly as deterministic `.log.gz` files
beside each receipt. Hashes and byte counts in each result refer to decompressed
original bytes. None is reported as a pass.

One attempt to request sandbox escalation was automatically rejected because
`sandbox_approval=false` prohibits `require_escalated`. There was no retry and
no socket, crypto, assertion, budget or deadline bypass. The existing native CI
with Unix socket capability must execute the original combined tests on the
final integrated source. This evidence does not claim that CI has run.

## Before/after control method

The [provenance](provenance.json) identifies the legacy method, source files and
both actual test binary hashes. The [adapter patch](legacy-signature-adapter.patch)
replaces only the fixed `open_existing` method with its exact parent body plus
an ignored `_expected: Checkpoint` argument so the unchanged new tests compile.
It retains native OpenSSL ML-DSA-65, real SQLite transitions, deadlines and all
other code. This demonstrates the specific pre-fix method weakness; it is not
a historical whole-tree acceptance run.

Apply that adapter only in an isolated checkout of the runtime commit to repeat
the two exact selectors. The two controls should fail there. On the unmodified
fixed runtime source they pass. The temporary adapter was removed byte-for-byte
before final Clippy and formatting; it is never part of the integration patch.

The fixed native test binary SHA-256 is
`9359584045d3698f8efe404ec6b99b2ae88c543b30a1537c385b444c58316835`.
The legacy-adapter binary SHA-256 is
`e3789e525ad4c1b3e0acc50442b927c36ee751ec30cbae53a8ce206bffd0b25a`.
Binaries are not committed; raw command arguments, outputs and hashes are.
Native runs used Rust/Cargo 1.95.0 and the existing pinned OpenSSL 3.5.9 setup;
[compiler output](runs/pq-recovery-compiler-1/stdout.log.gz) is retained.
Original business caps, including the 250 ms request deadline, were unchanged.

## Review and remaining work

The [seven-file review and effect-root audit](review.md) separates the fixed
cold-open failure from the unresolved complete-effect recovery and PQ migration
requirements. [Four mandatory selectors](mandatory-new-selectors.json) are
provided for the integration owner. The sole development plan remains
[TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN](../../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
