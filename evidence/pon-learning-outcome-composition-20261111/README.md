# PoN and Hepta outcome composition

Engineering continuation dated 2026-11-11 America/New_York. Native observations
below were recorded on 2026-11-12 UTC. Production qualification remains
`HOLD_NO_GO`; no protected-main merge or activation belongs to this change.

## Source identities

| Component | Exact source |
| --- | --- |
| Chain work and storage continuation, #907 | `58f225e973054f69661bf06aeda936f9126ea8e1` |
| Existing HEPLCP04 structural reader, #909 | `e338c000f26e9357ed33213624da787a3a009ed9` |
| Ordinary merge of those two sources | `b50519f29de609fd4a0f50445c01ee53492178ff` |
| Chain implementation and first native controls, C1 | `c2d67c5cf1ebb4caac525802362d5746b8fd957d` |
| C1 tree | `40796fa1aac9fa78b5a69647ea952cdb4f67663c` |
| Hepta original actor exports and trainer controls | `93fc43f6e87c4514485adcb01a7ffec8ad3b632f` |
| Hepta tree | `1de575fdbba23d25c483f539a15b455c9e8859cb` |

The #909 reader already understood structural local decisions. The new
[completed-use profile](../../docs/development/specs/pon/CELL_LOCAL_DECISION_COMPLETED_USE_V1.md)
adds the composition with original completed actor observations. The new
[proposal-retention operation](../../docs/development/specs/pon/CELL_PROPOSAL_RETENTION_V1.md)
binds the separately reviewed proposal to the unchanged TCA1 Retain(parent)
event. This does not reinterpret a local decision as training NoUpdate.

## Behaviours under test

| Distinct question | Concrete behaviour and observation |
| --- | --- |
| Can valid work have no model benefit? | The native role test admits and activates 76 W1 blocks, including empty blocks without model publication. Subsidies belong to the miner. Existing fixed-material controls keep one product/output meter across different challenges and reject an old proof under a new challenge. |
| Can real training correctly finish with NoUpdate? | The selected Hepta tests run actual Q24 SGD and the original training owner, preserve unchanged quantized weights, and recover Candidate and NoUpdate outcomes. These are controlled engineering training cases, not independent future-task benefit measurements. |
| Can a qualified candidate be deferred or retained? | Thirteen CLI controls include three distinct local owners choosing Adopt, Defer and Retain for the same proposal, with actual selected-cache readback and cold recovery. Three original Hepta local-decision exports complete use of either candidate or parent without rewriting Evaluation/Proposal to NoUpdate. |
| Must author, miner and service provider be the same account? | One native chain uses miner 0, provider 1, payer 2 and author 3. A completed NoGain service credits 2,000 to the provider; a matured model allocation credits 10,000 to the author. Wrong recipients and duplicate claims/payments are refused. |

The last row uses controlled score attestations, output digests and resource
records. It does not run an optimizer or an independent evaluator. The amounts
are the service credit and model allocation, not net account gains after fees.
The author does not need a miner or storage-provider role to use the tested
contribution/claim path.

## Retained observations

### C1 native controls

The [original C1 archive](native-c1/ARCHIVE_MANIFEST.json) preserves all 21
command records, stdout/stderr, exact source checks, versions and the locked
graph. All 21 original commands returned zero without timeout. The actual
harnesses report 25 adoption-library tests, 13 adoption-CLI tests and one
role/payment test passed, with no failed or ignored tests in those selections.

The original source-integrity and project-boundary negative controls report
43 and 16 passing tests. Full workspace formatting, locked metadata and the
complete repository/Markdown-link check passed on the full desktop checkout.
The original strict Clippy scope was the DA library/adoption CLI/CLI integration
and the Node role integration; this is not a full-workspace Clippy claim.

The first archive attempt then inspected a shared target after a separate
direct-Cargo run had created an unqualified build unit. That overly broad
target scan refused. Its actual failing output and both later target units are
preserved. A later target listing cannot authenticate the original build unit.

### Fixed-material controls and a refused build qualification

The [first fixed-task archive](fixed-task-c1-attempt1/ARCHIVE_MANIFEST.json)
retains three actual one-test passes: fixed product/meter identity, one durable
output across fresh challenges, and old-proof refusal under a changed
challenge/task. The runner correctly reports overall `FAIL` because the Node
command's direct Cargo entry omitted the toolchain base library directory from
the normal loader environment. The original SQLite build fence refused that
environment. Neither an exit-zero command nor a passing test overrides it.

The final source must use the existing Rustup Cargo entry, absolute real
RUSTC/RUSTDOC, and the original unmodified build fence. Its Cargo JSON
`build-script-executed` records must bind the witness and build-fence value to
the actual invocation, rather than collecting unrelated target directories.
No loader path or qualification cfg is injected.

### Original Hepta bytes and Python composition controls

The original selected Hepta command passed seven tests on clean source
`93fc43f6`. The 1,035 other nextest entries were excluded by the expression;
they are not additional passing tests. The original log is 235,411 bytes with
SHA-256 `3e7ee2dcd9019949256a2987a3c8612d976952a58503d7050198adaab11a5261`.

The [original local-use corpus](../heplcp04-completed-use-20261111/native-readbacks/fixture-manifest.json)
retains 32 files and exact stdout byte offsets/lengths/hashes for the initial,
Selection, completed checkpoint and use export of each local choice. The freeze
is derived only from the original initial HEPLCP02 bytes. The later local-choice
cuts are HEPLCP04; old HEPLCP02 pending cases are not relabelled as local choices.

The first new-reader run passed 19 tests after capture, on the uncommitted C2
changes over C1. Its validation record states that limit explicitly. It also
preserves the earlier genuine missing-fixture failure. Final committed-source
qualification is a separate observation; this preliminary result is not
relabelled as an exact final-head run.

All three local fixtures use empty output deltas. No pending work or delivery
proves a clear pending state, not an explicit output ACK event.
`completed_use_observed` and `pending_work_and_delivery_clear` can be true;
`output_ack_event_verified` stays false. Pending-state negative controls are
explicit mutations, not invented native pre-ACK exports.

### Earlier cloud attempts

The [original cloud archive](cloud-observations/ARCHIVE_MANIFEST.json) retains the
locked-offline missing-rustix exit 101, the later owned-build interruption exit
130 near the low-disk threshold, and the original absolute-RUSTC qualification
warning. The local sparse-checkout Markdown failure is also retained. Those
attempts did not execute the new role test. Their positive isolated negative
controls do not certify the sparse checkout as a complete source tree.

The cloud environment temporarily became unavailable during integration and
then recovered. Original bytes were re-read and their original checksum
manifest was verified; the failure observations are not reconstructed prose
substitutes for the raw logs.

## Authority and completion limits

- New nonces do not manufacture distinct model knowledge. Arithmetic-output
  accounting, consensus work validity and measured model benefit remain separate.
- A qualified local Defer/Retain keeps `evaluation_disposition=qualified`,
  `proposal_disposition=update_candidates` and `no_update=false`.
- Typed proposal retention requires the original full request for cold retry.
  Its stored hash cannot reconstruct that request or attest that the typed
  validator was the historical entry point.
- Hepta bundle digests and TCV1 commitments remain separate identities. This
  reader does not authenticate their content mapping or grant a local owner
  permission to install/consume a version.
- These controlled actor exports do not establish independently operated B/C,
  ordinary daemon assembly, complete costs, full-state recovery or ordinary
  end-to-end learning acceptance.
- `DENY_ALL`, `NOT_EXPORTED` and `HOLD_NO_GO` remain. Source and component
  tests do not certify model efficacy, current payment authority, public
  security qualification or production activation.

## Raw evidence representation

The first C2 staging attempt refused original command-stream blank lines and
terminal CRLF under Git whitespace checks. Its original failure output is
retained in `commit-preparation/`. Evidence-local Git attributes preserve the
original stdout, stderr and log bytes; each staged blob is checked against its
original file. Source-code whitespace checks remain unchanged.
