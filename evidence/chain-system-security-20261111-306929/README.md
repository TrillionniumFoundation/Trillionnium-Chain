# System security and incentive continuation

**HOLD / NO-GO. This is a review candidate above #908 C5.** It preserves the
original tested source commits and raw observations. It does not merge into
main, activate a production profile or certify whole-chain security.

## Implemented changes

The V5 witnessed Root owner now exposes a bounded historical provider-readback
route. The route authenticates live witness/local Root/anchor agreement around
the enrollment lookup and on both sides of the provider callback, enforces
provider/witness key separation, preserves the original operation and material,
and reuses pending/Unknown/no-redispatch semantics. It grants no effect authority.
The witness does not commit every provider-journal head. Cold provider-history
loss still requires the external system to reconcile that same operation.
See the [Root implementation and original observations](../pq-root-witness-provider-readback-20261112/README.md).

Five portable SQLite openers now reject every existing sidecar object,
including dangling symbolic links. Only an actual `NotFound` metadata result
permits the open to continue; other inspection errors fail closed. DA sidecar
names preserve the original OS path bytes, including non-UTF-8 names. The normal
WAL users outside these five previously strict openers keep their existing
contract. The change does not close the check/open race or demonstrate an
exploit of the bundled-SQLite advisory. See the [SQLite source and native evidence](../sqlite-open-boundary-20261112/README.md).

The incentive changes strengthen the existing full-roster commit/reveal
regression and retain a newly admitted V4 source-splitting counterexample.
They do not silently rewrite historical reward rules. See the
[incentive source, raw transcripts and independent checks](../chain-incentive-counterexamples-20261112/README.md).

## Completed observations, with their source scope

| Work | Actual observed result | Boundary |
| --- | --- | --- |
| Original service campaign readback | 0/3 campaigns, 0/9 phases, 3/27 timely confirmations; 41/47 native History imports | Original source `53e1b98a…`; readback is not a new native campaign. |
| SQLite rejected-input and retained compatibility controls | 17 focused + 15 retained passed at `9021d15…`; 10 actual old-source failures retained | The four owner binary identities/hashes and raw outputs are preserved. These original runs used a partial checkout with 297 selected source-file guards; the initial DA negative observation predates those guards. |
| Complete-roster evaluation | 8 native integration tests at `3b97b97…`, including 144 independent order/worker combinations and 12 missing-reviewer abort combinations | Finite fixture coverage; no universal economic-security claim. |
| Admitted V4 source split | The Node-genesis/continuous-M06 control at `8197606…` passed; original operation receipts and independent arithmetic/signature checks retained | Ordinary Node Submit, PNW1 verification and independent History are not covered. |
| Historical revision3 ordering | Two original native/reference controls passed while reproducing the `{10,100}` outcome set | Passing the counterexample does not repair the old rule. |
| Root source validation | Exact `b7ed54c…` static/source gates passed; original 60-method corpus run is separately scoped | The archived cloud attempts executed zero Root libtest cases. |

The [service report](liveness/README.md) separates ACKs, full-work observations,
History response/import, state equality and timely confirmation. It preserves
the failed no-attacker baseline and overlapping checkpoint/import CPU counters.
No accepted unmatched body was observed in that original archive; this is not
a universal cryptographic proof.

In the admitted split fixture, an already known source receives 66,666 units for
`(A, B)` and 96,551 for `(A + Z, -Z, B)`, while the full model and 100,000-unit
authorized budget stay the same. Its combined account increase after all fees
charged to its two fixture accounts rises from 60,051 to 86,865. Source caps remain
enforced. These are development-ledger amounts; real training/operating costs
and public economic security are not measured. A successor would need to
aggregate complete source increments before source-level omission/allocation,
with an explicit authorized payee policy and fresh protocol namespaces.

## Qualification still required

The original Root native attempts were interrupted or returned compiler
`SIGKILL`; no cause is asserted beyond the observed signal. The affected four
SQLite packages' strict Clippy observation also contains `SIGKILL` and lacks a
completed receipt. Those observations are retained. A new fixed-source run on
the independent Linux build host must establish the 17 + 12 + 8 Root V5 controls,
14 affected V4 provider controls, the combined candidate's 17 focused + 15
retained SQLite controls and retained incentive tests, strict Clippy and the complete source/graph/format/link gates. A planned or
compiled test is not counted as executed.

Independent surviving freshness authority, fresh recovery entropy, actual
external-effect reconciliation, ordinary M15/effect-sink assembly, service
completion under the original total resource bounds, unknown-controller
identification, prospective model benefit and long-term economic supply remain
separate unclosed obligations. The fixed 25-row saturation statement applies to
the retained V4 profile; the existing revision16/V5 task-window work does not by
itself qualify independent generalization.

## Provenance and preservation

The cloud executor temporarily became unavailable. All original source commits
and raw evidence were subsequently recovered and checked; the source-similar
SQLite reconstruction prepared during the interruption was never applied or
tested. Exact Root/incentive object recovery inputs were separately verified.
This candidate keeps the original tested ancestors instead of reassigning old
test outcomes to reconstructed source.

Two locally copied reader files initially contained one extra trailing LF.
The whitespace and raw Git-blob checks exposed the mismatch. The exact upstream
bytes were restored, the entire original ZIP was read again with byte-identical
output, and thirteen reader controls passed. The correction and preceding
checkpoint remain in [the reader provenance](liveness/reader-payloads.json).

Candidate dependency fixes remain distinct from main. At the retained readback,
main `dd6e1c3…` uses bundled `libsqlite3-sys 0.30.1`; #900 uses 0.39.1 and #901/C5
use 0.39.0. Both candidate versions meet the advisory's repaired version range.
#900's retained quality failure instead identifies `rustix 1.1.4` under
RUSTSEC-2026-0486; C5 already uses 1.1.6. None of these candidate observations
changes main's recorded dependency state.
