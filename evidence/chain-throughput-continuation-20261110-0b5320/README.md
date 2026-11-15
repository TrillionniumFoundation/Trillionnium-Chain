# Throughput budget and pool reconciliation continuation

## Delivery boundary

This continuation preserves the unpushed History writer-handoff and ordinary
pool-run fixes from `85a905b9e47cea0d76144253abb4a483b58bc2be`, then closes a
further original-run control gap in retained-pool reconciliation. It continues
PR #895 and does not change PQ command limits, block timing, paid CPU rules,
Host sampling sites, confirmation criteria, consensus rules or activation.

| Source | Role |
| --- | --- |
| `7d6567b92575d1d84766afd49d0720b6f197b0e0` | Last observed PR #895 head and the original campaign actually measured |
| `89fb2269b0dd306fbd32c36f464842c3d7daee2b` | Earlier budget production with identical revised History/mining controls |
| `db93026b9314bfd8bc4350945036998f1b7d34aa` | Earlier ordinary-pool production with identical existing run controls |
| `84e68b4f7a9b2f48f9c47ed05c9a44229d186e30` | Same old ordinary-pool production, correcting only the test injector's schema cleanup; active `pool-before-v2` subject |
| `85a905b9e47cea0d76144253abb4a483b58bc2be` | Preserved History writer and ordinary-pool implementation |
| `ae657e262278ae4a058220f66a6a0495721eb9ad` | Same prior production, adding only observation hooks and the two new pool-scan tests |
| `5ec9b4490fbfd22df4527e3b75ec74d6986572cf` | Corrected reconciliation scan; identical new test bytes |
| `36f803033ca342a966fe6a8c6d5bf8b68355b5b9` | Same production, correcting the durability fixture's auxiliary-table cleanup |

Native results are retained separately from this source-maintenance delivery.
Until a corresponding original native receipt exists, no code or Python-reader
pass is counted as a native component pass or a complete business confirmation.

The [first native readback and fixture correction](NATIVE_EXECUTION.md) preserve
the actual `5ec9b449` result of **20/21 targeted controls**, including the original
positive durability test's cold-open `SCHEMA` failure. The fixture left its own
SQL counter table behind. The correction removes that table with its trigger;
every packet, nonce, active-state and cold-reopen assertion and the original
deadline remain. Corrected native success requires a new execution.

On the unchanged `ae657e26` old reconciliation source, both new native controls
actually exited 101 at the exact row-count assertion (`6` versus `2`). A frozen
reader independently matched both transcripts. The ad hoc job wrapper still
has its original failed outcome because its own summary regex was overescaped;
that wrapper failure is retained, not reclassified. Each old test stops in its
first Legacy/initial-batch case, while each passing fixed scan test covers four
cases. Neither count is a complete service campaign.

## What changes

The preserved shared-History patch waits for headroom from the same paid CPU
account before taking the Node writer again. It keeps the original deadline,
reserves, measured debits, cancellation and refusal behavior, and does not wait
while holding the writer. The existing native controls test actual W1 debt,
refill, cancellation, expiry, original settlement and cold reopen.

The new reconciliation patch passes only the ordinary miner's original
lightweight run fence through retained pool-row decoding, permission checks,
classification and the returned snapshot. Existing public-owner callers retain
their previous wrapper and Host observations. Two new tests queue six real
signed transfers and stop or expire the actual run after its second retained
row. Each covers both state backends and both initial batch/post-search
reconciliation; assertions compare queue, active state, nonce and cold reopen.
The preceding test-only source must expose six decoded rows where two were
required. Signals, compilation failures, unrelated panics and other assertion
sites cannot satisfy that negative control.

The existing native component workflow now keeps four source lanes separate:
`budget-before-v2`, `pool-before-v2`, `pool-scan-before`, and fixed current head.
Its fixed roster contains 21 named library controls plus the original ten pool
integration tests and their actual CLI. The old groups compare only their own
identical input files and unchanged common Cargo/toolchain inputs. The
[reader review](reader-review.json) retains a separately discovered false-pass
case and its fix: a renamed or extra unrelated panic is rejected by the old
budget reader as well as the newer pool readers.

## Original business campaign still fails

The [exact artifact identity](original-campaign-identity.json) and
[exclusive History findings](EXCLUSIVE_HISTORY_FINDINGS.md) concern the already
executed `7d6567b9` campaign: **0/3 campaigns, 0/9 phases, 3/27 timely scheduled
confirmation rounds**, with one distinct timely transaction identity. All 84
honest submissions received acknowledgments and matching receiver acceptance.
All nine phases ended with a client History deadline failure. The campaign
uses the exclusive owner path, outside the shared-writer repair.

The evidence concentrates the next investigation on authenticated account-graph
readback and fresh Host checks. It does not authorize skipping checks or caching
successful Host verdicts. A narrow no-account-change graph-reuse proposal remains
unimplemented and needs the negative matrix in the findings report. The
relationship between the quarter-core Host quota, scalar refill and required
actual-depletion predicate is a separate reachability question, not a proved
impossibility or an excuse to relax the original campaign.

## Source maintenance and retained failures

The [curated source review](source-binding-review.json) keeps the 15-path
lifetime and 44-path authority maps at their declared scope, without claiming
full dependency coverage. The [corpus review](corpus-rebinding.json) retains all
prior paths and provenance and adds the reviewed native control inputs. The
embedded source inventory includes the new Rust files. Original budget,
activation and qualification fields remain unchanged.

Prior unpushed native-component binaries, original failed runs, pre-close
accounting review, source controls and incomplete local compiler observations
remain under the [preceding evidence directory](../chain-throughput-budget-20261110-065438/README.md).
The [local preparation record](preparation-observations.json) distinguishes
invocation mistakes from failed native behavior. Native test data, current
source checks, hosted CI and whole-service acceptance remain separate scopes.
