# Native path audit for the time/credit continuation

Audited execution source: `bd696c35f8b838823fad7ccf2868582554f33559`.
This is a source-path inventory. Runtime coverage is separately recorded in
[the command log](validation-native-01/commands.json); an inventoried route is
not automatically a newly executed or production-qualified route.

## Current-clock entry points

| Path | Format and role | Current observation boundary |
| --- | --- | --- |
| [public Growth dispatch](../../trillionnium/crates/trnm-pon-node/src/ingress/public_v3/growth.rs) | PGH2 / PNP2 GrowthSubmitV1 | Parent ancestry before W1 and duplicate fast return; fresh request rechecks after W1 under the original owner. Original request deadline and CPU callback remain in force. |
| [Growth CLI](../../trillionnium/crates/trnm-pon-node/src/growth_cli.rs) | Current growth-mine, growth-submit, growth-activate | Uses observed-history/activation. Default wall clock is sampled at the relevant boundaries. Mining checks the parent again after proof construction. Explicit logical time remains fixed. |
| [generic Node interface](../../trillionnium/crates/trnm-pon-node/src/store.rs) | check_observed_history and activate_observed | Correctly dispatches the Growth namespace to its actual PGH2 header reader instead of a PNH1 projection. Other existing packet routes retain their own reader. |
| [Growth owner](../../trillionnium/crates/trnm-pon-node/src/store/growth/recovery.rs) | Retained PGH2 ancestor eligibility | Reads bounded header/trace projections and verifies ID/record linkage under the existing SQL epoch guard. It does not replay ancestor W1. The ancestry walk remains O(height). |

The existing public signed resource profile explicitly retains a noncancellable
paid postcommit activation tail. Its `submit_result -> activate` call is not
silently relabelled as a newly cancellable operation. Both new public gates
are before durable admission.

Current clock observations are discrete. A CLI command can construct a packet,
or admit historically valid bytes, before a later clock observation defers
activation. The generated artifact and retained history are preserved.

## Historical storage, recovery and construction

`Node::activate` is the historical atomic activation route. The Growth
dispatcher and cold recovery use it to restore retained, verified history.
That history and accumulated work are not recomputed using a rolled-back wall
clock. Opening a store can recover its historically best branch before a later
current-clock check refuses the requested operation.

`growth-make` constructs a packet; `growth-recover` explicitly requests
historical recovery. Lower-level `admit_growth` checks the candidate in the
native historical/current-input contract supplied by its caller; it does not
promise that the whole ancestry was newly observed at every physical instant.

Cold audit retains complete W1 validation. The new research prefix is not
used to skip original native cold audit, state execution or witness checking.

## Sync and History boundaries

The [Growth network option gate](../../trillionnium/crates/trnm-pon-node/src/main.rs)
allows its dedicated serve/push/packet-status/head interface. It rejects
sync, ordinary mining/pool options, peer lists and polling options for that
namespace. The Growth public profile admits only its dedicated operation
family; an unsupported operation is not redirected through a legacy codec.

The existing [History import](../../trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs)
accepts `Packet` and uses the observed activation/termination route.
The [peer polling path](../../trillionnium/crates/trnm-pon-node/src/peer_polling.rs)
also decodes that packet family. Neither is an implicit PGH2 History/sync
service. Their existence is not evidence that a future Growth importer has
already been covered.

The existing [mining owner](../../trillionnium/crates/trnm-pon-node/src/mining.rs)
and ordinary command routes use their original observed interfaces and packet
profiles. Current Growth commands must use the explicit Growth path above.

## Migration boundaries

[Authenticated migration](../../trillionnium/crates/trnm-pon-node/src/store/authenticated_migration.rs)
checks historical successor relations with the original target/time/W1 rules.
Growth-profile preparation and reservation bind the selected migration plan
and storage namespace; they are not a current-time consensus activation.

The [Growth rehearsal](../../trillionnium/crates/trnm-pon-node/src/store/authenticated_migration/growth_rehearsal.rs)
constructs read-only archive/checkpoint observations. It does not initialize
or recover a live Growth owner, sign or publish external work, or install C1
or MU1 as native consensus.

## What must accompany a future C1 or MU1 activation

The real native parameter, wire and stored-state identities must bind the
chosen rule. Required target/work must derive from the verified parent branch
and actual activation ancestor. Mining, all accepted ingress/import paths,
duplicate handling, fork selection, recovery and migration must use the same
new rule at their proper historical/current boundaries.

A production reusable context must be published by the original Node commit
owner and invalidated coherently across foreign epochs, reorg and reopen.
The in-memory incremental research context supplies none of that storage
authority. Its complete-W1 append also does not establish application State,
task authorization, physical cost or quantum resource credit.

Those obligations, lifetime inventory and shared quantum state, honest growth
and network/service composition remain open. This inventory supplies no
production activation or complete mixed-resource consensus theorem.
