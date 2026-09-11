# M08 Finality / Node Commit / Recovery technical specification v1

Status: **implementation contract; candidate only; semantic acceptance not assessed**

## Authority

Resolve `docs/architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md` first. Frozen
`bft-v0` defines votes and three-chain finality; `pcc1` defines a candidate
composition, not a new wire version. M08 coordinates ordered application commit,
finalized receipt publication and restart convergence. M02/M03 remain the sole
consensus/Safety authorities. M08 cannot choose a fork, create signing authority,
change validity, or replace a verified proof with a stage label.

## Interfaces

The interfaces below are operation requirements, not newly frozen Rust types,
wire tags or constructors. Bind each operation to the selected exact source
symbol and accepted schema before enabling it. The historical candidate
`Prepared` through `OutboundPublished` ledger labels are inert observations;
they are not one production lifecycle for both votes and finalized receipts.

The signing operation binds chain/validator identity, epoch/view/block, exact
SignIntent bytes, Safety decision/revision, generation and signer watermark.
The finalized-application operation separately binds the commissioned proof
context, expected oldest target and parent, pre/post application roots, prepared
execution plan, finality bytes, ledger sequence and checkpoint predecessor.
The strict candidate seam is `trnm-native-execution-v0/src/pcc1_finality.rs`;
its verified proof/target is necessary but is not full checkpoint or publisher
integration. Opaque caller digests and telemetry cannot construct capabilities.

## State machine

Signing and vote publication follow:

```text
Validated -> IntentDurable -> SignatureRecorded -> VotePublished
```

Finalized application and receipt publication follow:

```text
FinalityVerified -> CommitIntentDurable -> ApplicationApplied -> CommitRecorded -> CheckpointConfirmed -> ReceiptPublished
```

The signing path MUST NOT wait for the voted block to become final. Before
voting, execute and validate the complete payload into a prepared overlay under
its authenticated parent and exact runtime; an overlay is not canonical state.
M03 persists its authorized Safety decision and exact signing intent before
custody is invoked and records the exact signature before it escapes. Lost
acknowledgement permits only exact intent replay/readback, not a fresh vote.

The finalized path first admits a complete three-chain proof against the
application's commissioned context and the expected oldest target. A single QC,
a newest certified descendant, or a valid proof for another root is insufficient.
Only then may a durable commit intent authorize the exact idempotent application
apply. Record its durable result, confirm checkpoint predecessor/CAS and expose
the finalized receipt, in that order. Readback cannot promote prepared state.

Finality is applied in ancestor order. A child cannot skip an unacknowledged
ancestor. Duplicate requests return the same logical effect; a changed context,
generation, root, intent or predecessor rejects or fences the owner. The two
paths may interleave, but neither grants the other's capabilities. In
particular, vote publication is not receipt publication and a receipt retry
cannot authorize signing.

## Persistence and recovery

The ledger coordinates facts but does not overrule an independent Safety,
application, signer or checkpoint authority. Reopen each named authority and
resolve uncertainty to its exact source or exact target. Do not overwrite newer
Safety decisions from an older ledger projection. Ambiguous or conflicting
records fence dependent signing, commit and publication until resolved.

Crash cuts exist before/after intent durability, custody, signature recording,
vote publication, application apply, ledger result, checkpoint CAS and receipt
publication. HSM success with lost response, disk-full, fsync error, WAL/SHM
failure and owner takeover are uncertainty cases, not proof of no side effect.
Recovery uses fresh authoritative readback and preserves exact replay identity.
Separate durable stores are not a distributed atomic transaction merely because
a process test passes. Whole-store rollback requires an independent external
anchor and device-qualified custody; local hash chains are insufficient.

## Resource bounds

Bound proof bytes, total signature work (including failed verification), pending
commits, retained ancestry, record size, recovery scan, replay and rebuild work.
Compaction requires authenticated finalized history and retains every applicable
replay, evidence, slashing and weak-subjectivity horizon. Reaching a local work
limit yields unavailability or a fenced recovery, not deterministic peer guilt.
No resource default may turn incomplete history into an accepted checkpoint.

The native v0 snapshot audit borrows the owner's immutable JMT collections
through a private `TreeReader`. Iteration and each existence proof use the same
snapshot and expected root for the entire borrow. This removes a full historical
store clone from every audit while retaining verification of every live value,
preimage and proof. It does not prune history, change snapshot codec bytes, or
close the separate full-snapshot persistence and cumulative recovery-work gap.

## Security

Reject wrong proof class, chain, validator set, epoch, oldest target, root or
parent before modifying the authoritative application or ledger. Generation
regression, same-height conflicting roots, replaced namespaces and inconsistent
signer watermarks fence the operation. An external rollback anchor must be in a
different rollback domain; a local sidecar cannot certify its own history.
No fixture, optimizer, indexer or historical journal tag supplies finality.

## Observability and SLO

Report signing, ordering-finality, durable-receipt and settlement latencies
separately, with p50/p95/p99, fsync/HSM tails, pending depth, oldest pending age,
replay count, ambiguous-stop count and restart convergence. Only finalized,
replay-verified application transactions contribute to committed goodput.
Metrics describe operations; they cannot synthesize stage authority.

## Verification and evidence

Retain tests that permit votes before their own block's finality and prohibit
receipts before finality/checkpoint completion. Reject single-QC/newest-target
substitution and prepared-state promotion by a read. Exhaust independent crash
cuts and lost acknowledgements on both paths, ancestor reorder, exact replay,
corrupt records, coherent rollback, takeover and state-sync rejoin. Verify no
double-sign, conflicting finality or duplicated application effect, plus exact
post-restart roots. Process kills do not stand in for physical controller/cache
loss or HSM evidence. Structural documentation checks are not runtime proofs.

## Activation boundary

M08 remains candidate until the default node's real producers and consumers
implement both separate paths, arbitrary valid proposals/transactions, bounded
recovery and state-sync rejoin, and independently accepted device, physical-fault
and multi-host evidence is bound to the exact artifact. The local strict-finality
seam and persistent ingress bridge alone do not close these requirements.
