# Retained strict History baseline: no-attacker failure

This is a fresh readback on 2026-10-30 UTC of historical CI output from source
`540d72356a921da31dde1113537382e5c0f0c4fd`. It does not execute a new native
campaign, restore a lost local run, change production code, or qualify service.

The first depth-six confirmation in the original fixed-Host baseline completed
at **45.067188843 seconds**, outside the unchanged 30-second phase. There were
zero attack actors and zero overlapping attack calls. A new identity-admission
gate therefore cannot by itself close this observed failure.

## Retained provenance and reproduction

- Original [admission run 40932471590](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40932471590),
  x64 job `123654214772`, artifact `12924656581`.
- Original archive SHA-256:
  `0fdcd182ab9eb06f84c6cf3208f5cf8c138040dd80ed448d1b809d4da8cf1467`.
  The complete archive is not copied into this evidence directory.
- [provenance.json](provenance.json) binds 26 original entries, their exact
  decompressed and compressed sizes/hashes, and the original committed source
  files. Deterministic gzip retains the baseline and failing qualification,
  job/ready/report, all ten request/response pairs and the actual closed SQLite
  database. These entries are unchanged historical bytes.
- The 3,350,528-byte database SHA-256 is
  `4cbc2b9ec7cbcb0be9a8684d7e81d9b4eb37aaba1c2d6e49bbef823403ee8990`.
- [reproduce_readback.py](reproduce_readback.py) verifies all retained entry
  hashes, the IPC request/response/report digest links, the source profiles,
  counter differences and read-only SQL observations. Its actual successful
  invocation is retained in [readback-process.json](readback-process.json);
  [readback.json](readback.json) contains the complete derived result.

Run from the repository root:

```sh
python evidence/pon-pure-security-20261030-rebuild/history-baseline/reproduce_readback.py
```

The SQL inspection opens a byte-identical temporary copy with
`mode=ro&immutable=1`. It compares retained snapshots and records; it does not
independently replay application execution or validate the account Merkle graph.
No signed download URL, new successful native receipt or substitute benchmark is
stored here.

## Actual costs and their scopes

The selected client is `pure-pon-fixed-host-client-v1`, using
`authenticated-v1` and `strict-every-native-checkpoint-v1`. The physical parent
is the existing `trnmponpublic.slice`, with `cpu.max=25000 100000`, zero CPU
burst, 2 GiB memory, zero swap and 256 tasks. The original four seed blocks and
1,024 signed seed transfers remain setup, before the measured phase.

| Retained observation | Process CPU | Process wall |
| --- | ---: | ---: |
| History import 0 | 1.061764206 s | 4.537685522 s |
| History import 1 | 1.050051657 s | 4.185570718 s |
| History import 2 | 1.060653485 s | 4.270785245 s |
| History import 3 | 1.055115795 s | 4.189306112 s |
| History import 4 | 1.051796922 s | 4.187223303 s |
| History import 5 | 1.057198570 s | 4.266768608 s |
| History import 6, complete page including activation | 4.005056549 s | 15.990904888 s |
| Separate confirmation | 0.058701016 s | 0.202745757 s |

Each page contains one actual packet. Only the seventh page is complete, so
only that import activates all seven newly admitted blocks. Its calling-thread
wall field is separately `15.990890457 s`; process wall is `15.990904888 s`.

The seven imports sum to **10.341637184 CPU seconds**. Dividing by the original
quarter-CPU duty fraction gives an idealized **41.366548736 wall seconds**, before
other work and waiting. This is explanatory budget arithmetic, not a separate
timing measurement or an exact sub-period scheduling theorem. Even an optimistic
whole 30-second allowance provides about 7.5 CPU seconds. Confirmation raises the
observed CPU sum to 10.400338200 seconds. Reaching even this first confirmation
inside that allowance would require more than a 27.8% CPU reduction before other
costs; the full original gate still requires all three business rounds.

The following are **nested current-thread stage deltas from ready through the
final snapshot**, including confirmation/snapshot work. They are not independent
additive costs and must not be added to the process CPU above.

| Native stage | Calls | Nested CPU | Nested wall |
| --- | ---: | ---: | ---: |
| Full state verification | 85 | 9.368587910 s | 36.891073921 s |
| Account graph within state verification | 85 | 9.240268480 s | 36.511421590 s |
| Admission | 7 | 6.203724773 s | 24.807448414 s |
| Final activation | 1 | 2.939621550 s | 11.761546211 s |
| M06 execution | 7 | 0.022249649 s | 0.022263276 s |
| Complete-state root calculation | 26 | 0.017008031 s | 0.017063287 s |

The account-node decode cache made 127,571 new observations, with 127,426 exact
hits and only 145 original decodes. This is evidence that another decode/hash
cache is not an established remedy for the dominant graph path. The retained
stage timings do not separate individual SQL, kernel-file, cancellation and
container-throttling contributions. In particular, they do not measure a
standalone W1 verifier or establish that every graph nanosecond is kernel I/O.

## Source mapping and repeated work

The complete source hashes in `provenance.json` are taken from the original
commit, independent of the concurrent working tree. Relevant implementations are:

- [ingress.rs](../../../trillionnium/crates/trnm-pon-node/src/ingress.rs):
  `metered_history_packet` creates strict CPU plus kernel-resource callbacks;
  complete-page activation retains its own paid operation.
- [native_progress.rs](../../../trillionnium/crates/trnm-pon-node/src/native_progress.rs):
  the strict adapter invokes the original checkpoint before every account node.
- [native_store.rs](../../../trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_store.rs):
  the account verifier reads every required node, checks every parent/child
  relationship and compares the entire leaf set/count/balance with actual State.
- [host_kernel_parent.rs](../../../trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs):
  each full resource check freshly reads boot identity, actual calling-thread
  membership and all five resource files, and rechecks parent metadata.
- [native_authenticated.rs](../../../trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs):
  `publish_with_native_progress`, `verify_state_with_native_progress` and
  `verify_history_with_native_progress` preserve post-write state/history checks.
- [store.rs](../../../trillionnium/crates/trnm-pon-node/src/store.rs):
  admission reads parent/child state back before commit; activation checks staged
  and active state around each durable reorganization step.

**Source-derived decomposition**, cross-checked against the actual counters:
seven admissions each perform eight state/graph checks (56); final activation
has intent, seven attach steps and publication, each with three checks (27);
confirmation and final snapshot add two. Total: **85**. This is not a per-call
instrumented trace.

The retained database has 1,028 accounts at heights 4 through 11 and four at
genesis. Sixty-two large graphs and 23 genesis graphs imply
`62 * (2 * 1028 - 1) + 23 * (2 * 4 - 1) = 127571` node loads, exactly matching
the observed decode-call delta. Heights 5 through 11 have identical retained
account maps and account-root tuples, but seven distinct complete State values.

Some repeated validations are adjacent within one immediate transaction: the
published child is checked again by `state_at(child)`, equal-account parent and
child states are revisited for empty business blocks, and final staged-target
verification is followed by active-target verification. Most other repetitions
straddle actual SQL writes, triggers or durable reorganization steps. Root
equality alone does not prove that current SQL rows remain valid.

A conservative same-transaction, unchanged-write-epoch reuse proposal would
target about 14 large admission walks plus two activation walks in this retained
fixture. That is a source estimate, not measured savings. It would also need a
fresh justification for the changed physical-checkpoint sequence, exact State
and parameter binding, foreign/same-connection mutation, schema changes,
cancellation, rollback and failed commit. **No such cache is implemented here**,
and these finite candidate savings do not establish the original service gate.

## Existing named successor, with its actual failures retained

The repository already has `history-account-graph-resource-fence-v1` in
[history_graph_resource_v1.rs](../../../trillionnium/crates/trnm-pon-node/src/ingress/history_graph_resource_v1.rs).
It is explicitly a **different resource observation schedule**. Every actual
graph node retains its CPU/cancel checkpoint and current SQL/graph validation.
Fresh complete kernel checks occur at entry, node zero and every eight node
bodies, final relation, exit, ordinary boundaries, commit and settlement. It
does not cache a successful kernel verdict or grant more CPU credit. The bound
is on node bodies, not elapsed revocation time; a change reverted between
observations is outside that observation claim.

Signed V6, continuous and mining owners cannot select this ordinary profile.
The old strict API remains separate. Strict observations contain zero values in
the *N8-specific* graph-resource counters because that controller was not used;
this does not mean the strict importer performed zero kernel checks.

[successor-ci-metadata.json](successor-ci-metadata.json) retains exact-source
GitHub jobs/artifact metadata, and
[successor-ci-terminal-excerpts.json](successor-ci-terminal-excerpts.json)
retains complete JSON terminal lines from the relevant decoded job logs.

| Existing run at source `540d723` | Actual retained status and scope |
| --- | --- |
| [40932472022](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40932472022), physical job `123663043503` | All 23 declared physical cases passed; original 22-test, lifecycle and reorganization jobs also have successful workflow metadata. This is finite boundary evidence. |
| [40932471976](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40932471976), original campaign | Strict and N8 jobs failed. N8 retained three native exit-101 attempts; each reader reported `actual full receiver/verifier state equality required`. |
| [40932471986](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40932471986), pure raw History | Strict and N8 jobs failed. N8 retained three native exit-101 attempts with valid readbacks but `original_criteria_met=false`. Detailed phase attribution needs its raw report. |
| [40932471462](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40932471462), same-runner pair | Workflow failed; no timing comparison is inferred from its status alone. |

The N8 implementation and its physical successes are real existing work. They
do not convert this strict baseline into a success and do not close N8's own
complete campaign. Fresh-identity admission, state/history service cost and the
resource-observation policy remain separate acceptance obligations.
