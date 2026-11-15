# System security blocker projection V1

Status: **HOLD_NO_GO**. Authority: **DENY_ALL**.

This continuation adds a read-only view of eight release-blocking questions to
the existing [Chain/Hepta qualification reader](../../scripts/ci/chain_hepta_qualification.py).
It improves the visibility of retained facts; it does not supply a missing
consensus theorem, certify independent operators, authenticate a provider effect,
or qualify a production release. A P0 label denotes release priority, not an
assertion that every row is a reproduced vulnerability.

The original projection continued the exact #835 source
`e2a02f9271b49f146e70806c8a66e161b5973971`, tree
`86d2014b560659106b3af6e6c19e1f82a290a60e`. This integration retains the reader
interfaces and imports its additive diagnostic controls; it does not transfer
historical execution results to the integrated source. The original seven gates and their
priorities are retained. In particular, the P1 presentation of source integration
below does not weaken the original reader's P0_INTEGRATION gate.

## Eight questions and their existing obligations

| Priority | Boundary | Existing obligations | Evidence still needed for qualification |
| --- | --- | --- | --- |
| P0 | Work cost and consensus credit | `w1_minimum_cost`, `quantum_work_daa_weight` | A reduction covering every allowed strategy, initial state, public help, preparation, reuse, failed attempts and branch inventories; actual classical and quantum cost envelopes and their credit calibration. |
| P0 | Time, difficulty, forks and progress | `timestamp_daa_chainweight`, `quantum_work_daa_weight` | One joint model of lawful cost, parent target, timestamps, cumulative credit, dynamic participation and delay, with concrete common-prefix, chain-growth and chain-quality bounds. |
| P0 | Verification cost and honest service | `hostile_honest_confirmation`, `cost_decomposition`, `matched_confirmation_tail_latency` | Complete original-budget service observations, including all scheduled honest rounds, failures, cancellations, process resources and confirmation latency. A validation rejection or ACK alone does not establish the business target. |
| P0 | Model evaluation and poisoning resistance | `same_iteration`, `no_update` | Authentic training origin, independent evaluation data and evaluator control, future tasks, matched strong controls, complete costs and recoverable Adopt/NoUpdate. |
| P0 | Authorization through the external effect | `entry_to_effect`, `current_revocation_load`, `recovery_effects`, `unknown_timeout`, `revocation`, `restart`, `reorg` | The original authorized operation, current permission at entry, provider-native execution and reconciliation, settlement and ordinary Hepta FinalUse, including Unknown and reorganization recovery. |
| P0 | Restoration of every old backup | `recovery_effects`, `rollback_external_effects` | Independently retained sufficiently current facts, authenticated acquisition and freshness policy, plus an operational recovery exercise covering joint restoration of all local state. |
| P1 | Storage availability and common failures | `dependency_closure`, `independent_custody_wan`, `renewal_repair_recovery`, `content_commitment` | Independent operations and failure domains, funded retention and repair, WAN measurements, complete model/environment closure and recovery over the retained set. |
| P1 | Combination of branch evidence | `source_locks`, `build_load`, `native_registry` | A single integrated source pair, exact build and loaded closures, complete original attempts and fresh full acceptance on that source. Separate branch successes do not supply this evidence. |

These are projections of existing obligations, not eight new authorizers. Every
row remains `qualified=false`. Known failures, unknown fields, invalid declarations
and historical evidence are reported separately.

## Evidence formats and limits

[The system security reader](../../scripts/ci/chain_system_security.py) calls
the original qualification reader before projecting the new view. It retains
the original result and never changes its `declared_result_consistent`, learning
blockers, seven gate decisions or effect state machine.

Specialized adapters expose facts from the fixed-probability contract, the
joint-consensus limitations, the original-campaign crosscheck and the local
resource-owner contract. The fixed-probability contract's sixteen unknown cost
points remain unknown. `binding_validation=PASS` is not a work lower bound.
The original-campaign adapter retains both campaign and round denominators;
unobserved scheduled rounds remain unobserved. Declared controller resources
are not substituted for constrained receiver resources.

The retained DAA input in this continuation is explicitly a
`trnm-joint-consensus-limitations-extract-v1` document. It contains only the
original report's limitations and its complete-original SHA-256, under
`extraction=limitations-only`. It is not the full original report. The reader
marks this distinction and does not re-execute the source model or qualify
consensus security from a declaration. The original report remains available at
its pinned repository location in the input provenance.

Every additional artifact has a retained-file digest and a declared source
commit/tree. Equal declarations remain `SAME_DECLARED_SOURCE_UNAUTHENTICATED`;
different identities remain historical; unobserved identities remain unknown.
Embedded identity conflicts are retained. Matching a retained hash establishes
the bytes that were read, not the issuer, execution, custody or truth of a claim.
No artifact can set a release or FinalUse flag.

## Learning and effect-stage detail

The independent `trnm-chain-hepta-stage-qualification-v1` projection distinguishes:

| State | Meaning |
| --- | --- |
| `NOT_REPORTED` | The stage or required field was not supplied. |
| `NOT_ESTABLISHED` | The supplied boolean does not establish the required property. This is not automatically a native-test failure. |
| `DECLARED_UNVERIFIED` | The field declares the property; the reader has not authenticated it. |
| `INVALID_DECLARATION` | The supplied value is not a valid boolean declaration for that field. |

Training, evaluation, selection, payment, cold fetch, installation, load and next
task retain separate rows. A structurally consistent sequence cannot establish
independent evaluation, settlement or FinalUse. A true declaration never produces
`qualified=true`. Known original-command source conflicts also prevent the new
stage-context field from describing the record as consistent.

The original legal NoUpdate exception is retained: a completed evaluation,
identical complete parent/selected manifest and bundle, no reset and no structural
learning blocker can make absent cold-fetch/install stages unnecessary for that
retained-parent path. It does not waive training provenance, independent evaluation,
payment, current load permission or the next task. NoUpdate is not invented from
Unknown evaluation.

## Independence requires three different relations

Counting keys, processes or directories does not certify decentralization.
Operational evidence must keep these relations distinct:

| Relation | Required question | Examples of common control or failure |
| --- | --- | --- |
| Key control | Who can obtain or use which private keys? | Shared administrator, device, credential store or recovery authority. |
| Availability | Which failures make which signers, stores and currentness sources unavailable? | Shared power, network, facility, funding or repair service. |
| Joint restoration | Which procedures can rewind which authoritative states together? | One backup operator, common image, shared restore workflow or simultaneously restored anchors. |

A power-domain count is not a private-key threshold. Distinct administrators may
still collude; authenticated identities do not certify honesty. An external floor
is useful only under its independent-currentness premise. A newer counter or
fresh signature on restored old history cannot itself establish that premise.

## Source boundary and current records

The [historical review packet](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b8672afb702e4b0bfff8e2bef2b6144d355442dd/evidence/system-security-review-20261109/README.md)
contains exact source locators, original hashes, the frozen audit plan and the
generated HOLD report. It records existing missing evidence rather than creating
synthetic native receipts or claiming a new model evaluation.

The following separation records the original projection's execution scope.
Later Git integration does not make these historical results current acceptance:

- #836 at `0746a462e80067b78317597f2fa4bacf5e3db958` has additional complete-version
  retention and repair components. They are not silently imported into #835.
- #837 at `44330b91eb552fd20ef6f2e69bf5e6f1e8f5c0b0` has the recovery-floor/provider
  continuation. Its 42 successful local commands and failed original 0/3 native
  campaign retain their own execution source. The separate V2 SQLite cleanup
  continuation also belongs to that stack.
- #830's resource-owner declarations remain another source, not evidence that
  every entry point or physical resource domain is covered on this one.

## Validation and command semantics

The new suite is mandatory once in the existing `repository-truth` lane after
the original qualification suite. Independent CI literals and source-contract
tests reject omission, duplication, relocation, conditional skipping and swallowed
failure. Original native selectors, workloads, budgets and vetoes remain intact.

Run the reader with the frozen plan hash, packet, evidence root and security-input
manifest shown in the evidence README. Exit 2 means a well-formed HOLD report;
exit 1 means rejected or unreadable inputs. Neither exit establishes native
success. The component tests cover reader semantics and source-contract wiring;
fresh full native, independent operator/WAN, model efficacy and external-effect
acceptance remain separate requirements.
