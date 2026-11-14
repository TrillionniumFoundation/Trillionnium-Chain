# Grouped multi-owner and current native evidence v1

Status: **implemented bounded evidence interfaces / research HOLD**. This
continuation composes grouped metering head
`0a0ac0cc9d33f4ddea01c72938a131ad2a946105` with the original funded-task owners at
`4a7e07e970d5bdb79626dda6bc98ae7906a02f18`. It preserves both histories and the
existing integration lineage. The sole development plan remains authoritative.

The selected work unit is the existing **classical security-seal step-oracle
query**. A lawful cached business result still gives a zero lower bound on fresh
producer business contractions per new ticket. Neither these interfaces nor a
successful controlled test registers the research seal as native consensus work.

## 1. Compose original observations across declared owners

The [composition reader](../../../../formal/pon-nakamoto-v1/grouped_work_composition_v1.py)
accepts original policies and evidence, each checked by the existing
[single-policy reader](../../../../formal/pon-nakamoto-v1/grouped_work_profile_v1.py).
It does not accept a collection of precomputed success flags or summary totals.

Its separately supplied expected manifest has the following fixed fields:

| Field | Meaning |
| --- | --- |
| `campaign`, `profile`, `denomination` | Exact selected research scope and work unit |
| `participants` | Opaque 32-byte owner namespace identifiers |
| `operations` | Expected pairs of owner namespace and immutable operation ID |
| `sources` | Expected source ID, reporting owner, original policy pin and exact actor-to-owner map |

The new namespaces are `pon-grouped-work-composition-manifest-v1`,
`pon-grouped-work-composition-evidence-v1`, and
`pon-grouped-work-composition-assessment-v1`. The manifest pin is a
domain-separated hash of bounded canonical JSON, not the raw file digest. An
independently fixed pin prevents substitution relative to that expectation; it
does not authenticate the actual control behind an owner namespace.

The complete input collection and manifest share a 16 MiB byte budget and a
16,384-record budget, with at most 32 source datasets. This prevents multiplying
the individual reader's limits by the number of sources.

### Query, execution and opportunity identities

The union key for a distinct query is the **complete native step preimage**.
Every supplied answer must match the original SHA-256 computation. A carrier,
policy name, local candidate name or receipt wrapper is not another query.

If two declared owners independently execute the same 64 native step inputs,
the union retains 128 execution observations and both owners' step costs, but
only 64 distinct oracle inputs and one canonical complete seal opportunity.
Replaying one owner/event identity through another source adds no execution.
Changing that identity's body is rejected.

A shared native challenge must retain the same statement, target, task,
material, issuer namespaces and declared authorization window. A new policy pin
cannot reprice the same challenge or make a renamed candidate a fresh lottery.
Owner operations, terminal receipts, demand references and consumer operations
are similarly reconciled across the original datasets.

Ordering checks remain inside their original policy coordinates. The reader
does not fabricate a common clock for different owners. A union assembled from
partial traces is a structural observation; it is not an independently
witnessed execution schedule or an expectation estimate.

Missing expected sources, reporting owners, operations and terminal records
remain visible as incomplete. A complete declared collection still says nothing
about an undeclared offline actor, preprocessing cache, delegate, auxiliary
verifier or a copied owner. Public and coalition query totals remain unknown.

### Cost composition without fabricated physical totals

The reader retains every distinct cost observation, including failed, canceled,
unfinished and unknown operations. It checks immutable owner/operation costs
against the union of execution events. Two separate partial reports cannot reuse
one 32-step counter to cover 64 distinct executions by the same owner.

Cost containment is checked over the entire merged forest. Separately valid
subtrees cannot exceed their shared parent after composition. A known payer or
beneficiary remains a constraint through any number of unknown intermediate
records. UNKNOWN is preserved as an observation; it does not erase a known
ancestor or acquire an inferred payment identity.

Repeated `(owner, unit, covered atom)` scopes must lie on one ancestor path.
The same consumer CPU atom cannot occur as a child of a producer aggregate and
also as an independent consumer root. Legitimate nested diagnostic subsets are
retained without charging them twice.

Namespace separation is not a proof of physically disjoint meters. The report
therefore leaves cross-owner additive physical totals unknown. Meter receipts,
covered-atom labels and `funding_units` remain declarations until their original
owners, exact units and actual transfers are authenticated. CPU time, GPU time,
wall time, bytes, energy, business MACs, oracle queries and monetary amounts are
never silently combined into one scalar.

## 2. Read current paid status from the original native owners

The original
[V2 operation contract](NATIVE_TASK_OPERATION_V2.md)
persists prospective binding, once-only begin, costs, completion, provider
delivery and payment. Its historical reconciliation correctly retains a payment
after a reorganization. Historical truth alone is insufficient for current
payment or delivery membership.

The original Node now exposes the read-only method
`observe_current_native_task_operation_v3(store, expected_binding,
expected_contract, consumer_epoch)` in its
[operation reconciliation owner](../../../../trillionnium/crates/trnm-pon-node/src/store/task_operation_v2/reconciliation.rs).
The new report namespace is `pon-native-task-operation-current-v3`, with scope
`CURRENT_PAID_NATIVE_TASK_OBSERVATION`. Existing signed and stored V2 namespaces
are unchanged.

The method reads the actual Node and M12 owners. It does not import a JSON report
as authority. It requires all of the following:

1. The existing durable Node operation pin, source history and reconciliation
   history validate against the supplied M12 journal.
2. The complete expected operation binding and complete original TSC1 contract
   match exactly. This includes qualified-work reference, request, provider,
   model, input, output specification, evaluation protocol, fee schedule,
   dispute policy, arbitrator, escrow and deadlines.
3. The requested epoch equals the latest already recorded reconciliation epoch.
   The current M12 checkpoint equals the complete checkpoint already retained
   by Node. A merely retained prefix or an unreconciled suffix is insufficient.
4. On the selected active block and generation, the original task is settled
   with zero remaining escrow. The original provider receipt is replayed, and
   its output and operation identity match the retained completion and delivery.
5. The actual original native monetary transition is replayed on that same
   active anchor. Source, subject, beneficiary, payment operation, gross escrow
   debit and beneficiary credit match the retained original payment.
6. Before return, the current complete M12 checkpoint, Node pins, Node history
   and active generation are checked again.

The read cannot advance a begin fence, journal floor or epoch; reconciliation
must use the existing owner method first. Its JSON output is a report with no
authenticated import path, execution permission or payment capability.

### Reorganizations, deadlines and consumer state

The same original signed receipt and payment may legitimately reappear at new
heights on another canonical branch. Their new anchors do not create new
operations. A different receipt for the same output or a different payment for
the same beneficiary and amount cannot replace the original identities.

An already settled task can remain present after its delivery deadline and at
the dispute deadline. Such current membership is not a fresh execution grant.
The original mandatory transition removes a zero-remaining task when its native
row deadline is less than the current height; TSC1 uses the dispute deadline for
that row. After this cleanup the full current-task observation must refuse the
absent source. Cleanup does not reverse the original payment or erase its
historical evidence. Refunded tasks and expired unresolved escrow also fail the
paid-only read even when historical output and delivery remain present.

`consumer_epoch` is an already recorded monotone reconciliation coordinate.
It is not an authenticated consumer owner state or actual consumer use. Node
and M12 remain separate owners: the final checks establish a bounded current
observation, not an atomic external FinalUse transaction or future freshness.
Current branch membership and finality remain distinct.

### Keep commitment domains distinct

| Value | Authority and meaning |
| --- | --- |
| Grouped candidate `task` | The task-content commitment fixed by that research policy |
| TSC1 native Task ID | The original native instance ID derived from its actual contract and reservation |
| TSC1 `qualified_work` | A contract reference commitment, not proof of registry membership |
| Grouped policy digest | The exact policy identity under its own domain |
| `target_scope`, `target_receipt` | Commitments whose external target authority is not established here |

These values cannot be renamed into one another. In particular, defining
`qualified_work` as a policy digest containing the same TSC1 Task ID would make
the commitments circular. A future authorized adapter must fix its pre-task
work-request/profile commitment and bind the native instance separately. The
new readback checks the expected full native terms; it does not invent this
external authorization or a profile-registration rule.

## 3. Observe actual native seed and step evaluations

The [native seal](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_grouped_fresh_seal_v0.rs)
now provides opt-in `prove_with_query_observer` and
`verify_with_query_observer` entry points. Their `EvaluatedQuery` value has
private fields and no public constructor or decoder. The callback receives the
profile, challenge, statement, predecessor and answer captured immediately after
the corresponding native hash evaluation. Calling `preimage()` frames those
already captured fields; it does not rehash the input or recompute the profile
hash. The existing progress APIs, proof bytes and fixed SHA-256 prefix preparation
remain in place.

The [original verification owner](../../../../trillionnium/crates/trnm-pon-node/src/grouped_verification_authority_v0.rs)
adds `execute_with_query_observer`. Its existing `execute` entry point uses the
same path with a noncanceling observer. Each emitted observation binds the
original policy, authority, epoch, generation, journal sequence, receiver,
request ID, candidate and request fingerprint, followed by its query ordinal.
The fingerprint still binds the original supplied product and proof. These
events have the fresh namespace `pon-grouped-owner-query-observation-v1`;
existing signed requests, stored receipts and once-only execution fences retain
their original namespaces and rules.

| Observation | Ordinal | Exact framed input length | Accounting unit |
| --- | --- | --- | --- |
| Seed evaluation | `0` | 139 bytes | `seed_hash` |
| Each of 64 step evaluations | `1..64` | 145 bytes | `classical-seal-step-oracle-query` |

A completed replay therefore has at most 65 callback observations, of which
64 belong to the selected security-work denomination. Profile hashes, event-ID
hashes, framing, JSON encoding and capture I/O are additional work. A query
record cannot substitute for the independently verified useful relation or
establish public-network completeness.

### Cancellation, cache and uncertain execution

The original owner commits its `started` reservation before replay. It increments
the seed or step counter before invoking the observer and the existing progress
control. Cancellation at seed, step 17 or step 64 therefore retains the query
that has just completed. It returns the existing canceled outcome with the
corresponding costs, without issuing a successful partial witness or closing the
candidate as a verified hit or miss.

A previously completed operation returns its historical receipt and emits zero
new observations. A previously started/UNKNOWN operation also emits zero new
observations. Neither path reruns the seal to manufacture a missing historical
transcript, renews its reservation or refunds its consumed budget.

The controlled interruption test writes and file-syncs the selected query row,
then exits with code 86. The original journal remains `started`. Reopening that
same journal through the original owner changes its state to UNKNOWN; the same
operation is not rerun. An observed prefix of one seed and 17 steps is contained
inside the original upper bound of one seed and 64 steps. Adding that prefix on
top of the UNKNOWN upper bound would double count its possible cost.

An invalid framing can be rejected without a seed or step observation. A forged
low endpoint that passes framing still produces the full actual replay before
the original endpoint check rejects it. Trace collection follows these actual
control paths rather than reconstructing queries from aggregate counters.

### Opt-in fixture command and raw evidence retention

The [existing owner example](../../../../trillionnium/crates/trnm-pon-node/examples/grouped_verification_authority_v0.rs)
has a separate local command:

```bash
/absolute/path/grouped_verification_authority_v0 execute_observed_v1 \
  /absolute/path/owner \
  /absolute/path/observed-command.json \
  /absolute/path/observation.json \
  73
```

The request namespace is `pon-grouped-owner-observed-command-v1`. It contains the
original unsigned `execute` command, `cancel_after_query` and
`abort_after_query`. Each control is either `null` or an ordinal from `0` through
`64`; at most one can be enabled. The example signs the unchanged Execute
message using its existing public fixture receiver key, then enters the original
native authentication path. These local controls add no network wire action.
The original `serve` and `client` modes keep their existing schemas.

All paths must be absolute. Before an attempt begins, the command reserves a
create-only response file and a create-only sibling named
`observation.json.queries.ndjson`. Each actual callback appends and file-syncs
one row. The response uses `pon-grouped-owner-execution-observation-v1` and
includes the captured query array, original receipt/state, owner snapshot,
source/configuration/runner identities and capture errors. An interrupted
response can remain empty while its recorded query prefix is available.

The [native observer tests](../../../../formal/pon-nakamoto-v1/test_grouped_query_observation_v1.py)
print complete first-hand responses, query prefixes and independent reader
checks into the retained command log. Every nonzero child exit, including the
deliberate code 86, and every timeout triggers a create-only copy of the original
fixture files with a hash inventory before another owner open can change them.
Malformed captures and failing assertions also retain evidence. In particular,
the original `started` journal bytes are copied before UNKNOWN reconciliation.
Timeouts remain test failures.

The enclosing validation collector must collect the original and sibling paths
named in `pon-grouped-query-retained-native-failure-v1` manifests. Log hashes and
paths alone do not contain the original SQLite bytes. These copies are pinned
by hashes and written only once by this harness; they are not tamper-proof
storage. File `fsync` here does not establish parent-directory or power-loss
durability. Observer framing, metadata hashing and file-sync work belongs to
the measured owner replay; later controller snapshots and report writes have
their separately stated scope.

The seven native integration controls cover the following behaviors:

| Control | Native observations and state checked |
| --- | --- |
| Complete replay | One seed and 64 steps; exact raw inputs, answers, event identities, receipt binding and v1 reader agreement |
| Observer cancellation | Seed, step 17 and final step 64 remain charged; no successful partial receipt |
| Cached reply after reopen | Original receipt retained; zero new callbacks, queries or reservations |
| Synced interruption and recovery | Exit 86 after the 18-row prefix; original operation becomes UNKNOWN with its full upper bound and cannot rerun or refund |
| Forged endpoint | Full 65-row actual replay followed by the original relation rejection |
| Framing rejection | Zero fabricated query rows and zero seed/step counts |
| Create-only export | Existing output and prefix bytes remain intact; a refused overwrite cannot start another attempt |

The fixed observer event identity remains scoped to the existing one-owner
journal assumption. Copying or rolling back that journal is not prevented by
this export and can reproduce its namespace. Distinct labels, an observed
prefix, or a successful controlled capture do not prove independent operators,
all offline/delegated work, authentic external demand or an atomic FinalUse.

## 4. Security-work and physical-cost boundary

The [existing metering specification](GROUPED_SECURITY_WORK_METERING_V1.md)
retains the conditional classical oracle-query theorem. Its diagnostic quantity
`64 * floor(2^256 / (T + 1))` is neither observed physical cost nor native chainwork.
The native seal already caches its fixed SHA-256 prefix. Pricing each logical
step as a new full-prefix computation would misdescribe the legal implementation.

A finite minimum among measured legal strategies supplies an observed upper
bound on the cheapest implementation in that comparison. It does not prove a
positive physical lower bound over all legal implementations. Complete machine,
network, preparation, failed-attempt and delegated costs still need their real
meters, accounting horizon and payer/beneficiary transfer evidence.

The new interfaces leave native W1 dispatch, proof verification, block weight
and fork choice unchanged. There is no seal-to-`VerifiedWork` conversion and no
hash-only fallback. Formal native consensus adoption remains a separate,
unfulfilled gate.

## 5. Five acceptance conditions

| Condition | Concrete engineering result | Facts still required for qualification |
| --- | --- | --- |
| Public query attribution | Actual in-loop native observations bound to the original owner attempt, original multi-owner inputs, exact preimage union and declared cost reconciliation | All actual public/offline/preparation/delegated/helper queries and real control relationships |
| Independent task and target authority | Existing prospective native operation fence plus exact full contract/current native readback | Independent issuers, unbiased assignment, authentic prequery target permission and actual current consumer/target authority |
| Genuine demand | Original native delivery and payment replay, current membership distinct from history | Independent customers, external budgets, actual current consumer use and authentic external funding origin |
| Complete cost transfer | Whole-forest containment and transfer checks; original gross debit and beneficiary credit kept distinct | Authentic complete resource meters, preparation/failure/machine/network costs and actual payer/beneficiary incidence |
| Adoptable weight rule | Explicit security-work denomination; cached-business zero lower bound retained | Cheapest-legal-implementation transfer theorem and formal native consensus profile registration |

Controlled fixtures exercise the real native code and state transitions. Their
keys, funding, target references and meter values are not independent external
evidence. All qualification flags remain HOLD/false, and actual chainwork is zero.

## 6. Reproduction and retained failures

The [combined validator](../../../../formal/pon-nakamoto-v1/experiments/validate_grouped_profile_closure_v1.py)
keeps the original grouped validator's 24 command records as an exact prefix.
It adds original funded-task core crates, the five native owner test targets,
demand/upgrade controls and negative research-integration controls. Every
command retains its result, full output, timeout and source identity. Source
checks bind both validation drivers and all tracked source bytes before and
after execution. This is not a full public-service or production campaign.

### Preliminary native validation before the integration commit

HeptaRuntime job `1a1b869c80d-12894-f28` completed the preliminary native run
retained under `preliminary-native-observation-v2` in the isolated ROG work
directory. The actual native `native_task_operation_v2` target passed all four
tests, the release owner example built successfully, and all seven observer
Python controls passed against that real binary. Their retained logs have these
SHA256 pins:

| Preliminary command | Result | Log SHA256 |
| --- | --- | --- |
| Native task operation V2 target | 4 passed | `e2d880e3adaa0cec54e0a80d5d50ce70346554358bd7012d571e2cdb1be02ac7` |
| Release owner example build | Passed | `1d110dc8d10e6b775013d8774ced3a0b4fa8f95b710d4db0baea7e9b167b39eb` |
| Actual native observer Python controls | 7 passed | `0a24afcebaa17093c62e9c22a12ad03b021814d60b06d861995cd417f023ff60` |

These results precede the integrated implementation commit. At this preliminary
checkpoint, the complete 33-command validation has not yet run, and
committed-source equivalence has not yet been established by that gate. The
successful deliberate interruption
control includes the actual exit-86 process and retained UNKNOWN state; it does
not turn the interrupted process into an ordinary successful execution.

The observer subset is reproducible with the bound example binary:

```bash
PYTHONDONTWRITEBYTECODE=1 \
TRNM_GROUPED_AUTHORITY_NATIVE=/absolute/path/grouped_verification_authority_v0 \
python3 -m unittest discover -s formal/pon-nakamoto-v1 \
  -p 'test_grouped_query_observation_v1.py' -v
```

An unset runner causes an explicit skipped integration class. The combined
validator supplies the actual built runner and keeps its source/binary binding;
a skipped standalone run does not replace that validation.

The inherited
[native demand acceptance record](../../../../evidence/pon-native-demand-acceptance-20261107/README.md)
retains the interrupted original Node invocation, its separate continuation and
the remaining original Host/cgroup failures. This continuation does not waive
those gates or turn the earlier cross-run union into one successful invocation.

The [new evidence record](../../../../evidence/pon-native-profile-closure-20261107/README.md)
pins the combined source, controlled observations, regression results and
publication identities. Prior failures and UNKNOWN states remain preserved.
