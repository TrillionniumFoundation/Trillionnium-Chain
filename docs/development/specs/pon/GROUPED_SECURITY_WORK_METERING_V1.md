# Grouped security-work metering and qualification v1

Status: **implemented evidence contract / research HOLD**. This continuation
starts from `4699b4079fca323f8db7b9d3644fbb159aa687c0`, the retained grouped
resource-transfer checkpoint. The sole development plan, existing integration
candidate, original resource limits and native W1 rules remain authoritative.

## 1. Precisely what the candidate measures

The [metering declaration](../../../../config/pon/grouped-security-work-metering-v1.json)
selects **classical security-seal step-oracle queries**. The fixed relation uses
64 steps and the unique canonical last endpoint as its ticket. The diagnostic
nominal award at an independently preauthorized target `T` is
`64 * floor(2^256 / (T + 1))`. It is a quantity in the conditional mathematical
model, not a native chainwork award, CPU time, energy, money or neural MAC count.

The useful Cell relation and its cached result remain independently verified.
The existing legal producer can retain a correct business result and produce
another seal without new business contractions. Consequently the admitted cache
scope has a **zero per-ticket lower bound on fresh producer business
contractions**. There is no promotion based on the claim that a new ticket must
force a new neural computation. Receiver recomputation belongs to that receiver.

The [aggregate-query theorem](../../../../formal/pon-nakamoto-v1/fresh_work_query_floor_v0.py)
and [resource-transfer corollary](../../../../formal/pon-nakamoto-v1/fresh_work_resource_transfer_v0.py)
retain their explicit classical model, predictable target, fixed statement,
injective domain, accounting-horizon and unique-credit assumptions. If assisting
verifiers reveal their complete transcript, their queries belong in the total
query budget. This does not transfer their invoice to the attack coalition.
An observed lucky win is not a pathwise violation of an expectation bound.

## 2. Executable evidence contract

The [inspector](../../../../formal/pon-nakamoto-v1/grouped_work_profile_v1.py)
accepts an evidence object and a separately supplied expected policy and policy
digest. These use fresh v1 namespaces. The policy fixes the campaign, profile,
denomination, actors, candidates, demand operations, planned operations and
required cost stages. The evidence supplies bounded query observations, terminal
records, declared consumer-use references and resource observations.

A digest pin detects substitution relative to the independently supplied pin.
It does not authenticate a customer, issuer, operator, clock, meter or payment.
The input has no `trusted`, `qualified` or `production_eligible` switch. The
inspector grants no native capability and returns zero actual chainwork.

### Query identity and attribution

The inspector reconstructs the exact fixed native step preimage and verifies
the observed SHA256 answer. Full preimage identity, rather than an envelope,
claimant name or carrier hash, defines a distinct observed query. Exact event
retransmissions do not create new events. Separate executions of the same query
can incur separate costs without creating another distinct oracle input.

Planned operation and actor references retain producer, preparation, delegate,
verifier, receiver, consumer and helper work separately. Target and task declarations must precede
the observations in the supplied ordering coordinates. Those coordinates are
not an externally witnessed chronology. Missing trace records are not recreated
from a native aggregate counter and presented as observed history.

Only the observed scope is counted. Private, offline, omitted, cross-owner,
cross-epoch and delegated queries remain outside any demonstrated completeness
claim. A local journal quota cannot establish a global public-network cap.

### Task, target and demand authority

Task, material, statement, challenge, target, issuer and authorization window
are pinned outside the evidence object. Rebinding the evidence's target or
policy cannot turn a later choice into a prequery authorization.
Expiry follows the native exclusive upper boundary: observations must be
strictly before `expires_at`, and operation records strictly before their
deadline. The inspector additionally requires queries and consumer uses to
follow their pinned authorization declarations strictly in the supplied
ordering coordinates. A query observed at or after expiry remains in the cost
denominator and produces an explicit authorization issue.

Different key strings or actor labels do not prove independent control. A native
Node target snapshot establishes the checked branch value, not governance
authorization to register this new profile. The existing owner receipt is a
historical verification result; it does not establish current authorization at
later journal commit or FinalUse. That requires the actual owning state and a
defined commit/use-time boundary.

Demand and consumer-operation identities are separate from material identity.
Two legitimate customers may request identical material, while many seals over
one cached result do not demonstrate many customers. Exact consumer-operation
replays cannot create additional declared uses. Even a structurally consistent
use reference remains a declaration until the actual consumer owner, current
FinalUse, funding and settlement are independently established.

### Complete costs and transfers

Every planned operation, including rejected, canceled, unfinished and unknown
work, remains in the denominator. Resource records name the operation, stage,
meter, payer, beneficiary, resource unit, covered atoms and any enclosing record.
Unknown amount, payer, beneficiary or missing required stage remains explicit.

Only disjoint enclosing scopes are added. A named subset is diagnostic and is
not charged again on top of its enclosing measurement. Disjoint children must
fit every enclosing exact amount or upper bound. Known descendant costs pass
through unknown intermediate records; unknown totals never become zero.
CPU, GPU, wall time,
bytes, energy, funding units, seed hashes, seal queries and business MACs remain
separate units; the inspector supplies no uncalibrated scalar conversion.
Preparation, caches and reused material require an explicit accounting horizon.
Cheap valid implementations and invalid-input service attacks remain different
comparisons. A finite minimum among observed strategies is not a lower bound
on all legal implementations.

## 3. Hardening the existing fanout cost reader

The existing [fanout reader](../../../../formal/pon-nakamoto-v1/grouped_fresh_deployment_cost_v0.py)
previously admitted six inconsistent synthetic records: verified receptions
without work identities, missing byte counters becoming zero, negative byte
counts, finite CPU inputs summing to infinity, child CPU exceeding its declared
enclosing measurement, and unknown attempt states counted as completed.

The continuation rejects these records. Missing totals stay unknown, known
partial values and denominators remain visible, and malformed nested records
cannot erase the remaining observed work. Strict integer and Boolean checks
also prevent `true` or `false` from impersonating numeric values or successful
exit codes. The retained original experiment files are not rewritten; new
readback results bind the original bytes and the new reader version.

The [pinned reanalysis CLI](../../../../formal/pon-nakamoto-v1/experiments/reanalyze_grouped_fanout_v1.py)
requires an external SHA256 pin and the original ordered `[1, 2, 4]` receiver
denominator. It recomputes accounting from worker observations, retains original
failure inventories and qualification limits, and refuses an existing output
path. It does not rerun the workload or reauthenticate historical packet files.
The [retained evidence](../../../../evidence/pon-security-work-metering-20261107/README.md)
distinguishes this reanalysis from the separate recorded-query reinspection.

The fixed two-packet fanout also binds each successful reception to its original
packet slot. The valid and whitespace-only carrier replay use nonce 1; the
discarded-response control uses nonce 2. A receiver cannot assign another work
identity to one carrier, exchange the two slots, or reuse nonce 1's identity for
nonce 2. The same identities must hold across receivers and topologies.

These stronger report semantics use fresh output namespaces:
`pon-grouped-fresh-deployment-cost-v1` for accounting and
`pon-grouped-fanout-reanalysis-v2` for offline readback. The existing Python
entrypoint filenames are retained. The historical campaign input remains
`pon-grouped-fresh-fanout-campaign-v0`; stored old reports, signed protocol
domains and the native work profile are unchanged.

The actual runner passes the existing native producer table into the reader
before receivers start. Offline reanalysis uses that table from the unchanged,
externally pinned historical report. Missing or malformed producer entries stay
a refusal; they are not reconstructed from receiver claims. An inconsistent
complete identity count becomes unknown while reported partial identities,
CPU, byte counts, rejected/canceled work and the original denominators remain
visible. The direct accounting helper still supports unanchored structural
observations, explicitly reporting that producer binding was not established.
Neither a consistent label mapping nor the historical report pin reauthenticates
the original native packet, proves useful demand, or grants chainwork.

These were report-integrity defects. Their rejection does not imply a native
consensus exploit or certify the public-network economic qualifications.

## 4. Current closure boundary

| Requirement | Engineering evidence supplied here | Still requires external evidence |
| --- | --- | --- |
| Chosen security-work unit | Fixed 64-step query denomination and exact step reader | Real SHA256 implementation and physical-cost transfer assumptions |
| Query attribution | Bound operations, actors, preimages, duplicates and assisting work | Complete public coalition and helper coverage across all owners and horizons |
| Task and target authority | External expected policy pin and prequery binding checks | Actual independent issuers, allocation policy and profile governance |
| Genuine demand | Separate material, demand and consumer-operation identities | Actual request, current consumer use, funding and settlement |
| Complete cost transfer | Typed costs, explicit unknowns, scope overlap and payer/beneficiary checks | Authentic meters and complete machine, transport, failure and preparation costs |
| Native admission | Existing owner performs full Cell and seal verification with retained reservations | Public admission, clone/rollback resistance, adopted consensus registration |

No locally produced fixture or `PASS` structural result closes the right-hand
column. The inspector's qualification remains HOLD and actual chainwork remains
zero. The missing obligations are named in its report instead of being hidden
behind one aggregate success flag.

## 5. Reproduction

Run in an allowed exact-source development checkout:

```bash
bash scripts/project-preflight.sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s formal/pon-nakamoto-v1 -p 'test_grouped_work_profile_v1.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s formal/pon-nakamoto-v1 -p 'test_grouped_fresh_deployment_cost_v0.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s formal/pon-nakamoto-v1 -p 'test_grouped_fanout_reanalysis_v1.py' -v
python3 formal/pon-nakamoto-v1/grouped_work_profile_v1.py \
  --evidence /absolute/path/evidence.json \
  --expected-policy /absolute/path/policy.json \
  --expected-policy-sha256 INDEPENDENTLY_ESTABLISHED_POLICY_DIGEST
```

The policy digest is the inspector's domain-separated `policy_digest(policy)`,
not the SHA256 of arbitrary JSON file bytes. The JSON/API readers reject duplicate
keys, nonfinite values, unexpected fields and resource-limit violations. API
container aliases and cycles are rejected before potentially amplifying them
through serialization.

The ordinary protocol CI already collects `test_grouped*.py`, including these
tests. No workflow or required gate is removed, duplicated or weakened. A
successful evidence inspection is distinct from production qualification.
