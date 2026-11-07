# Security-work metering continuation — 2026-11-07

Qualification: **HOLD; actual chainwork 0; production activation false**.
The implemented object is a research evidence contract for **classical
security-seal step-oracle queries**. It does not establish a positive fresh
producer neural-contraction floor. The existing lawful cached business result
can be reused, including across newly produced security seals.

This continuation starts from commit
`4699b4079fca323f8db7b9d3644fbb159aa687c0`. The prior native subtree was
`38b2aba7fd25cfddb0e45747d7716a5ada3e9321`, retained from
`e95e2eb9f456a37ec8841def69db79f49fbba7cb`. Native runtime logic is unchanged;
the generated distributed-source inventory is extended to include the new
research declaration, using the repository's existing generator.
The [sole plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [metering specification](../../docs/development/specs/pon/GROUPED_SECURITY_WORK_METERING_V1.md)
define the continuation. Existing native verification, reservation rules and
required CI gates remain authoritative.

## 1. Delivered implementation

- [New v1 inspector](../../formal/pon-nakamoto-v1/grouped_work_profile_v1.py):
  separately pinned policies, exact native query preimages and SHA256 answers,
  immutable operation identities, declared use references, typed costs and
  explicit unresolved predicates. A policy pin authenticates neither its issuer
  nor the chronology supplied with the observations.
- [Hardened existing cost reader](../../formal/pon-nakamoto-v1/grouped_fresh_deployment_cost_v0.py):
  rejects missing verified work IDs, missing or negative bytes, overflowed CPU
  totals, impossible child CPU subsets and unknown attempt states. Missing
  observations remain unknown while known partial work is retained.
- [Pinned historical reanalysis](../../formal/pon-nakamoto-v1/experiments/reanalyze_grouped_fanout_v1.py):
  requires a separate raw-byte SHA256 pin and the complete ordered receiver
  denominator `[1, 2, 4]`. It recomputes the reader from worker observations and
  preserves earlier failures. Existing output paths are refused.
- [Fixed-input query reinspection](replay_retained_query_trace.py):
  reproduces all retained Python trace rows without fabricating missing native
  queries, independent issuers, consumer demand or complete campaign costs.

The selected unit is one classical call to the existing fixed security-seal
step oracle. A complete seal has 64 steps. The diagnostic quantity
`64 * floor(2^256 / (T + 1))` uses a preauthorized target in the conditional
model; it is neither a measured physical cost nor an actual chainwork award.

The new inspector reconciles costs for each operation separately. An honest
verifier's 64 recorded queries cannot cover a producer's missing charge. Scope
containment is explicit: disjoint descendants must fit every enclosing exact
amount or upper bound, including through UNKNOWN intermediate nodes. CPU, GPU,
wall time, bytes, energy, funding, seed hashes, seal queries and business MACs
are separate units. Input aliases, cycles, duplicate JSON keys and bounded
resource violations are rejected.

## 2. Historical ROG fanout: accounting reanalysis

The [original report](../pon-resource-transfer-20261107/rog/key-records/fanout-exact-rog/report.json)
is 402,979 bytes with SHA256
`915485a66d8b9ee4d1aadece413edb928274640a1830a840f818571b3042df96`.
Its experiment source was `e95e2eb9f456a37ec8841def69db79f49fbba7cb`.
The [new reanalysis](fanout-exact-rog-reanalysis-v1.json) binds those exact bytes
and the new reader source hashes. It executes no new workload, native binary or
packet-file readback. Original metadata remains a retained historical
observation, not reauthenticated evidence.

| Receiver slots | Original → reanalysis | Attempts | Verified receptions | Distinct work IDs | Full Cell calls | Reference MACs | Sum of local reservations |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | PASS → PASS | 6 | 3 | 2 | 4 | 148,032 | 256 |
| 2 | PASS → PASS | 12 | 6 | 2 | 8 | 296,064 | 512 |
| 4 | PASS → PASS | 24 | 12 | 2 | 16 | 592,128 | 1,024 |

| Receiver slots | Enclosing receiver CPU (s) | Native CPU subset (s) | Received bytes | Client-read bytes | Kernel-accepted ACK bytes |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.309628 | 0.103199 | 17,654 | 8,372 | 11,229 |
| 2 | 0.586721 | 0.202294 | 35,308 | 16,766 | 22,482 |
| 4 | 1.198597 | 0.392033 | 70,616 | 33,511 | 44,937 |

CPU values above are rounded only for display. Native CPU is a subset of
receiver CPU and is not added again. Across the three topologies there are
42 attempts, 21 verified receptions and 28 full Cell calls. The same two work
IDs recur; they are not six distinct tickets or 21 independent useful jobs.
The 1,792 reservations are the sum of local allowances, not a globally enforced
public-network cap. All original observations were same-host TCP on ext4 with
controlled operators. Actual independent customer demand and consumer uses
remain unestablished.

## 3. Complete retained Python trace reinspection

This is a different historical run. The original
[fresh-work report](../pon-fresh-work-floor-20261107/fresh-work/report.json)
binds source `1e0eba75f4f4a4e24e17cbd0f263f915c1493ac7` and has SHA256
`3e18ebd0437320941f452e66088f49dedd1f71e3c747fb4d1965d85945285ac3`.
The [recorded transcript](../pon-fresh-work-floor-20261107/fresh-work/hash-transcript.ndjson)
has SHA256
`16c761002daf687fa16086fe2966b89d0443bf2c7dafbd1fb8df55eaea082e3d`.

The [normalized observations](query-reinspection/observations.json.gz),
[expected policy](query-reinspection/expected-policy.json),
[assessment](query-reinspection/assessment.json) and
[provenance](query-reinspection/provenance.json) retain all **1,088 Python step
observations**: 1,024 helper crosscheck queries and 64 queries from the recorded
untrusted producer control. They contain 1,088 distinct native inputs and 17
complete seal traces. There are zero omitted Python trace rows and zero native
counter rows promoted to observed transcripts.

The selected 17 operations describe the trace subset, not all experiment work.
The original denominator of 16 primary attempts and all 251 control records
remains bound by the original report and named in provenance. Reader-assigned
file-order coordinates are not trusted original clocks. All policy actors are
declared as one controlled group. There are no fabricated demand or consumer-use
records. Unknown physical costs, payers and beneficiaries remain explicit.
The assessment reports **104 local issues and nine external obligations**, with
public and coalition query totals unknown and qualification HOLD.

The inspection itself recomputes hashes to check the old observations. These
new inspection hashes are excluded from the original experiment's query counts
and original physical-cost measurements.

## 4. Validation record and preserved failures

The focused standard-library suites passed **100 tests**: 41 inspector tests,
41 accounting tests and 18 reanalysis tests. Their retained logs are
[inspector](grouped-work-profile-v1-tests.log) and
[accounting plus reanalysis](grouped-fanout-integrity-and-reanalysis-tests.log).
An independent targeted review also rechecked the previously failing nested
cost cases, UNKNOWN propagation, aliases/cycles and half-open authorization
boundaries against the final inspector source.

The broader [initial local validation](local-validation-history/summary.json)
must not be called a complete PASS. All three discovery commands ran: 252
tests comprised 247 passes, three Git-context errors and two native skips.
The staging directory had no `.git` metadata or native binary. The complete
logs and source hashes are retained unchanged in
[local-validation-history](local-validation-history/SUMMARY.md).
The first complete-checkout validation on
`66b4f5a735d350849267e44526be2e12f1d076b5` ran all 24 original gates. It
recorded 23 PASS and one FAIL, with no unstarted commands or timeouts. The new
JSON configuration had not yet been listed in the generated distributed-source
inventory. All native tests, Python discovery, repository links, negative CI
controls and strict Clippy passed in that run. In particular, the original
three Git-context errors and two native skips were resolved: grouped discovery
passed all 210 tests with no skips. The inventory failure is retained separately
from the subsequent corrected-source validation; no gate is waived.
The [complete first-run capture](native-validation-source-v1.tar.gz) includes
all raw logs, source snapshots, runner bindings, the earlier launcher-only
path-assertion failure and the generator's exact one-path inventory correction.
Its [summary](native-validation-source-v1/summary.json) and
[24 command records](native-validation-source-v1/commands.json) are also
available separately. The capture's members were read back and SHA256-checked.

The corrected source, `ed2ed1ba614edb913b22b43b49bc3c7c43a0201f`, tree
`f272a84a69b034889413ab901793dffe1a5b591b`, then passed **all 24 original
gates**, with zero failed, unstarted or timed-out commands. Its complete
10,970-entry worktree (1,045,516,388 bytes) matched the committed source before
and after execution. The [successful capture](native-validation-source-v2.tar.gz),
[summary](native-validation-source-v2/summary.json),
[command receipts](native-validation-source-v2/commands.json) and
[test-count review](native-validation-source-v2/review.json) identify that exact
source; this publication adds the recorded evidence without changing its
implementation or configuration.

| Executed test group | Passed | Failed / skipped / ignored |
| --- | ---: | --- |
| Grouped Python and actual native integration | 210 | 0 |
| Conditional query bound | 21 | 0 |
| Fresh query floor | 27 | 0 |
| Resource transfer | 15 | 0 |
| Negative source-integrity controls | 43 | 0 |
| CI contract controls | 103 | 0 |
| Rust crypto, all targets and features | 243 | 0 |
| Native header binding | 1 | 0 |
| Native fresh admission | 14 | 0 |
| Native verification authority | 18 | 0 |

The 100 focused tests above are included in grouped discovery, not an additional
100 cases. Offline locked workspace and fuzz dependency graphs, formatting,
workspace Clippy with all targets/features and `-D warnings`, inventory,
repository/Markdown links and whitespace all passed. This is the retained
24-gate validation scope; it does not claim that the entire workspace's unit
test inventory or a new public service campaign was executed.

The existing `test_grouped*.py` CI discovery already includes every new test
module. No workflow, required gate or source-integrity check is weakened.

## 5. External obligations still open

The executable assessment lists all nine obligations explicitly:

1. Authenticated policy, task and target issuers.
2. Trusted prequery ordering and unomitted preprocessing.
3. Complete public coalition and assisting-query coverage.
4. Independent task supply and unbiased assignment.
5. Current target, task and consumer state at actual use.
6. Genuine demand, current consumer use and settlement.
7. Authenticated meters and complete resource transfer.
8. Cheapest legal implementation and physical-cost transfer.
9. Adopted native consensus profile registration.

The native owner's historical verification receipt does not prove current
authorization at later journal commit or FinalUse. Separate keys or names do
not prove independent operators. Local quotas do not establish public global
coverage. Passing a structural fixture cannot satisfy these external facts.
There is no Boolean input that enables qualification or positive chainwork.

The concurrent demand work was also checked for relevant acceptance evidence:
[demand/evaluation PR 777](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/777)
at `ce9b9f734b99c0c7d0c0264e2819020e0bb9a5db`, and
[native demand PR 779](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/779)
at `4a7e07e970d5bdb79626dda6bc98ae7906a02f18`. Their own review boundaries
still leave independent customers and external budgets, actual adoption and
complete physical costs unaccepted. Those parallel implementations are not
merged or rerun by this continuation, and their reported tests are not added
to this continuation's counts. They do not close the obligations above.

## 6. Reproduce the retained readings

Run from the repository root with new output paths outside the source checkout:

```bash
bash scripts/project-preflight.sh
PYTHONDONTWRITEBYTECODE=1 python3 \
  formal/pon-nakamoto-v1/experiments/reanalyze_grouped_fanout_v1.py \
  --input evidence/pon-resource-transfer-20261107/rog/key-records/fanout-exact-rog/report.json \
  --expected-sha256 915485a66d8b9ee4d1aadece413edb928274640a1830a840f818571b3042df96 \
  --out /absolute/new-output/fanout-reanalysis.json
PYTHONDONTWRITEBYTECODE=1 python3 \
  evidence/pon-security-work-metering-20261107/replay_retained_query_trace.py \
  --report evidence/pon-fresh-work-floor-20261107/fresh-work/report.json \
  --trace evidence/pon-fresh-work-floor-20261107/fresh-work/hash-transcript.ndjson \
  --out /absolute/new-output/query-reinspection
```

The reader outputs bind source hashes and the raw historical pins. Neither
command reruns the historical workload. The policy digest uses the inspector's
domain-separated `policy_digest()` and is not a raw JSON-file SHA256.
