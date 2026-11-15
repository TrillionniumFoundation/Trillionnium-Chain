# System security and incentive continuation

**HOLD / NO-GO. This is a review candidate above #908 C5.** The runtime and
native observations are bound to immutable source commits. Passing component
controls does not qualify continuous public service, independent custody,
model generalization or whole-chain security.

## Implemented changes

The V5 witnessed Root owner now exposes a bounded historical provider-readback
route. It authenticates live witness/local Root/anchor agreement around the
enrollment lookup and on both sides of the provider callback, enforces
provider/witness key separation, preserves the original operation and material,
and keeps pending/Unknown/no-redispatch semantics. It grants no effect authority.
The witness does not commit every provider-journal head. Cold provider-history
loss still requires the external system to reconcile that same operation.
See the [Root implementation and original observations](../pq-root-witness-provider-readback-20261112/README.md)
and the [new fixed-source Root observations](ai395/root-native/README.md).

Five existing strict portable SQLite openers now reject every existing sidecar
object, including dangling symbolic links. Only an actual `NotFound` metadata
result permits the open to continue; other inspection errors fail closed. DA
sidecar names preserve the original OS path bytes, including non-UTF-8 names.
The five owners are DA, MVCC/Fee, ServiceSettlement, TaskKernel and Task archive.
Other ordinary WAL users keep their existing contract. This repair does not
close the check/open race or reproduce the bundled-SQLite advisory.
See the [original failure-to-repair observations](../sqlite-open-boundary-20261112/README.md)
and the [combined-source SQLite observations](ai395/sqlite/README.md).

The incentive changes strengthen the existing full-roster commit/reveal
regression and retain an admitted V4 source-splitting counterexample. They do
not change historical reward rules. See the
[original incentive observations](../chain-incentive-counterexamples-20261112/README.md)
and the [new fixed-source observations and pinned Python checks](ai395/incentives/README.md).

## Actual execution on one frozen source

Runtime composition checkpoint:
`813620f387199bef3eae2493e2af07c70444db58`.

The combined metadata successor used for the new AI395 native runs in the following table is
`bac6b7659bd7e2d633e25c2da0add60f6a10c7fb`, tree
`371c3f55de7940e276496efe2008b537ba4d8268`. Its full physical-source checks cover
28,327 tracked entries and 2,578,801,275 bytes. The observed before/after checks
match. Later evidence-only commits retain distinct identities and do not
replace this native source.

| Component | Actual result at `bac6b765…` | Scope |
| --- | --- | --- |
| Root V5 original runner | 37 passed: 17 fresh witness + 12 durable witness + 8 witnessed provider readback | Real PQ signatures and SQLite/files, with an in-process witness fixture. |
| Root V4 original complete runner | 29 passed: 9 recovery floor + 14 provider + 6 callback budget | Original runner, feature and 1,200-second per-target timeout retained. |
| SQLite | 17 focused + 15 retained methods passed | Default-feature controls for the four owner packages and five strict openers. |
| Incentives | 31 Rust methods passed | M06 quorum 9, V5 evolution 4, V4 composition 5; Node V4 composition 5 and public evaluation 8. |
| Strict Clippy | Workspace, all targets, all features passed with `-D warnings`; four SQLite owner packages also passed their recorded strict checks | Actual Rust/Cargo/Clippy 1.95 binaries and original feature scopes recorded. |
| Pinned Python comparison | 8 composition-oracle + 5 native-differential checks passed; independent split recomputation passed; all 6 mutations rejected | Python 3.12, NumPy 1.26.4 and cryptography 50.0.2; same 13 native input files and run identity. |

The new Rust scope contains **129 distinct methods: 66 Root + 32 SQLite + 31
incentive methods**. An earlier scoped provider-14 command also passed, so the
Root archives contain 80 method executions with 14 duplicates. That earlier
command did not enforce the full V4 runner's outer per-target timeout. Its
original `v4_complete_inventory_passed` field refers only to its selected
PROVIDER inventory, not all 29 V4 controls. The raw observation is unchanged;
the later complete original runner is recorded separately.

The original Cargo profiles and assertions were retained and the target
directory was reused. These are component executions on a build host, not a
new service campaign under the original 0.25-CPU bound. The initial system
Python checks used different dependency versions and remain separately scoped;
only the isolated pinned-environment results support the CI-requirements claim.
The repeated Python observations consume the same native bytes and do not add
Rust methods.

The [source-freeze archive](ai395/source-freeze/README.md) preserves the original
metadata refusal, its narrow correction and the `bac6b765…` source gates:
65 authority/Root/V5-runner controls, 43 source-integrity rejection controls,
positive authority/Root/corpus checks, formatting, links and both locked Cargo
graphs. The [provider archive](ai395/provider/README.md) is preparation and
ML-DSA-65 smoke evidence only; it is not substituted for the Root native runs.

## Service liveness remains an observed failure

The [canonical service report](liveness/README.md) rereads the complete original
archive from source `53e1b98a…`. It is not a fresh execution of this candidate.

| Original campaign observation | Result |
| --- | --- |
| Complete campaigns / phases | 0/3 campaigns; 0/9 phases |
| Timely confirmations | 3/27 |
| Receiver/client final-state equality | 0/9 |
| History response / actual native import | 47/47 RPC responses; 41/47 imports; 6 `PUBLIC_REQUEST_DEADLINE` failures |
| Submit / timely ACK | 83 Submits; 80 timely ACKs |
| Accepted full-work records | 82, all matching original honest-body digests; zero unmatched or dropped records |

Matching a body digest does not identify an honest submitting actor. The three
confirmations concern the same fixture transaction and carry neither finality
nor execution authority. The no-attacker baseline also fails, so the archive
does not attribute all liveness failures exclusively to attackers. Checkpoint
CPU is nested within importer CPU and cannot be added to it or treated as a
proven removable fraction. The original limits, deadlines and failure records
remain unchanged. The inherited C5 ordinary PNQ2 failures are not repaired or
rerun by these component tests.

## An already known source can still benefit from V4 splitting

In the admitted fixture, `(A, B)` and `(A + Z, -Z, B)` produce the same full
model bytes and artifact. Authors of the two split components already share
the same installed source identity. The signed publisher authorizes the same
100,000-unit budget.

| Same source's result | `(A, B)` | `(A + Z, -Z, B)` |
| --- | ---: | ---: |
| Gross reward | 66,666 | 96,551 |
| Fees charged to its fixture accounts | 6,615 | 9,686 |
| Combined account increase | 60,051 | 86,865 |
| Source intake count / cap | 1 / 4 | 2 / 4 |
| Reserved reward / source budget | 66,666 / 100,000 | 96,551 / 100,000 |

The net difference is **26,814 development-ledger units**. Total claims are
99,999 and dust is 1 in both cases. Source caps remain enforced. This is not a
cap bypass, signature forgery, unwilling debit or a discovery of hidden common
control. Training and operating costs are not measured, so these figures do
not establish real-world profit.

The control starts from ordinary Node genesis and then exercises contiguous
signed M06 admission, complete-roster commit/reveal, authorized funding and
actual claim transitions. It does
not cover ordinary Node Submit, PNW1 verification or independent History.
Passing this control means the counterexample remains reproducible.

A successor needs an explicitly specified rule that aggregates complete
parent-relative updates by known source **before** source-level omission and
allocation, followed by authorized payee and intra-source allocation rules and
fresh protocol namespaces. Equivalent partitions of the same source update
must preserve its gross entitlement and source-level budget reservation. The
successor must specify source-level rounding and dust conservation before
authorized intra-source allocation. Summing component weights after omission
does not repair this example. That successor rule is not implemented in this candidate.

The historical revision3 native/reference controls also reproduce the
`{10,100}` ordering outcome set. They record producer influence over reward,
not nondeterminism for the same ordered block. These revision3 results are
retained observations from their earlier recorded source. They were not rerun
in this bac6 campaign and are not additional methods in its 31-test incentive
total. The fixed 25-row saturation statement applies to the retained public V4
fixture and its strict-improvement metric. Existing revision16/V5
owner-pinned task-window controls have a different scope and do not, by
themselves, qualify independent generalization.

## Remaining qualification obligations

Root signatures authenticate authorization and bytes; freshness depends on an
independently surviving authority. Both the surviving-floor rejection and the
common-restore acceptance counterexample remain in the suite. Different key
families and public keys do not establish independent administrators, devices,
backups or recovery permissions.

Independent freshness custody, new entropy after recovery, witness daemon and
wire assembly, ordinary M15/effect-sink entry and actual external-effect
reconciliation remain open. SQL rollback does not undo an already emitted
external action. Unknown grants no authority to retry under a new nonce.
Cold provider-journal rollback remains a separate reconciliation obligation.

Service completion under the original total resource bounds, identification of
unknown common controllers, prospective model value, Shapley fairness,
permissionless Sybil resistance and long-term economic supply remain unqualified.
The component passes and finite counterexamples do not remove these obligations.

## Preservation and dependency boundary

The original cloud attempts remain in their original evidence directories:
Root executed zero libtest cases before interruption/compiler `SIGKILL`;
the original SQLite strict-Clippy attempt lacks a completed receipt. No cause
beyond the observed signal is asserted. The original SQLite 17 + 15 positive
observations used a partial checkout with 297 selected guards, and its initial
DA negative observation predates those guards. The new complete-checkout runs
are separate observations.

The temporary cloud outages did not justify reconstructing a historical source
identity. All original tested commits and their evidence ancestry were retained
in the integration candidate; the source-similar SQLite fallback was never
applied or tested. Two initially copied service-reader files contained an extra
trailing LF. Exact upstream bytes were restored, the entire original ZIP was
read again with byte-identical output, and thirteen reader controls passed.
The mismatch and correction remain in [reader provenance](liveness/reader-payloads.json).

At the retained repository readback, main `dd6e1c3…` has bundled
`libsqlite3-sys 0.30.1`; #900 has 0.39.1 and #901/C5 have 0.39.0. Both candidate
versions meet [RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459.html)'s
repaired version range. This candidate inherits the C5 dependency graph; the
opener repair is a separate change, and no local memory-exposure exploit or
remote consensus exploit was reproduced.

The retained #900 quality failure identifies `rustix 1.1.4` under
[RUSTSEC-2026-0486](https://rustsec.org/advisories/RUSTSEC-2026-0486.html), not an
unrepaired SQLite version. C5 already uses rustix 1.1.6. Candidate fixes do not
change main's recorded dependency state.

## Raw log formatting preservation

The first evidence integration stopped at a parent-added generic whitespace
check before committing. Its 71 diagnostics concern exactly four original PTY
CRLF logs and nineteen original Rust logs with a final blank line. All raw bytes
and their manifest hashes remain unchanged. The continuation reconciled the
staged set and all 182 published payloads, classified the exact diagnostic
bytes, and applied the original whitespace check to every other staged file.
The repository hooks and Git whitespace settings were not changed. See the
[raw log review](ai395/final-integration/raw-log-whitespace-review.json) and
[continuation driver](ai395/final-integration/integration-continuation.py).
The failed operation and its command receipts are retained with the final
source-gate provenance; this formatting observation is not a native test failure.

## Final committed source-gate observation

The full source-only run executed at `2d72fa3293989b01596ec8ce0ba3ff370dc4c584`
(tree `ebc11e05eb0015ae5be58ca85ed764e06f4386be`). All ten recorded
commands returned zero: positive authority/Root/corpus checks, 65 authority,
Root and V5-runner controls, 43 source-integrity controls, repository links,
Cargo formatting, and default/all-features locked dependency graphs, including
preflight. Each command recorded the complete physical source before and after.
The 108 controls belong to this exact F commit; they are not new native tests.

The original outer driver returned 1 and retained all_gates_passed=false:
its parser incorrectly required the entire unittest log to end at OK. The 43
source-integrity methods each passed and their single OK summary was followed
by six expected fixture receipt JSON lines. A separate derived qualification
hash-binds and rereads those original bytes, the 65/43 exact test inventories
and all ten command/source receipts. It verifies 108 controls without rerunning
them or changing the original failed aggregate receipt. Both observations and
the corrected reader are retained in the final source evidence.

The [final source evidence](ai395/final-source/README.md) preserves the raw
commands and the initially failed evidence integration plus its successful
continuation. This evidence-only successor keeps trillionnium, formal and
scripts/ci bytes identical to the actual native source `bac6b7659bd7e2d633e25c2da0add60f6a10c7fb`.
Its separate final identity, restricted corpus delta and source/link checks are
recorded by the publication process; those checks do not relabel the F control
run or the 129 native Rust methods. Status remains **HOLD**.

The first evidence-child admission stopped before any repository mutation because
an optional transient Cargo lock file was absent. Its clean F snapshot, actual
exit 1, inputs, driver and complete output are preserved in the
[admission failure record](ai395/final-source/failed-admission-v2-README.md).
After all native/source owners released the checkout, the continuation used a
dedicated outside integration lock; no build or test was rerun.
