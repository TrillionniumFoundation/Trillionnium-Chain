# Actual native owner observations, v1

Status: **local native execution and complete admitted-view observation;
world execution attestation and security qualification remain HOLD**.
Starting source: `f8362822b406463ac3dfcc911a0c3eda1686e32d`.
Date: 2026-11-07 UTC.

## 1. What this adds

The previous finite execution checker established the score-deficit identity
and fork-cut reductions on declared event records. It did not obtain the
complete candidate maximum from an actual native owner. This change adds a
read-only, bounded `Node::native_owner_census` API and an executable experiment
that actually calls native block production, admission, confirmation and
activation in two fresh local stores. Each returned census enumerates and
rechecks every admitted row in one source-schema-bound SQLite snapshot.

This is a concrete source of the local admitted-and-time-eligible maximum
`M_v` and selected score used by the deficit accounting. It is not an exporter
of all world-ready outputs, remote inventory, residual preprocessing state,
or authenticated physical time. The returned Rust type has private fields
and no `Deserialize`; serialized JSON can still be forged by somebody who
does not run the program. The evidence records actual calls, source/binary
bindings and refusal tests without equating those records with independent
trusted execution attestation.

The implementation is
[`native_owner_observation.rs`](../../trillionnium/crates/trnm-pon-node/src/store/native_owner_observation.rs).
The native experiment is
[`native_owner_observation_v1.rs`](../../trillionnium/crates/trnm-pon-node/examples/native_owner_observation_v1.rs),
using
[`native_owner_scenario.rs`](../../trillionnium/crates/trnm-pon-node/examples/support/native_owner_scenario.rs).
The integration tests are
[`native_owner_observation.rs`](../../trillionnium/crates/trnm-pon-node/tests/native_owner_observation.rs).

No consensus parameter, packet format, stored schema, signature domain,
activation rule or public request endpoint changes. The `Node` receives only
a lazy, volatile owner-observer identity/clock and an attempt counter.
That counter is local to the open owner and does not rewind with a reorg.

## 2. Scope and snapshot theorem

The initial API deliberately supports ordinary PNP1 nodes with the
`legacy-task-v1` relation on either `Legacy` or `AuthenticatedV1` storage.
PNP2 growth, PQ profiles, other task profiles, and policy/mining/continuous
owners are explicitly refused. The existing growth packet observer has a
different account-witness and retained-transition path; this PNP1 census
does not silently substitute for it.

An observation request supplies a validation clock `observed_now`, local
packet/row limits and a progress callback. The callback can implement the
original owner's deadline or CPU refusal. Maximum limits are 256 total
blocks, including genesis, and 16 MiB of retained packet bytes. These are
diagnostic limits, not protocol limits or physical memory/CPU guarantees.

The method performs the following steps in one held owner:

1. Validate scope and limits, allocate/increment this owner's process-local
   observation instance and attempt, and check native namespace/readiness.
2. Capture the connection epoch and open one SQLite read transaction. Compare
   the actual full SQLite schema with the selected backend's source DDL,
   instantiated in an ephemeral in-memory database exactly as at native cold
   open. The metadata schema hash alone is insufficient: an earlier filtering
   SQL view could otherwise hide a stored fork.
3. Read the active tip, generation and state slot, and enumerate the actual
   `blocks` table in parent-first height order with `LIMIT maximum+1`.
   Reaching the extra row or exceeding the byte budget refuses the entire
   request; no partial census is returned as complete.
4. Check genesis against actual configured initial state and zero chainwork.
   Re-read the active KV state and root. For every non-genesis row, decode
   the full stored native packet, recompute its actual native ID, validate
   parent/height/network/parameters, recompute branch target and MTP, and
   verify the complete PNW1 proof using the original verifier.
5. Use the original native parent/task binding and M06 execution to replay
   application state and receipts. Compare the resulting complete state and
   roots with the retained state, and compare all expected canonical delta
   rows with the stored delta rows. A corrupt retained proof is not trusted
   merely because its block ID already appears in `blocks`.
6. Recompute cumulative 512-bit chainwork using the original
   `required_work(target)` and checked addition. Accumulate timestamp
   eligibility through every parent; a current-time child of a deferred
   ancestor remains deferred. Derive active membership by actual parent
   traversal, and compute the maximum of the entire eligible admitted set.
7. Recheck tip/generation/slot, same-connection write count, schema version,
   and full source schema before output. Roll back the read transaction;
   never commit it. After release, recheck namespace, connection epoch and
   active view so a foreign data-changing SQLite commit hidden by the snapshot
   is not treated as absent. SQLite may elide a no-op update; the epoch is not
   an audit log of every foreign connection or transaction attempt.

**Local snapshot theorem.** Assume the native code, SQLite read semantics,
source configuration and held-owner/file-identity boundary operate as
specified. If the method returns successfully, there is one consistent
local database snapshot whose exact admitted row set is the exported set.
Each non-genesis row passed the full supported native relation replay, each
exported score equals the native required-work sum from genesis, and the
exported eligible maximum is the maximum over those rows under the supplied
validation clock. The exported active membership, generation and state slot
belong to that same snapshot. The local read transaction published no
database mutation.

**Argument.** Exact source-schema comparison prevents SQL substitution of a
filtered relation. Enumeration reaches EOF within the bound, rather than
silently truncating; every enumerated row is either completely checked or
causes whole-request failure. The genesis base case and checked parent-first
score recurrence prove the score identity inductively. The conjunction of
parent eligibility and the current header timestamp gives full-ancestry
eligibility inductively. No invalid row is discarded to make the maximum
smaller. Active membership follows the checked parent map. All reads share
one transaction; pre-output and post-release fences protect its owner/view
binding. Rollback with no successful write-count change prevents this query
from committing callback writes. This proves the stated local snapshot
claim and no larger world claim.

Completeness means **all admitted rows currently present in this snapshot**.
It is not completeness of every block ever admitted, bytes already received
but not admitted, pending verification or execution jobs, mined but withheld
packets, or any remote owner. Historical deletions or pruning are not erased
from the world-ready ledger by a current local census. Arbitrary tampering
outside the database/owner assumptions is not authenticated by file inode
numbers or an ordinary source hash.

The API is explicit local diagnostic work. It is not placed on an unmetered
public read lane. Full native state reconstruction and commitment work may
still contain bounded nonpreemptive stages; the row/packet limits do not
claim an RSS or worst-case latency bound.

## 3. Exported identities, clocks and maxima

`pon-native-owner-census-v1` exports:

| Field group | Actual source and meaning |
| --- | --- |
| `network`, `parameters`, `genesis`, `state_backend`, `task_profile` | The opened native owner's settings and selected backend. |
| `owner_process_id`, `owner_observation_instance`, `owner_attempt` | A private process-local observation identity and monotone attempt count, distinct after a reopen. They are not a globally authenticated principal. |
| Directory/database/lock device and inode fields | The identities bound to this actual owner; the namespace checks compare the files with the held owner lock. |
| `started_ns`, `ended_ns` | Actual `Instant` elapsed time within this owner observation process. No cross-process synchronization or trusted timestamp assertion. |
| `observed_now`, `future_skew_seconds` | Caller-supplied native validation time and actual installed future-skew setting. This clock is explicitly separate from the `Instant` interval. |
| `confirmation_depth`, `confirmation_work_multiplier` | Actual native settings, exported for independent recomputation of the existing two-condition confirmation rule. |
| `active_tip`, `active_generation`, `state_slot`, `active_score_hex` | Actual native active row plus fully checked current state. |
| `rows` | Genesis and every checked admitted block: native ID, parent, height, target, timestamp, exact 512-bit BE work/score, packet/proof SHA-256, ancestry eligibility, and active membership. |
| `eligible_max_score_hex`, `eligible_max_ids` | Maximum and all maximizers over this exact eligible admitted set, including genesis. |
| `raw_selection_deficit_hex` | Maximum minus selected score, only when the selected chain itself is eligible. Otherwise `null`; no negative lag or valid-observation fiction. |
| `local_view_commitment` | A domain-separated commitment to the settings, active view, supplied validation time and complete ordered checked rows. Clock/attempt counters are excluded so an unchanged view has a stable comparison key. |

Native `Work` values are 64-byte big-endian values rendered as 128 lowercase
hex characters. The target is 32 bytes. The recurrence uses

\[
w(B)=\left\lfloor\frac{2^{256}}{T(B)+1}\right\rfloor,
\qquad S(B)=S(parent(B))+w(B),\qquad S(genesis)=0.
\]

Zero targets are refused by the native arithmetic. Genesis has no packet,
proof or target and is explicitly a zero-score special row; no full-work
replay is falsely claimed for it. This is the current native unit relation,
not the research MU1 `16*u` credit.

The sealed Rust output sets `complete_for_all_admitted_rows_in_snapshot`,
`local_candidate_relation_rechecked`, and `exact_source_schema_rechecked`
only after those checks finish. It always leaves remote/private coverage,
global first-ready, physical-clock authenticity, exported-artifact
authenticity, probabilistic environment and six-successor risk fields false.

## 4. Actual two-owner experiment

The native example creates two fresh temporary PNP1 stores. It executes the
original native producer and verifier, signed application transaction,
admission/state persistence, confirmations, strict activation and real
rollback. It does not inject synthetic block scores into a model tree.

The schedule first produces and activates `A1..A7` at Alice, with a real
signed transfer in `A1`. Native confirmation observes six successors and
the installed required-work threshold. Bob initially has only genesis.
Next, Bob actually produces and admits an independent legal `B1..B8` chain
without delivering it to Alice. Alice's complete local view commitment is
unchanged before and after this private remote construction.

Alice then admits `A8,A9` while leaving `A7` active. A future-dated descendant
and its individually current-time child are produced with complete valid
work and admitted using a later validation clock. At the earlier clock both
remain ancestry-deferred. An attempted activation returns `TIME_DEFERRED`.

After the real Bob packets are delivered and admitted at Alice, the seven-block
`B7` tie preserves `A7`. Submitting the eight-block `B8` causes an actual rollback
even though admitted eligible `A9` has greater score: the original activation
compares its submitted target with the incumbent. The census captures the
remaining score-selection deficit. A subsequent native confirmation reports
the original transaction as reorged. Advancing the supplied validation clock
makes the complete future branch eligible, while the selected tip remains
`B8` until another explicit activation.

In the retained run, each of these actual native blocks has weight 2. Thus
`A7` has score 14, admitted `A9` has score 18, selected `B8` has score 16,
and the fully mature eleven-block branch has score 22. These values are
derived from captured native targets; they are not the unit-weight constants
of the earlier model fixtures. The observed selection deficits are 4 while
`A7` remains selected below `A9`, 2 after the strict `B8` rollback, and 6 after
future eligibility matures without another activation.

The schedule also submits a malformed product claim through actual native
admission and preserves the refusal, tests a cancelled census, and exhausts
a census row budget. The raw original and malformed packet bytes are saved
with SHA-256 and native-ID metadata. Local admission and local output
observation times are **not** relabeled as global first-ready times.

The run schema is `pon-native-owner-observation-run-v1`, with:

- `snapshots: [{name,node,census}]`;
- `confirmations`: actual native `Observation` outputs, including their
  transaction, target block, selected tip, generation and validation clock;
- `scenarios: [{name,reference_snapshot,confirmation_index,competing_snapshot}]`;
- `references`: explicit target/transaction IDs, hidden/future branch IDs,
  and named hidden-before/hidden-after snapshots;
- `operations`: actual call ordering, local `Instant` intervals, inputs and
  native success/error results;
- `packet_artifacts`: native packet identities, exact hashes, sizes and paths.

The actual generation/tip/clock tuple of the initial confirmation matches
`alice_confirmed_a7`, the reference snapshot used by all paired scenarios.
An independent bridge may compute later visible containing-`b` baselines
from a competing census; it must not retroactively place those candidates in
the initial confirming view.

The schedules and block-header timestamps are controlled experiment inputs.
Their numeric spacing is not elapsed production time, a live mining rate,
or a probabilistic network-delay measurement. `native_execution_exercised`
means these native functions actually ran; `native_runtime_attested` remains
false because no independent trusted exporter is supplied.

## 5. What can and cannot be composed

This output can substantiate a local score identity and admitted-view maximum
at each successful census. For a node whose active chain is eligible, its
`M-S(D)` is an actual locally measured score-selection deficit. A native
paired observation can therefore be inserted into the deterministic score
identities of
[`NATIVE_EXECUTION_CERTIFICATE_V1.md`](NATIVE_EXECUTION_CERTIFICATE_V1.md),
provided identities and native weights are preserved.

It cannot populate the all-world initial inventory `B0`, first-ready
adversarial process `A`, honest off-branch process, residual potential `V_tau`,
or a global proof/validation/publication delay envelope merely by counting
local admission events. An already ready remote packet can be delivered
later, and a complete local packet may sit outside the admitted table.
Selection queueing and admission delay must remain explicitly charged.

The unchanged Alice local view before/after the actually constructed hidden
Bob chain gives a concrete observation for the indistinguishable-extension
argument: no function of that local view can uniquely determine the hidden
world inventory or future publication choice. The experiment does not assert
that its two different timestamped JSON snapshots are byte-identical; the
stable logical view commitment is what remains identical.

Likewise, a private Rust constructor and packet hashes authenticate neither
the published JSON artifact nor the physical machine. A trusted external
exporter, clock/owner binding and complete-scope contract are still separate
requirements. Actual signed resource receipts for individual checks do not
prove a universal minimum resource cost for every valid producer.

## 6. Reproduction and resource scope

From the repository root, with a managed Rust toolchain and private Cargo
home/target:

```sh
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test native_owner_observation
cargo run --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --example native_owner_observation_v1 -- NEW_OUTPUT_JSON
```

The example refuses to overwrite its output or packet artifacts. A failed
attempt's logs and any reserved output remain available for diagnosis.
The integration tests run the actual supported native relation and include
full retained-product corruption, retained work/packet failure, prior SQL
view substitution, foreign-commit detection after read-snapshot release,
limits/cancellation, owner reopening, both supported storage backends and an
explicit unsupported-growth refusal.

The retained evidence records the exact toolchain, Cargo graph, build
commands, output hashes and any explicit low-memory compilation settings.
An optimization/debug setting used for this local experiment is not a
consensus change and must not be interpreted as a production performance
certificate. No elapsed measurement here is substituted into a six-successor
risk formula.
