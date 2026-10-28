# History Startup CPU, cancellation and material reuse audit

This records the original source audit and its subsequent implementation
candidate. The audit's base is frozen History candidate
`1521ae83831a060e2e8afeabeb130591dc783823`, tree
`73c47f12954a93c98a2ea9f026fbb769eabc6e4e`. The measured runtime remains
`8d7741028eb650f0600e61fcab46ff3d14b50767`, binary SHA-256
`136bbeb0b474dc9d0bcb3c254ab3bf21d47666f4fb4e04957752f69ea905729b`.
The previous complete local batch remains 14 passed / 1 failed / 1 ignored.
The independently built frozen runtime subsequently passed its complete release
group, as recorded in the [original hosted readback](../../../../evidence/pon-history-hosted-afc8d6d-20261028/README.md).
That result does not qualify the new implementation. The
[new candidate evidence](../../../../evidence/pon-history-startup-native-20261028/README.md)
records nine current-source material tests passed, with the new Node still
awaiting its independent compilation and full original-budget native gate.
The [development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
remains the sole plan. [Audit source pins](../../../../evidence/pon-history-startup-audit-20261028/source-audit.json)
identify the inspected bytes.

## Evidence-supported problem

The retained [Startup observation](../../../../evidence/pon-history-publication-native-20261028/startup-capacity-observation.json)
contains 2,087,314,423 ns owner/total CPU, zero worker CPU, a 2,000,000,000 ns local
burst, a 4,000,000,000 ns signed operation allowance and an actual
`PUBLIC_MUTATION_CPU_BUDGET` refusal. Live-paid CPU is 2,086,987,006 ns and residual
CPU is 327,417 ns. Accounting is available. This is a regular resumed Startup in
the older `publication-intent-final-synced` case; it does not invoke the new
settled-epoch reconciliation API. Its one isolated retry failed before Startup
because the original strict process observer could not obtain the required graph.

The observed store contains one genesis block, ten KV rows, one 3,479-byte snapshot,
no effect markers and no pending reorg or peer queues. Its checkpoint material is
663,663 bytes; model and input are each 16,384 bytes. These facts rule out explaining
this particular failure as traversal of a large existing History journal/store.
They do not assign CPU time to individual functions. The local binary uses package
opt-level 0; its elapsed times are not release-performance measurements.

## Frozen call chain before this implementation

[HistoryEffectV6::open](../../../../trillionnium/crates/trnm-pon-node/src/store/history_effect_v6.rs)
opens and replays the journal, reserves the complete Startup allowance, constructs
a zero-credit CPU epoch and waits for the original stored credit. It then starts
one `ServiceMutationCpuOperation`. Material verification, Settings construction,
native open and final frontier checks are inside that operation. Journal reservation
precedes the measured interval; an optimization must not describe reservation CPU
as already covered by the operation's owner stamp.

The first local `progress` closure checks the absolute deadline, signed operation
and budget expiry, the **same** CPU operation's checkpoint and its signed CPU
allowance. `verify_catalog_bound` and `HeldCatalog::read_role` call this closure.
The closure is not forwarded into the Settings/material derivation below it.

[Settings::development_with_operator_checkpoint_tile](../../../../trillionnium/crates/trnm-pon-node/src/operator_checkpoint_tile.rs)
calls `prepare`, and `prepare` calls `CheckpointTileRuntimePaths::replay`. That
replay validates model/input hashes, reads activation bytes, opens the checkpoint
with no-follow flags, checks file mode/link count/size, derives the full checked
material, rechecks metadata and validates policy. Its progress callback checks a
90-second wall limit. It does not call the History CPU or cancellation checkpoint.
The Settings constructor subsequently verifies requester/bootstrap signatures,
builds the initial State and computes genesis.

[Node::open_selected](../../../../trillionnium/crates/trnm-pon-node/src/store.rs)
checks the History owner once, then calls `Settings::replay_checkpoint_tile_material`.
That method calls the same full material replay a second time and discards its
checked result. The first and second calls do not share a private checked material
object or a retained material-file proof.

After opening SQLite, Node calls `read_active`, performs existing replay/outbox/
budget validation, calls `recover`, then calls `read_active` again. History V6
`recover` only checks its owner and returns the current active frontier. Both
`read_active` calls still verify namespace, actual State, continuity, commitment
and tip/generation/slot stability; neither can simply be removed on the basis that
this recovery branch does not activate a block. Their default progress callback
is `Ok(())` even though `read_active_with_progress` already exists.

[HeldCatalog::ready](../../../../trillionnium/crates/trnm-pon-node/src/operator_continuous_policy.rs)
checks held/visible metadata for every retained role. It does not hash all bytes
on each call. `read_role` reads through a retained file, with a progress checkpoint
at each 65,536-byte buffer, then checks metadata and exact length again. Treating
`ready` as repeated full-content hashing would overstate the possible saving.

### Interior gaps in the existing material callback

[derive_checkpoint_tile_material_v1](../../../../trillionnium/crates/trnm-mvcc-fee/src/checkpoint_tile_material_v1.rs)
already takes `FnMut(u64) -> MaterialResult<()>`. The callback runs after the
header read and after each full-checkpoint buffer, currently 1 MiB. The current
source has additional work between or after those callbacks:

- Activation JSON validation and byte decoding occur before the first callback.
- Strict unique-key JSON parsing and tensor-header validation occur after the
  header callback and before the full-file scan.
- The final matrix quantization, all-activation nonfinite scan, exact A/B comparison,
  task-ID derivation and canonical descriptor construction occur after the last
  full-file callback.

The parser's existing byte, depth, array, map, tensor and descriptor limits must
remain. Forwarding the outer callback alone does not establish prompt cancellation
inside all these stages. For this small fixture, the entire checkpoint fits in one
existing scan buffer; that makes the interior-stage distinction material.

## First implementation boundary: propagate original resource checks

Introduce internal replay/prepare/Settings entry points with an explicit resource
callback. The public offline preparation path can retain its existing wall-bound
policy, while the History caller supplies its original Startup checkpoint. Do not
create another CPU domain, operation, allowance or worker registration to measure
the replay. All costs, including additional checks and hashing, remain in the
original operation and its final residual settlement.

These are cooperative checks, not a hard scheduler cutoff. Signature verification,
root arithmetic and any other indivisible primitive still set a lower bound on
stop latency. Check before and after them, retain actual CPU including any refusal
overshoot, and measure the largest unchecked stage before making a latency claim.
The present `read_active_with_progress` explicitly treats root arithmetic as one
bounded stage; this audit does not silently claim it has interior cancellation.

The callback must check the same deadline, current issued/expires window, budget
expiry, actual live-paid CPU and operation allowance at each interior boundary.
Once an `Active` owner exists, use its existing cancellation flag and the same
checkpoint handle. During the earlier build phase, carry the same resource state
explicitly instead of switching to a new clock or no-op callback.

The existing `open` API returns only after Startup and exposes no cancellation
handle during Settings construction. Therefore interior cancellation during Startup
needs a separately reviewed, request-only cancellation input or an internal
`open_with_progress` owner hook. Such a handle must name the exact authenticated
Startup operation ID and must grant no execution, signature, nonce or CPU credit.
A default non-cancelling wrapper preserves existing callers. Merely forwarding
CPU checks does **not** prove that external Startup cancellation is now reachable.

Suggested checkpoints are before/after activation parsing, bounded strict-JSON
visitor work, tensor-header iterations, each bounded file chunk, batches of original
activation/weight values, task derivation, and descriptor validation. The parser
requires a checkpoint-aware seed/visitor or equivalently bounded parser mechanism;
surrounding a maximum-size parse with two callbacks is not an interior bound.
One static check per byte is unnecessarily expensive: the bound should count
bounded bytes/nodes or values, and its real maximum CPU/cancel latency must be
measured. A 64 KiB file quantum and 256-value quantization quantum are initial
engineering candidates, not qualified limits.

At Node open, call `read_active_with_progress` with the same History callback at
both current read sites. Keep the second read, root check and generation/slot
check. Audit the intervening schema, replay, queue, budget, ancestry and known-marker
loops for bounded checkpoints. SQLite progress callbacks, if added, must be tied
to this exact owner and translate interruption back into an owner-resource result;
they cannot silently turn resource refusal into evidence of invalid State.

### Error provenance is part of the change

The material callback returns a static-string error type, while History has a
richer `Error` and CPU settlement. A small adapter may retain the **first exact
owner error**, return a private sentinel to stop material work, then restore that
error at the node boundary. Do not reinterpret `CANCELLED`, expiry, clock failure
or exhausted CPU as an invalid checkpoint/signature/PoN result. Preserve any
already completed native outcome and the original operation's CPU receipt when
later settlement/readback fails, as required by the retained owner-error fixes.

An interruption before any native effect should settle the original known CPU
when possible. Unknown clocks still produce unavailable accounting and a durable
unresolved scope where appropriate. Drop, timeout, cancellation or a retry must
never manufacture zero CPU, return old predebits or create a fresh burst.

## Second implementation boundary: one-shot material proof reuse

The first replay already constructs `CheckedCheckpointTileMaterialV1`, whose
fields are private and which is not `Clone` or deserializable. `prepare` uses its
descriptor ID and drops the object. Retain that checked object inside a new private,
one-shot prepared-Startup value. This should flow only through the explicit History
Startup path and be consumed by the second Node boundary.

Do **not** put a reusable boolean, an arbitrary serialized descriptor, or a
`material_verified` flag on Settings. [Settings is Clone](../../../../trillionnium/crates/trnm-pon-node/src/lib.rs),
and existing callers use it outside History. An opaque prepared value containing
the owned Settings plus its one-shot seal avoids accidentally cloning authority or
allowing Settings mutation between sealing and use. Other Node entry points retain
their normal full replay. If an explicitly supplied seal is invalid, fail; do not
fall back in a way that hides a broken binding.

The seal itself grants no chain authority. Node must still possess the actual
authenticated, prepaid History owner and compare its current active operation to
the seal. Only the original verified path may construct the seal; it has no public
constructor or deserializer and should not be transferable to a worker thread.

| Binding | Required second-boundary check |
| --- | --- |
| Actual operation | Same journal identity, epoch, operation ID, nonce, intent digest, original CPU checkpoint and still-current signed window. |
| Execution context | Same canonical spec/bundle, app policy, task binding, model/input bytes, parameters/network/genesis and owned Settings. |
| Original material | Retained checkpoint and activation handles; no-follow visible paths; same dev/inode, type, owner, mode, link count, length and timestamps before and after re-read. |
| Content | **Recompute complete SHA-256 over actual current checkpoint and activation bytes**, and model/input/spec/bundle hashes. Same hash plus the private checked object permits reuse of deterministic derivation only. |
| Native authority | Verify the actual SQLite owner marker and externally signed frontier, including generation, when opening; keep the existing final frontier/reorg/known-marker checks. |
| Consumption | Move/consume the one-shot value. No global cache, saved token, restart reuse, copied epoch or cross-operation replay. |

Holding a file descriptor or making a value immutable in Rust does not prevent
external in-place writes. Metadata equality alone is insufficient; this design
retains the second full-byte hash and held-versus-visible checks. It also retains
the second active-State verification. The possible saving is repeated parse,
quantization, exact material derivation and associated object construction, not
skipping file identity, hashing, chain State or generation validation.

The retained original checked object proves the complete deterministic relation
for the pinned original bytes and exact context. The second hash proves that the
current bytes still satisfy the same content pins; current owner checks prove that
the same signed Startup remains active. These are separate obligations. A valid
material seal cannot stand in for parent eligibility, revocation, current chain
State, nonce freshness, recovery authority or final CPU settlement.

Any future attempt to reuse the first active-State read needs a different proof:
an explicitly held SQLite snapshot, exact raw-state/root binding, same namespace,
slot and generation, and final visible-state checks. That is excluded from the
first material-reuse implementation; the second full State read stays in place.

## Measurements needed before claiming a saving

Add test-only stage observations around catalog verification, first material
replay, bootstrap/signature construction, second content verification, SQLite
schema/open, each active-State read and final marker/frontier validation. Use
owner-thread CPU stamps from the same accounting infrastructure. Store counters
and labels in memory, then report the actual receipt; do not exclude observer CPU,
pause the meter or relabel a wall-time delta as CPU.

Stage intervals must be disjoint or explicitly marked nested so their sum is not
double counted. Retain a top-level full-operation measurement and any unassigned
residual. Record actual byte counts, callback counts, State rows and source/binary
identity. Compare the baseline and new release build on the same fixture/envelope
under the original limits. If the remaining legitimate work exceeds the original
burst, preserve the failure and design a separately authorized continuation; do
not add sleeps, split one signed operation into fresh epochs, or increase budgets
solely to produce a passing test.

## Acceptance and adversarial obligations

The implementation must exercise cancellation/refusal inside header parsing,
activation decoding, quantization, the second full hash and both active-State
reads. Tests should trigger the internal boundary deterministically, not wait for
an outer test timeout. Each path must retain the original predebit, known CPU or
honest unknown accounting, no fabricated validation fact, and joined original
workers. A subsequent operation requires its own fresh authorization.

Material proof controls must cover checkpoint/activation replacement, symlink or
hardlink alias changes, mode/owner/size changes, in-place content mutation during
the second scan, wrong spec/bundle/model/input, wrong operation/epoch/nonce/budget,
expired current authorization, wrong signed frontier/generation, cross-Startup
reuse and a stale or missing seal. Deterministic barriers should place mutations
between first derivation and second boundary and during the second read. Counters
must establish that complete second hashes and both State checks actually ran.

For valid unchanged inputs, descriptor IDs, Settings/genesis, task bindings,
accepted/rejected original material, journal semantics and next-task bytes must
match the original full-replay path. Existing malformed/duplicate JSON, tensor
coverage, nonfinite activation, matrix mismatch and exact task controls must keep
their original refusals. A new successful cache-like path without these negative
controls is insufficient.

Finally rerun the complete exact-source History suite in one batch: retain the
original 15 and add four mandatory Startup methods, requiring **19 passed,
0 failed, 1 ignored helper**, same 600-second full-suite outer bound, 2-second local
burst, 4-second fixture allowance, zero-credit epoch and maximum four process graph
snapshots. The current hosted workflow can supply that independent run. Formatting,
strict Clippy, locked graph and source-integrity gates still apply to the actual
implementation. Existing failed archives remain immutable. Passing this narrower
work still would not close pending Startup/Close recovery, multistep reorg or
whole-host capacity by implication.

## Implementation candidate and its current limits

The new Rust entry points propagate the original owner callback through activation
and header parsing, JSON byte reads and visitor traversal, tensor checks, full
checkpoint scanning, quantization, matrix/task binding and descriptor encoding.
Legacy callback entry points retain their original read-byte event sequence. A
request-only cancellation input is bound to the signed Startup operation ID.
Both actual State reads retain their complete content/generation checks and now
call the same live History owner. Initial catalog failures also preserve the first
actual CPU/cancellation error instead of converting it to a generic catalog error.

`PreparedHistoryCheckpoint` privately carries Settings and a consumed,
non-Clone/non-serializable material seal. The seal holds both original file handles,
exact metadata, the checked original material and the actual Startup CPU Arc,
intent, cancellation Arc, deadline and budget expiry. Consumption re-reads current
protected catalog roles, compares current Settings/context, performs complete
second checkpoint and activation hashes, and rechecks held/visible identities and
policy. The original namespace/frontier/generation checks remain after native
open. Generic Settings still use their original complete replay path.

This is cooperative cancellation, with bounded signature/root/sort primitives
still indivisible. Waiting for original zero-credit Startup refill is unchanged;
the new handle does not promise immediate cancellation of that wait. A known
failed Startup keeps its irreversible debit and open epoch, rather than inventing
a clean close. General recovery of that Startup/Close interval remains separate.
Neither the new Node path nor its four methods has been executed locally: disk
fell below the retained 256 MiB compilation stop line. The mandatory hosted gate
will compile the actual new source, retain its reconstructable release ELF, run
all 19 methods and all nine material tests, and require formatting and strict
Clippy. No performance saving or new History P0 closure is asserted before that
result. The original frozen publication and complete failure archives stay intact.
