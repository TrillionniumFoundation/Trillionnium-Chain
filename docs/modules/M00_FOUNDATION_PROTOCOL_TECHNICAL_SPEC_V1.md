# M00 Protocol bytes and state commitments

Revision: invariant-driven revision3. Selected target: `pon-nakamoto-v1`.
[Sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md); [exact invariant registry](../../config/pon/invariants-v2.json).

## Scope and ownership

Native/Python codecs and pure in-memory state commitments, not application acceptance or native persistent storage.

The claims below apply to their named component and tests, not to an independently accepted full native node.

## PoN State machine

### M00.DecodeHeader

Require PNH1/version1 and exactly318 bytes; decode the twelve fixed fields at the published offsets; compute challenge only from those bytes; no field normalization.

**Atomic/commit boundary:** None; codec has no database.

### M00.DecodeTransaction

Read 95-byte prefix, match exact tag-specific payload length and bounded proof/list count, require nonce>0 and fee cap, then separate final64 signature bytes. Signature verification belongs to admission.

**Atomic/commit boundary:** None; decode success cannot reserve nonce or funds.

## M00.CanonicalBytes

**Invariant:** Replacing any header field changes its challenge; malformed transaction bytes reject without nonce or balance authority. Incremental compressed commitments equal the full state-root builder; failed batches preserve immutable predecessor snapshots.

**Scope:** Native/Python codecs and pure in-memory state commitments, not application acceptance or native persistent storage.

**Atomic boundary:** Decode is pure and bounded; signature verification and state publication are later independent boundaries. StateTree checks the whole before/root batch before returning a staged immutable tree.

**Failure schedule:** Every header field mutation; Truncation, trailing bytes, zero nonce, unknown tag.

**Expected result:** Replacing any header field changes its challenge; malformed transaction bytes reject without nonce or balance authority. Incremental compressed commitments equal the full state-root builder; failed batches preserve immutable predecessor snapshots.

**Resource and retention rule:** 318-byte header, 2048-byte envelope; original twelve tags plus explicit context-gated native
extensions13..23. V3 tag22 is exact1028B; standalone19 is refused in V3 execution.
Tag23 is the explicit revision11 [integer factor witness](../protocol/pon-nakamoto-v1/details/NATIVE_INTEGER_FACTOR_CANDIDATE_V2.md),
with921/1441B signed envelopes; ILF2 decoding alone grants no model or parent authority.
See [V3 codec/activation](../protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V3.md).

## Concrete regression selectors

`formal/pon-nakamoto-v1/test_contracts.py::CodecTests.test_header_mutations_bind_all_fields`

`formal/pon-nakamoto-v1/test_interop.py::InteropTests.test_rejection_vectors`

These exact functions contain executable assertions. The registry only checks binding; actual outcomes and source/input identities belong to the separate qualification report.

## Module-specific threat and residual work

Encoding ambiguity, cross-genesis replay and unsafe unversioned upgrades.

Third-party verifier and production upgrade policy remain unaccepted.

## Current source and verification

- [`trillionnium/crates/trnm-protocol/src/pon_wire.rs`](../../trillionnium/crates/trnm-protocol/src/pon_wire.rs).
- [`formal/pon-nakamoto-v1/contract_wire.py`](../../formal/pon-nakamoto-v1/contract_wire.py).

No test binding or local campaign grants independent acceptance, ordinary Hepta execution or production activation. Preserve the exact source, profile and environment of every outcome.

## Executed evidence and scope

[Responsibility-level evidence navigation](README.md#responsibility-and-evidence) reads
measured commits from immutable receipts. The module's entries in
[module-maturity-v1.json](../../config/pon/module-maturity-v1.json) identify actual callable
owners, controlled entrypoints, backends, persistence and exact observed test selectors.
Run `python3 scripts/ci/report_module_evidence.py --module M00` from the repository
root to see subject-byte and complete recorded-runtime matches separately, plus scenarios
not observed in each package. A byte match is not a new test run or product acceptance.
Historical v1/v3/v4 results are never repinned. The sole plan selects further work.

## Native cache / receiver continuation

The exact continuation is specified in [native execution](../protocol/pon-nakamoto-v1/details/EXECUTION_PARALLEL.md), [admission](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md) and [client/recovery](../protocol/pon-nakamoto-v1/details/NETWORK_CLIENT.md). It does not promote native persistence, independent acceptance or public-network capacity. Exact additional counterexamples:

- `trillionnium/crates/trnm-protocol/src/pon_state.rs::mixed_batches_match_full_builder_and_inverse_restores_predecessor`.
- `trillionnium/crates/trnm-protocol/src/pon_state.rs::all_deletions_return_empty_and_values_remain_bounded`.

## Complete state-root constants and exact node encoding

M00 retains the full canonical root operation and its existing M06/M07 consumers.
The private node encoder writes the exact94-byte preimage of
`H("state-node", left, right)` into one fixed buffer: the original domain,
LE16 tag length, ten-byte tag, LE32 child lengths and ordered32-byte children.
The generic domain hash and all header, transaction, work and leaf encodings are
unchanged. The full root borrows one immutable257-entry empty-subtree table,
derived once from the same compiled grammar. Its value payload is8,224 bytes;
OnceLock metadata, stack, allocator and RSS are separate accounting domains.

No State, SQL row, block identifier, clock, currentness verdict or successful
validation is cached. Every input row, limit, duplicate hash path, canonical
value check and complete root reconstruction remains required. Empty values
remain distinct from absent leaves. Failures and iterator cancellation return no
partial root. Single-writer transactions, actual stored-byte rereads, pre-COMMIT
fences and cold recovery are unchanged. This is not incremental full-history
validation, a larger protocol state limit or a new authenticated storage schema.

All original codec and streamed-root tests and the complete original root
algorithm remain unchanged. The existing module adds exact single-bit/order and
deterministic-pair encoding checks, all257 empty depths with concurrent readers,
and warmed-root value/absence/overflow/cancellation/duplicate controls:

- `pon_wire::streamed_state_root_tests::state_node_single_buffer_matches_original_wire`.
- `pon_wire::streamed_state_root_tests::state_empty_constants_match_all_depths_and_parallel_callers`.
- `pon_wire::streamed_state_root_tests::state_root_constants_do_not_cache_values_or_failures`.

The explicit release-only
`pon_wire::streamed_state_root_tests::state_node_and_complete_root_paired_cost_observation`
compares16 complete33-key roots per arm in eight alternating-order pairs. Both
arms read the same unchanged map and must match the independently reconstructed
root. The new arm is warmed before timing; the old arm rebuilds its own constants
on every call as originally implemented. Raw time is descriptive, not a speed
threshold, public-service result, saturated TPS or a claim of physical minimum
work cost. No result is inferred before the named native test actually executes.

The existing four-lane branch-encoding workflow binds the exact protocol source,
runs all retained wire tests, each new nonempty selector, the explicit paired
observation and strict all-target/all-feature Clippy. Original public-service
workloads, deadlines, CPU reserves, capacity/history campaigns and complete
baselines remain mandatory on each final source and actual main merge. The
Hepta consumer must pin that exact tuple and rerun its own retained checks.
Prior failures and cancellations remain separate; no independent model adoption,
future-task custody, physical power loss, DA or WAN acceptance follows from this
encoding change.
