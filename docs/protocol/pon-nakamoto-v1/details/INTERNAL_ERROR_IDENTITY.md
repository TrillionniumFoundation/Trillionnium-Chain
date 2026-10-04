# Native internal error identity

The native Node retains its existing display and wire error strings while
carrying `ErrorCode`, `ErrorKind` and an optional typed underlying cause in
`trnm-pon-node/src/error.rs`. This changes no signed domain, stored schema,
profile selection, error precedence or admission rule. A code identifies an
observed failure; it does not by itself establish remote authentication,
transaction non-entry, persistence, membership or permission to retry.

## Construction and scope

Exact registered local codes are classified once when constructed. There is no
prefix-based classification. Typed `std::io`, SQLite and JSON conversions keep
the original cause for `std::error::Error::source()` and preserve the respective
`IO: `, `STORAGE: ` and `JSON: ` display prefixes. Their message text is never
parsed as a protocol code. Thus an IO cause containing `FRAME_EOF` is still an
IO error and cannot acquire the local frame-EOF retry identity.

Known codes cover the decisions migrated below and selected protocol,
capacity, cancellation, context and identity failures. Other legacy strings,
including formatted work, task and authenticated-store diagnostics, remain
`Unclassified`; this is not a claim that every Node error producer has been
migrated. A new structural code must be registered explicitly rather than
inheriting a shutdown policy through its spelling.

Stored-data provenance is assigned where the Node has actually selected an existing
local record. `local_integrity` preserves the original diagnostic/code and typed cause
while marking a failed retained header, ancestry link, canonical KV/root, undo delta,
reorganization step or generation invariant as `LocalStructure`. The same code on a
new packet or unknown caller-supplied locator has no such authority. In particular,
`UNKNOWN_PARENT` from a missing ancestor of an already retained block stops the owner;
an ordinary unknown polling locator remains `StaleContext` and keeps its bounded
retry behavior. The polling lookup therefore tests both code and origin.

`local_replay_source` similarly keeps the typed replay/outbox reconstruction or
recovery cause and original `AUTH_REPLAY:`, `AUTH_RECOVERY:` and
`AUTH_OUTBOX_RECOVERY:` text. It is applied to local retained journals, not incoming
frame conflicts. No recovery/shutdown decision parses those prefixes. Progress
callbacks, visitor errors, cancellation, clock deferral and reorganization fault hooks
are deliberately outside these provenance conversions. Complete untrusted operations
must never be wrapped merely because they can also access the store.

The explicit revision14 composition refusals are also registered individually.
Configuration/profile/current-parent mismatches are stale context; missing bundle
gain, nonpositive marginal gain and exactly cancelling component subsets are policy
refusals. Invalid count/order/range/slot/state/derivation/weight are protocol failures.
None acquires local database-corruption or owner-stop authority, and these categories
do not grant a generic retry. Earlier profile codes and their wire strings are retained.

Remote business failures are marked `RemoteRefusal` at the existing validated
reply boundary. A remote message can retain a known code for the narrowly
permitted client response, but cannot become a local database/owner failure.
The existing authenticated session constructor derives terminal/retryable
identity from the already verified terminal flag, independently of error text.
Its `REMOTE_TERMINAL:` and `REMOTE_RETRYABLE:` display strings remain unchanged.

## Recovery decisions

| Path | Typed condition | Recovery behavior |
| --- | --- | --- |
| Pinned polling | Local owner, namespace/database replacement, storage or validated ancestry structure failure | Preserve failure/cursor, return error, stop shared runtime |
| Pinned polling | `ANCESTRY_INDEX_BUDGET` | Stop as before; kind is capacity, not a corruption diagnosis |
| Pinned polling | Unknown parent/block, remote refusal, ordinary transport error | Preserve target/cursor and wait for next bounded cycle |
| Pinned polling | `PEER_POLL_CANCELLED` | Normal runtime/shared-stop completion |
| Submit recovery | Local `FRAME_EOF` at `challenge` or `solution-body-response` | Existing bounded membership check/retry |
| Submit recovery | Verified remote `UNKNOWN_PARENT` | Existing bounded retained-parent restoration when enabled |
| Submit recovery | Verified remote `PUBLIC_MUTATION_CPU_BUDGET` | Existing membership check and finite epoch/call/attempt budget |
| Submit recovery | Other errors, including `STATE_CAPACITY` and CPU accounting unavailable | No new recovery or retry |
| Original admission / V2 / V3 | Exact reserved-capacity, spent-ticket-replay and scalar CPU-budget codes | Original response precedence and metrics |

`ErrorKind` is diagnostic grouping, not a generic retry table. In particular,
capacity can mean a permanent candidate refusal, an exhausted whole-operation
budget or a narrowly retryable remote CPU reservation. The call site still
requires the exact code, original operation/stage and existing finite limits.
No new ingress owner, supervisor, implicit fallback or cross-profile admission
adapter is introduced.

The public V3 client's failed phase also carries `PublicClientStage`, rather than
selecting retry, uncertain-submission reporting or elapsed-time accounting by a
diagnostic string. `Construction`, `Challenge`, `SolutionSearch`,
`SolutionBodyResponse` and `Complete` serialize to exactly the prior labels;
`failed_stage: null` is unchanged. An unknown static diagnostic remains
representable as `Unknown(label)`, but its text grants no native phase authority,
including a label identical to `challenge`. The client constructs known variants
at its actual phase transitions. Existing metrics are output-only (`Serialize`),
so no old-record deserialization format is narrowed or newly accepted. This is a
Rust field-type refinement; JSON observation fields, signed replies, retry limits
and stage timing boundaries remain unchanged.

## Verification

Native error tests preserve source types and exact displays, alter diagnostic
text without altering typed decisions, reject prefix lookalikes, and prevent
remote structural names from stopping a local owner. The polling regression
executes the actual rejection/event path for local SQLite/structure errors,
remote and IO errors, missing ancestry and ancestry-budget exhaustion. The
Submit recovery stage matrix refuses remote EOF claims, IO lookalikes, public
EOF, deadlines and unavailable CPU accounting at every tested stage.

The phase matrix covers all five native stages, `None`, an unknown future phase
and unknown labels resembling the three post-construction phases. It checks exact
retry/uncertainty decisions and preserves every serialized metrics field while
charging only the actual failed phase. The retained real EOF-before-admission and
lost-ACK tests check both the typed phase and original JSON label. A normal local
signed-refusal regression confirms that EOF lookalikes, deadline and stale-context
labels complete one authenticated call and never acquire local EOF retry identity.

The retained real TCP `public_submit_recovery`, `pinned_peer_polling`,
`protected_ingress`, `public_intake_v2` and `public_pool_v3` targets remain
the behavior checks for wire compatibility, signed refusals, bounded retries,
native membership, persisted recovery and original profile separation.

The seven provenance regressions additionally mutate actual test-owned retained
header/KV/undo/journal bytes, execute the real read, recovery and polling paths, and
repair the exact rows before checking successful recovery and cold reopen. They
compare the same diagnostic on an incoming peer response, preserve cancellations
and clock deferral, and verify the concrete nested source type. These are bounded
local integrity tests; they do not declare every legacy formatted error migrated.
