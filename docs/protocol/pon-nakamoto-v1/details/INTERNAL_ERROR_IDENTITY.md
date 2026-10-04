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

| Path | Typed condition | Existing behavior retained |
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

## Verification

Native error tests preserve source types and exact displays, alter diagnostic
text without altering typed decisions, reject prefix lookalikes, and prevent
remote structural names from stopping a local owner. The polling regression
executes the actual rejection/event path for local SQLite/structure errors,
remote and IO errors, missing ancestry and ancestry-budget exhaustion. The
Submit recovery stage matrix refuses remote EOF claims, IO lookalikes, public
EOF, deadlines and unavailable CPU accounting at every tested stage.

The retained real TCP `public_submit_recovery`, `pinned_peer_polling`,
`protected_ingress`, `public_intake_v2` and `public_pool_v3` targets remain
the behavior checks for wire compatibility, signed refusals, bounded retries,
native membership, persisted recovery and original profile separation.
