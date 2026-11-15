# Q3 — atomic requester renewal and source activation

This is a fresh native development contract, `signed-task-lifecycle-dev-v3`,
consensus revision8. The [registry](../../../../config/pon/qualified-task-lifecycle-v3.json)
commits the exact contract in its own registry hash domain and new network/parameters.
Settings explicitly select it through `development_with_profiles`; existing V2 stores,
transaction networks and genesis are rejected. There is no automatic migration.

## Why the V2 pair is insufficient

[V2](QUALIFIED_TASK_LIFECYCLE_V2.md) accepts tag19 renewal before source tag21. A block
can have valid work under its parent lease while changing the post-state lease and
retaining a statement signed for the old lease. If it is the sole task, the next
block has no eligible work to carry a replacement statement. A local mempool bundle
cannot require every producer to include both commands. Existing V2 pair-command
1005-packet observations demonstrate that pair only; they are not atomic renewal
qualification and do not establish independent liveness. V2 semantics remain intact.

## Exact command, identities and atomic boundary

V3 accepts task tags18 open,20 revoke,21 standalone registration and22 atomic renewal.
It refuses standalone19 at main-envelope preparation and lifecycle dispatch, including
when the requester signature is valid. Native evaluation14..17 and original application
commands remain subject to their configured gates; no unknown command is accepted.

Tag22 payload is exactly1028 bytes: canonical QDL2 lease344 followed by canonical
QWA2 source statement684. No additional length field, optional metadata, nested main
transaction or alternate decoder is accepted. PNX1 total length is1187 bytes under the
2048-byte envelope limit. Truncation, trailing bytes or mismatched leaseID/network/
parameters reject. Main-envelope signature by the previous requester binds the full
payload; the existing strict source signature binds the exact successor lease and
manifest. V2 internal hash/signature codec domains are reused, while their signed
network/parameters fields select the fresh V3 context. Decoding alone proves neither
signature nor genuine demand. Base fee is200 plus the existing encoded-byte fee.

The executor verifies and charges the main envelope normally. Lifecycle code reads
one bounded slot set and constructs a proposed successor without writes. It checks
current status, authenticated requester, immutable demand/generation/source/purpose/
cost/provenance/authorization/DA identities, revision previous+1 and overlapping later
expiry. Then it verifies the successor source signature, exact new lease/window,
source sequence previous+1, existing bound model/input/task/meter and active-slot
matrix uniqueness. Only after all checks succeed does it write the one slot record.
A failed command/block does not advance lease, source sequence, main nonce or funds.
The old parent statement remains the work authority for the containing block; the
new statement becomes eligible for its successor. It cannot grant work in its own block.

The current V3 command has an exact containing-height constraint. Renewal requires
`successor.not_before >= height`, while source-statement admission at that same
height requires `height >= statement.not_before`; the statement and lease windows
must match. Therefore an accepted atomic successor has `not_before == height`.
A future-start statement submitted in an earlier block fails `TASK_STATEMENT`;
a delayed successor whose start is below the actual containing height fails
`TASK_WINDOW`. Mempool preview success does not reserve that height. Public latency,
transaction reordering and a producer withholding the renewal can invalidate its
planned inclusion. Source-authorized reissue, critical capacity and any future
overlapping/preauthorized renewal contract require explicit rules and actual tests.
The finite height900 experiment does not certify asynchronous renewal liveness.

Only the requester main-ledger nonce advances. The source signs a per-demand sequence;
there is no source main-ledger transaction in tag22. Material identity, arithmetic
output_count/product/height and the one-output meter survive renewal. Maintenance
has zero useful-output credit. Revocation and expiry still stop eligibility; no random
or legacy work fallback exists. Slots remain32, validity1000 blocks, retention exactly
expires+100, and each record at most4096 bytes. These keys reuse the V2 bounded layout
inside the fresh context; chain archive and independent local effect/withdrawal histories
keep their own owners and must not be reset or rolled back as local permissions.

## Executable verification and finite continuity observation

`trnm-pon-node/tests/task_lifecycle_v3.rs` exercises actual PNW1 packets and M06
execution: sole-task renewal and next-block eligibility, partial payload/standalone19/
requester or source signature/window/source sequence/mismatched lease rejection with
unchanged durable state, reopen, heavier branch, old admission rejection, preserved
already-used output meter, revoke/reorg, and rejection of V2 context or stores.

`lifecycle_atomic_continuity` builds/admit/activates at least1005 actual packets under
one bootstrap task, performs a **single tag22** at height900 and reopens at900/1001.
It retains all packets, source/config fingerprints, model/input/source statements,
local receipt hash chain, failed-control denominators, timing and disk observations.
The native API example is a finite laboratory run: historical logical header spacing
is not actual5h/72h uptime, infinite mining, live new demand, public transport, a
confidential signer or independent attestation. It does not certify work hardness,
cheap-invalid-proof safety, circuit optimality, marginal model utility, source fairness,
remote DA availability or readiness. All such acceptance flags remain false.
