# Q4 — source-authorized overlap for queued atomic renewal

`signed-task-lifecycle-dev-v4` is an explicit development profile, consensus
revision9. The [V4 registry](../../../../config/pon/qualified-task-lifecycle-v4.json)
is committed by `qualified-task-registry-v4` into fresh parameters, network and
genesis. Existing V2/V3 stores and signed main envelopes are refused. There is no
migration, reinterpretation of historical observations or automatic source signing.

## Signed window and one native state transition

[V3](QUALIFIED_TASK_LIFECYCLE_V3.md) combines successor start at or after inclusion
with source verification requiring that signed window already started. Its accepted
atomic renewal therefore requires exactly the containing height. A valid local queue
preview reserves no block height; delayed inclusion may fail even while the old
lease remains active. V3 bytes and behavior are preserved.

V4 changes only that atomic renewal window. For the actual containing height `h`,
all these conditions must hold:

- `old.not_before <= successor.not_before <= h <= old.expires`;
- `successor.not_before <= old.expires` and `successor.expires > old.expires`;
- the bounded lease codec still requires start at most expiry, a maximum1000-block
  window and `available_until == expires+100` with checked arithmetic;
- the source statement is strictly verified at **actual h**, including its exact
  successor lease, matching signed window, source sequence previous+1, material,
  authorization, availability, purpose and existing output meter.

The requester and source sign before submission. Main tag22 remains the exact1028
payload of QDL2 lease344 plus QWA2 source statement684; the PNX1 envelope is1187
bytes. V4 reuses the strict codecs and inner signature domains. Signed network and
parameters bind the new authority. Tag19 remains refused in V4; tags18/20/21 retain
initial opening, revocation and registration rules. Evaluation14..17 and the twelve
original commands retain separate gates. Base fee22 remains200 plus encoded bytes.

Only after every check succeeds does the lifecycle owner replace one slot record.
The containing block uses the old parent statement; subsequent blocks use the
new one. Requester main nonce and source per-demand sequence advance independently;
source main nonce does not advance just for the embedded certificate. Material,
output_count, source identity and output meter cannot reset through renewal. Failed
signature, sequence, future window, regressing start, expired old lease, malformed
payload, nonce or balance checks leave durable chain state unchanged.

## Queue delay, branches and local operation history

M05 admission and complete M06 prefix preview remain queue facts. They neither
reserve inclusion nor authorize chain execution. Mining must fence the actual
parent/generation and recheck preserved raw groups. A delayed signed successor is
valid only during the overlap above. Missing materials, expiry/revocation of all
work leases or unwilling requesters/sources still stop the chain; no random work,
legacy fallback, invented demand or automatic re-signing restores eligibility.

Reorganization restores branch-relative lease, source sequence and ledger nonce.
Independent local operator removals remain monotonic. An explicitly pruned queued
raw stays refused by that node after reorg, while another producer may still include
a consensus-valid transaction; a local tombstone grants no global revocation.
Cache eviction of expired/consumed groups is a separate pool resource policy.

## Meaningful tests and bounded evidence scope

`trnm-mvcc-fee/tests/qualified_task_lifecycle_v4.rs` checks actual containing900,
905,999 and the final old-lease boundary1000, rejects899/1001, bad source signature,
sequence and start regression without writes, and proves V3 exact-height behavior
is unchanged. `trnm-pon-node/tests/task_lifecycle_v4.rs` executes actual native work,
main signatures, M06 and SQLite activation for different containing heights;
reopen, consumed output meter, revoke/heavier fork and old namespace rejection.

The explicit ignored release test
`actual_900_preview_905_delayed_inclusion_999_reorg_preserves_certificate_and_local_prune`
retains every actual packet, exact signed successor/raw, store and summary in a
caller-selected **fresh** receipt directory. It previews the sole maintenance renewal
for next height900, retains the same raw through old-authority blocks, includes at905,
reopens, restores the old lease on a genuinely heavier fork and includes that same
certificate at999. It verifies successors1000/1001, source sequence2, unchanged
maintenance output_count0, requester/source main nonce separation, two reopens and
local removal persistence. It also admits the same raw at900 on a real side branch.

These are logical native transition observations with public development keys,
synthetic10-second header spacing and an explicitly frozen verifier clock. They do
not qualify wall-clock uptime, remote independent demand, public throughput, global
fairness, DA availability, model marginal utility, circuit optimality or computational
hardness. All corresponding registry acceptance flags remain false. Physical chain,
SQLite/WAL and archive growth remain separate from bounded slot/pool logical occupancy.
