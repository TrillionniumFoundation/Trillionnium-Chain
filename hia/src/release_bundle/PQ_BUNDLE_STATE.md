# Release PQ V1 bundle state guard in shadow

[`pq_bundle_state.hepta`](pq_bundle_state.hepta) is the read-only
NodeSoftware policy boundary **after** the V0 callback and **before** the
original private token consumption in
[`accept_with_quorum`](../../../trillionnium/crates/trnm-release-bundle/src/pq_release.rs).
It implements none of the callback's verification or state-advance
side effects. It is not a release admission or a replacement owner.

The original outer owner requires NodeSoftware and matching declared
V0/PQ content, then the role's presence. The V0 content verifier runs
before a callback that compares the stable role identity and canonical
signature-set locator and checks every supplied signature. Original
public `accept_bundle` maps those internal errors to `InvalidBundle`.
Only after the callback does the owner check time, root scope and
state. In particular the existing
[strict scoped native quorum](PQ_QUORUM.md) checks network and
generation before its math. Calling that as the original callback
would reorder compound failures. This shadow guard deliberately does
not make that substitution or fabricate the same-call token.

## Immutable inputs

The private `f0(input, output, work)` borrows disjoint live regions.
There are no computed PASS flags, opaque proof inputs or output writes.
The source begins with the exact 155-byte
[V1 metadata descriptor](PQ_SIGNING.md). It then contains:

| Byte offset | Field |
| ---: | --- |
| 155 | Independently supplied fresh owner checkpoint, 32 bytes |
| 187 | Snapshot root network, 32 bytes |
| 219, 227 | Snapshot root generation and expiry, u64 LE |
| 235 | Snapshot's own checkpoint, 32 bytes |
| 267 | Snapshot current NodeSoftware content `Option`: one presence byte and 32 bytes, zero when absent |
| 300, 308, 316, 324 | Snapshot NodeSoftware version, snapshot clock floor, independently observed now, snapshot event count, u64 LE |
| 332 | Full retained-history count, u16 LE (0–4096) |
| 334 | 33-byte history rows, each role (1–4) followed by the 32-byte accepted content digest |

History covers *all* roles and must use the original role/digest
ordering without duplicates. The guard computes scoped history
membership from those actual rows; it does not take a caller's
`revisited` or `has_room` claim. Some zero and absent are not aliases.
The caller must obtain the immutable owner snapshot, checkpoint pin
and clock through trusted independent channels. In particular it must
not obtain the fresh pin from the same possibly stale snapshot or
from the release. The guard cannot authenticate those channels or
establish persistence, recovery, rotation or freshness on its own.

## Result and order

Malformed private framing returns `100`. An all-zero or unequal
independent checkpoint pin returns `111`, before entering otherwise
exact original policy. A candidate's own expected checkpoint is
checked later, separately, and can still fail against an anchored
snapshot. Original NodeSoftware policy is:

1. `201` full event history, then `202` clock rollback.
2. `203` expiry, then `204` wrong network or generation.
3. `205` expected checkpoint or previous content conflict.
4. `206` role version not exactly current plus one, including overflow.
5. `207` zero content.
6. `208` rollback approval differs from actual revisit.
7. `201` full retained history with novel scoped content.

A zero return means only that this pure state predicate passed. It
cannot stand in for real math, the V0 callback's private borrowed token,
or an authorization transition. No disk, key, clock, release state,
or output/scratch buffer is modified.

The differential runs both pinned HIA emitters and the original
hash-bound Rust branch body with synthetic immutable projections.
Compound errors, two distinct anchors, exact time/overflow edges,
independent role history, and the 4,096-row boundary are covered. No
keys or network/filesystem release actions are used.

```sh
python3 -B -m unittest -v hia.tests.test_release_pq_bundle_state
```
