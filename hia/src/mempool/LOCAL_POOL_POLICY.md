# Local-pool policy identity (pure candidate)

This bounded candidate produces the compact policy bytes and context digest
used by the original Node's `enable_local_mempool`. It implements the pure
`PoolLimits::validate`, serialization and `pon_wire::hash` segment, not the
original method's namespace, growth-profile rejection, database transaction,
held-owner permit, or post-commit reconciliation.

The standalone [borrowed ABI](local_pool_policy_abi.json) entry is `f0(readbuf, mutbuf, mutbuf) -> u32`.
The caller supplies distinct, live buffer regions. Input is exactly 172 bytes,
in this order:

- `LPV1`
- network, parameters, genesis and preview miner (32 bytes each)
- max records, max bytes, max group members, critical reserve and max removals
  (each little-endian u64)

Bounds are the original 1..=256 records, 1..=524288 bytes, 1..=16 group members
also bounded by records, reserve strictly below records, 1..=4096 removals, and
a nonzero miner. These input values and identities remain caller-supplied
facts even when the context agrees.

Output requires 282 bytes and scratch 1664. Success returns the written prefix
length and emits the 32-byte context followed by compact original Rust struct
JSON. The JSON has the exact original field order and preview-miner array
representation. The framing is identical to `pon_wire::hash` with domain
`native-local-queued-pnx1-v2` and parts `[network, parameters, genesis,
canonical_policy_json]`. No hash cache or string is trusted from a caller.
A successful result modifies only the returned output prefix and the finite
scratch prefix (bounded by 1609 bytes).

Refusals are 1 malformed frame, 2 insufficient output or scratch, 3 original
`POOL_LIMITS`, and 4 internal hash failure. Frame, capacity, and policy
refusal occur before any output or scratch write. Hash failure never publishes
output. The required output extent is the exact worst-case capacity (32 digest
bytes plus 250 JSON bytes); output tails are never canonical data. No file,
socket, or persistent capability is accessed.

Do not wire this into the existing Node owner until it is differentially
checked against the complete exact original `Node` method on a disposable
database and its actual owner creates the identity input. That test must
observe matching metadata/context, cold readback, mismatched-context refusal,
and unchanged accepted metadata after a normal refusal or cancelled
transaction. The pure buffer rollback checked here is not database rollback.


## Standalone qualification

```sh
python3 -B -m unittest hia.tests.test_m05_local_pool_policy -v
```

Set the three locked HIA toolchain variables as for the general component
suite. Run with Rust/Cargo matching the repository pin and its locked
dependencies already cached. The suite owns this crate and temporary buffers,
uses Cargo offline, compares the dependency checksums against the Chain lock,
and fails if the original Rust comparison cannot run. It compiles the exact
`PoolLimits` declaration and validation plus the unchanged in-method
serialization/hash statements, using the complete original `trnm-protocol`
dependency through a test-only identity adapter. It emits and calls both
pinned x86-64 HIA backends and checks exact responses and carry-forward refusal.

The general component CI shard discovers this test. The package ownership map
assigns the source to `trnm-pon-node`, which owns the original local-pool
policy and method; M05 is the consuming boundary, not a different Rust owner.
