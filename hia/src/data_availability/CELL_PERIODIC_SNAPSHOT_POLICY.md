# Native CPS1 snapshot policy value

The private `trnm_cell_periodic_snapshot_policy_v1` computes only the exact
original public `CellPeriodicSnapshotPolicyV1` immutable value behavior:
decode, validate, encode and compute the commitment. It does not schedule
a snapshot, acquire funding, create an owner, open a store, or verify a
declared ID against an external authority.

Use `f0(input, output, work)` with disjoint, caller-owned spans. Input is
the exact 152-byte original CPS1 wire: four ASCII bytes `CPS1`, followed
by four 32-byte IDs (responsible owner, store, initial operation, initial
contract), then the first due height and interval as u64 big-endian,
and maximum snapshots as u32 big-endian.

The four IDs must each be nonzero. First height, interval and count must
be positive; count is at most 127. The final cadence must fit in
signed-64-bit height, with checked multiply and add. At count one the
interval is not used to compute the final height: any nonzero u64
interval remains valid if the first height fits.

Success returns 0 and publishes 184 bytes: the exact 152-byte canonical
wire followed by 32 SHA-256 bytes for the domain
`trnm.cell-periodic-snapshot-policy.v1`, one NUL, then the canonical wire.
Caller output beyond byte 183 and work beyond byte 1397 stay unchanged.

First original errors are 100 (namespace/length), 101 (identity),
102 (finite cadence), 103 (cadence overflow). Private short-output/work
status 104 is considered only after semantic validation; minima are 184
and 1398 bytes. These refusal statuses change neither output nor scratch.
Unexpected internal status 105 never publishes output. The helper
performs no I/O and cannot establish authorization or retained data.
