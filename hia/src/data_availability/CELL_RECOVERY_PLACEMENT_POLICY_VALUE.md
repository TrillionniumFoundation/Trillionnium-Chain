# Immutable Cell recovery-placement policy

The native entry accepts a bounded borrowed typed-value adapter: the
eight-byte tag `NRPP0001`, big-endian unsigned 16-bit provider count,
five 32-byte declarations per provider, a maximum-lost-events byte,
an axis-count byte, and exactly that many axis codes (1 through 3).
The five declarations are provider ID, operator, administrator,
failure domain, and domain evidence, in original order.

It matches the admission of the original public
`CellRecoveryPlacementPolicyV1::new`, which calls the evaluator with
no placements and `u64::MAX` for its step allowance. The native value
requires 1–16 providers, at most three increasing typed axes, at
most two losses, a nonempty axis set for nonzero losses, increasing
unique provider IDs, and all five identities nonzero. Repeated
non-provider labels are permitted. In this empty-placement path the
remaining original bounds cannot reject a valid input: at most 48
distinct typed events, 1,177 scenarios, and 20,777 steps. This entry
does not expose steps, masks, scenarios, or recoverability outcomes.

After validation, it returns the original 64-byte SHA-512 commitment
over `TRNM/Cell/RecoveryPlacement/v1\0` and the adapter bytes after
the tag. Separate scratch is 131,264 bytes. Input refusals and inadequate
capacity preserve scratch and output. Publication changes only the
first 64 output bytes, never the suffix.

No slots, placement data, endpoints, live identity, provider observation,
recovery, store, owner authority, or independence are checked or granted
here. The original oracle calls only the public constructor on typed
synthetic data, then its public commitment. Adapter-only cases are
tested separately on both stock native backends.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_recovery_placement_policy_value
```
