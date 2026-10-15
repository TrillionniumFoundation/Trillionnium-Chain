# trnm-governance-guard

Owner: M01. Local proposal/timelock, role separation and optimistic version checks; no network governance authority.

This state machine is retained from the independent application contracts, not from
ledger consensus. Its tests cover local transitions only. In-memory state and role
strings provide no durable, cryptographic, reorg or deployment authority. Integration
must choose one authoritative business owner; this is not a second active chain store.

Run `cargo test --locked -p trnm-governance-guard --all-targets` in the `trillionnium` workspace.
See [the inventory](../../../config/portability-inventory-v1.json).

## Boundary arithmetic and caller trust

Both parameter proposals and unpause schedules reject an unrepresentable minimum
ETA with `InvalidEta`; saturation must never shorten the configured delay. The
largest representable exact ETA remains valid. Parameter versions and proposal
IDs fail closed with `CounterExhausted` before changing proposals, bridge state
or audit events. The maximum nonce is reserved as the exhausted sentinel, so IDs
cannot be reused. Counter-boundary tests seed private state; reaching these counts
through ordinary operations is not a realistic attack claim.

The integrating owner must authenticate caller identities and supply trusted time.
A caller string or supplied `now` value alone is not an authorization or clock
proof. These local boundary tests do not establish live network governance safety.
