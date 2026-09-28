# trnm-escrow-vault

Owner: M12. Pure in-memory escrow conservation reference; no second production ledger or durability claim.

This state machine is retained from the independent application contracts, not from
ledger consensus. Its tests cover local transitions only. In-memory state and role
strings provide no durable, cryptographic, reorg or deployment authority. Integration
must choose one authoritative business owner; this is not a second active chain store.

Run `cargo test --locked -p trnm-escrow-vault --all-targets` in the `trillionnium` workspace.
See [the inventory](../../../config/portability-inventory-v1.json).
