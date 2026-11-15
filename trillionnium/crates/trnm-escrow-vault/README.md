# trnm-escrow-vault

Owner: M12. Pure in-memory escrow conservation reference; no second production ledger or durability claim.

This state machine is retained from the independent application contracts, not from
ledger consensus. Its tests cover local transitions only. In-memory state and role
strings provide no durable, cryptographic, reorg or deployment authority. Integration
must choose one authoritative business owner; this is not a second active chain store.

Run `cargo test --locked -p trnm-escrow-vault --all-targets` in the `trillionnium` workspace.
See [the inventory](../../../config/portability-inventory-v1.json).

## Conservation and trust boundary

Successful deposits are owner-authorized credits, not verified external payments.
The integrating owner must authenticate the caller and validate real asset backing
before crediting. Passing the owner string is not cryptographic authentication.

Within this reference model, available balances plus amounts in `Locked` records
equal cumulative successful deposits. Release and slash move locked value once;
terminal records remain reserved to prevent request-ID replay. Transfer preserves
value, including self-transfer. All returned operation errors preserve balances,
locks, pause state and audit events. Existing overflow tests cover deposits,
release, slash and transfer; a fixed-seed mixed-operation test checks conservation
and complete rejection atomicity after each transition. These checks do not claim
external funding, durable storage, crash atomicity or a global `u128` supply cap.

Deposit accounts, like transfer and slash recipients, must not be empty or
whitespace-only; rejected deposits return `InvalidBeneficiary` without changing
state or audit events. Nonblank account strings remain opaque, exact keys; the
integrating owner remains responsible for account identity validation.
