# Persistent host identity and recovery barrier v0

Primary module: M15. Consumers: authority adapters and production-shaped node
composition. This is a stable implementation contract under the
[canonical Plan v2](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
not a release or activation record.

## Identity and readiness

A host captures one validated `NodeIdentityV0` at construction. A different
chain, validator, application or generation cannot be adopted by changing an
adapter behind that host; it requires a separately constructed and recovered
host. Identity is checked before and after recovery and authority application,
and around I/O polling. This does not authenticate an arbitrary malicious
adapter or replace trusted composition and exclusive lifecycle ownership.

`recover()` first sets `Recovering`, before calling a fallible adapter. Only a
successful response with the same identity and, for Resume, a valid operation
binding can restore `Ready`. Errors, invalid resumed bindings and unwinding
must not retain readiness from a previous successful recovery. Quarantine
remains a non-ready disposition.

`prepare_bound_ingress()` rejects malformed input before calling the authority
adapter. Such a peer/input error does not revoke a valid recovery barrier.
Immediately before Begin application, readiness becomes Recovering. A write
may have occurred despite a failed/lost acknowledgement; an adapter error or
invalid returned binding/stage/facts/record leaves the host non-ready. Only the
complete validated receipt restores Ready. No implicit retry is performed.
Fresh adapter recovery and exact idempotent replay resolve an uncertain write.
The host does not remint an operation, reset a sequence or invent a durable fact.

I/O unavailability and malformed ingress remain local errors, not consensus
invalidity or automatic invalidation of otherwise known durable authority.
Polling after an authority uncertainty is blocked until recovery succeeds.

## Verification boundary

`host_recovery_tests` contains thirteen actual-host tests covering repeated
recovery errors, invalid Resume, adapter panics, Begin failure before and after
recording, four receipt substitutions, identity changes, invalid initial
identity and positive controls for peer/I/O errors and exact replay. The
reference coordinator and injected faults are explicit test doubles: they do
not prove disk durability, signing safety, live networking or physical recovery.

```bash
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-node-boundary-v0 --lib --locked
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node-production-v0 \
  -p trnm-production-adapter-conformance-v0 --all-targets --locked
```

Run the pinned compiler, formatting, Clippy, dependency and complete consumer
gates on the unchanged source before acceptance. This change adds no signing,
finality or production activation authority and does not complete the live
validator's network, pacemaker or application integration.
