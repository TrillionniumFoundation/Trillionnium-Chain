# Native Research state transitions

`state_transition.hepta` implements the original seven command transitions over
a privately admitted state index. It produces a candidate snapshot and outcome;
the forthcoming native owner must validate, allocate and publish that candidate
atomically. The original Rust remains the independent test oracle, not a runtime
implementation. This private continuation alone is not the complete state owner.

## Required composition

Before every apply, including an unbound-state or replay call, the owner must
run the existing native signed-command validation and Ed25519 verification.
Only that successful native result supplies the fingerprint and typed command
to this continuation. The entry does not independently reverify a signature and
must be hidden from the public ABI. Host-provided fingerprints or caller-created
arenas cannot establish authority.

After signature validation, state checks retain the original order: nonempty
chain binding, exact chain match, authority tuple membership, fingerprint replay
or command-id conflict, journal-chain consistency and nonce floor, then the
specific transition. A matching replay returns the original recorded primary
reference even if that object has subsequently advanced to another version.
Nonce lookup uses complete sorted identities and full-width nonces.

All seven payload variants preserve the original reference, decision, claimant,
timestamp, existence and version-overflow precedence. Open challenge and resolve
challenge update the associated claim/challenge statuses and references exactly
once. All four resolution decisions are represented. Claim amendments preserve
the immutable original payload separately from current claimant allocation.
Historical license and journal references retain the original semantics.

An applied result contains the normalized snapshot, with all seven maps and the
journal in original BTree order. The native candidate becomes the next native
input in the integration tests; Python does not reconstruct a business result.
Every failure and replay preserves the prior snapshot. Rejection must not
publish an allocation or partial candidate in the future state owner.

## Private borrowed ABI

The frame is `RST1`, twenty zero bytes, then the already validated signed-command
typed fields. The private arena holds the admitted index, configured chain and
the fingerprint returned by native command validation. For old snapshot length
`n` and command length `c`, scratch requires `299520 + 33*n + 32*c`, with checked
arithmetic and disjoint live extents. There is no new semantic collection limit.

The output prefix is 320 bytes. The first four u64 little-endian words are
outcome, candidate length, changed-reference count and error code. Outcome 1 is
applied; 2 is idempotent. The 48-byte primary reference begins at offset 32;
up to three changed references begin at 80. Error metadata occupies 256–319.
The candidate typed snapshot follows at 320. Idempotence returns no candidate
and no changed references. Semantic refusal writes metadata only; capacity
status 64 and malformed-frame status 65 preserve the complete output.

The candidate is staged separately from the old snapshot, which remains intact
even on success. Private error pointers refer into the live arena and require
owned copying before cleanup. This ABI cannot be exposed as an untrusted state
injection interface.

## Actual development observations

Six formal methods passed in 136.859 seconds with five native builds and 811
recorded calls. They include 151 actual original/native transition comparisons,
49 ABI controls, all seven commands, four resolution decisions, idempotent
replay, authorization/error precedence, positive timestamp regression, exhausted
versions and a growing 32-command state with reverse key and command-id order.
Each step checks normalized snapshot bytes, canonical encoding, hash, outcomes
and exact changed references. Every rejected step checks unchanged state.

The earlier six-method run remains a failure. Two test fixtures were corrected:
a trailing byte legitimately increased scratch demand by 32 bytes, and a zero
timestamp was rejected by signed-command validation before reaching the intended
state timestamp check. The corrected cases separately exercise insufficient
scratch and malformed framing, and use positive earlier/later timestamps.
No production transition was changed to make those fixtures pass.

```sh
python3 -m unittest hia.tests.test_research_state_transition -v
```
