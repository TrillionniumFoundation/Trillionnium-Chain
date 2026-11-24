# Verification statement preflight and observational output

The native entry implements the actual
[`VerificationStatementV1::new` and `verify_statement_v1` pre-provider sequence](../../../trillionnium/crates/trnm-verification-profiles/src/lib.rs).
It computes the original SHA-256 transcript itself, using the original
domain including its terminator, big-endian u64 frame lengths, ordered
digest fields, big-endian version and heights. In preflight mode it
checks the declared digest before exact profile resolution, checks all
evidence identifiers before comparing their links, and checks the
inclusive current-height evidence window only after evidence matches.

An immutable profile table is validated through the shared
[closed registry](PROFILE_REGISTRY.md) used by the original native entry.
Invalid tables fail at registry construction, before simulating any call
over an already constructed Rust registry. No expected profile or result flag can stand in for native validation.
The optional output codec accepts only a typed, non-authoritative observation,
and derives all digest fields and kind from the same checked frame.

## Private frame

The 92-byte prefix contains `VPS1`, little-endian u32 operation, u64
row count, u64 observed height, and 68 ignored header bytes. It is
followed by exactly that many 97-byte profile rows in the VPR1 format.
There are at most 64 rows; this private bound does not widen the
original six-kind roster.

The statement body is 252 bytes: task, lease, execution receipt and
profile identity (32 bytes each), u32 version, profile hash, artifact
evidence and availability digest (32 bytes each), then u64 first, last
and submitted heights. Integers in this private argument are little-endian.

- Operation 0 requires an empty profile table, with the statement body
  as the final field. Success writes the 32-byte computed statement digest.
- Operation 1 adds the declared 32-byte statement digest and six 32-byte
  evidence fields (task, lease, execution receipt, artifact, availability,
  and backend payload). Success writes the computed statement digest and
  exact 97-byte resolved profile. No backend result is an input or output.
- Operation 2 appends one byte to operation 1: the read-only observational
  label (0 Verified, 1 Rejected, 2 Unavailable). It runs the same
  preflight; only after success does it interpret the label. It publishes
  a private 68-byte record: observed status, resolved kind, computed
  statement digest (32 bytes), decision digest (32 bytes), and two literal
  zero bytes for economic and order-reorganization authority.

The operation-2 digest uses the original `trnm.g2c.verification-decision.v1`
domain including its NUL, verified statement digest, exact selected kind
(one byte, original tags 0, 1, 2, 3, 5, 6), observed tag (one byte), and the
backend-payload digest from the same admitted evidence (32 bytes), in that
order. Each field uses its original big-endian u64 length. The result is
a deterministic presentation, not a public wire status, backend proof,
or signed authority. No backend is called from HIA.

The result uses original registry statuses, plus 14 malformed statement,
15 evidence binding mismatch, and 16 evidence window closed. Local framing,
capacity and internal failures use 100, 102 and 103 respectively. The
kernel needs 1,591 scratch bytes and does not alter bytes beyond that
extent. It changes no output on refusal, and no suffix on acceptance.

The [original differential](../../tests/test_verification_statement_preflight.py)
compiles the unchanged Rust methods with pinned rustc and an independent
system SHA-256 adapter. Rust invokes a purely offline enum fixture and counts actual calls.
Operation 1 keeps the Unavailable fixture; operation 2 covers all six
kinds and all three enum labels, and compares every output byte from the
original Rust decision. Rust validation refusals never invoke the fixture.
Neither the fixture's label nor any emitted record proves verification;
backend ownership, challenge lifecycle, payments, fork weight and
production admission remain outside this component.
