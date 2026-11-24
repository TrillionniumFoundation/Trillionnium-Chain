# Pure challenge record lifecycle

The HIA entry implements the
[original per-record Rust owner](../../../trillionnium/crates/trnm-verification-profiles/src/lib.rs):
construction plus submit evidence, begin response, submit response, decide,
appeal, finalize, withdraw and expire. It returns a new record on success;
the input remains unchanged. It neither consults nor updates a book,
authenticates an actor, assigns authority, or writes persistent state.
The caller must supply a previously held typed record; this codec does not
authenticate arbitrary prior bytes or establish custody of their digest.

The exact original order matters: identifiers precede opening deadlines;
phase precedes action deadline except that a spent appeal precedes both.
Ordinary deadlines are inclusive, expiration and finalization require a
strictly later height, and finalization at its deadline is an invalid
phase, not an expired-deadline error. An appeal resets both decision and
appeal deadlines, clears the old outcome, and marks the only appeal used.
Terminal records and refusals are not economic or reorganization outcomes.

## Private fixture representation

The input is exactly 197 bytes: a 24-byte header and a 173-byte record.
It begins with `VCX1`, an operation byte (0–8 in the order above), a
decision argument byte (1 Upheld, 2 Rejected, 3 Withdrawn, 4 Expired,
otherwise zero), two zero reserved bytes, a u64 observed height and a
u64 argument. The argument is the opening window end (operation 0) or new
deadline (appeal); elsewhere it is zero. The observed height is zero on
opening, and not used by withdrawal. Unsupported typed decision choices
(Withdrawn/Expired) are refused by the original decision policy.

The record begins with the three exact 32-byte identifiers (challenge,
result and challenger), five u64 values (opened and evidence, response,
decision and appeal deadlines), phase (0–7, original enum order), used
byte (0–1), optional outcome (0 None, or tags 1–4 as above), two literal
false authority bytes, and the 32-byte record digest. All u64 frame
fields are little-endian. Opening supplies a zero 37-byte tail instead of
a prior state. Prior digest bytes are not input to the new digest, as in
the original per-record methods. This is a private representation, not a
public wire format, signature, storage record or authorization.

The native digest uses SHA-256 over the original domain
`trnm.g2c.challenge-record.v1` including its NUL and the original ordered
fields. Each field has a u64 big-endian length and numeric hash values are
big-endian. Output is exactly the 173-byte record, plus no changes beyond
its extent. Codes 1, 17, 18 and 19 represent zero identifier, invalid
phase, missed deadline and already-used appeal. Local failures are 100
framing, 102 capacity and 103 internal. The scratch bound is 1,472 bytes;
refusals write no output, and early refusals do not start hashing.

The [original differential](../../tests/test_verification_challenge.py)
compiles the unchanged original Rust methods with pinned rustc and an
independent system SHA-256 fixture, then compares two distinct native
images byte-for-byte. Only previously derived synthetic records are used
for valid lifecycle calls. No production caller is replaced.
