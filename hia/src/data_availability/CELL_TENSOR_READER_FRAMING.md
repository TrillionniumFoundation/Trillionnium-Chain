# Cell tensor reader framing (bounded candidate)

One immutable loan contains 32 bytes of separately supplied TMT1 digest,
BE16 file index, BE32 TMT1 length and TMT1 bytes, BE32 TMR1 length and TMR1
bytes, then the complete synthetic Safetensors container bytes. The common
native limit is 1 MiB for the entire loan; 13,944 bytes of scratch is required.
The digest is a fixture input, not proof that a caller is the owner.

The native prefix validates the original TMT1 and TMR1 declarations, compares
contract content digest and model ID, checks member lengths and required
Base/Adapter coverage, then selects the declared file from that same input.
It checks the actual file length against TMR1, the LE64 Safetensors header
length, opening brace and final non-space closing brace in original order.
Successful framing returns LE64 header and data lengths plus raw SHA-256
of the same complete container, with no writes to output on refusal. The
SHA is an observation, **not** compared against TMR1 here. The original
compares it only after JSON, tensor/interval geometry and full reads; returning
a mismatch earlier would change error priority.

Status 0 means framing only. 210 is a private malformed envelope; 211 is
contract digest mismatch; 212–216 are undeclared file, actual length, header
length, header prefix and header padding, respectively. Prior nested decoder
statuses and 79/94–96, 102/103 retain their meanings. No JSON decode or layout,
full `verify_reader` result, stream/seek/clock behavior, loader, storage, authority
or production use is implemented. The separate Rust-only +1 byte fixture is
outside the shared native cap.

The locked original tests invoke public `CellTensorContractV1::verify_reader`
with a recorded `Cursor` over owned synthetic bytes. The returned original
readback supplies the success SHA; distinct original later refusals only
provide evidence of successful pre-JSON framing. They include genuine JSON,
roster, range, overlap/hole, trailing data and payload-SHA refusals, which must
not be conflated with verified or authorized bytes when native framing succeeds.
