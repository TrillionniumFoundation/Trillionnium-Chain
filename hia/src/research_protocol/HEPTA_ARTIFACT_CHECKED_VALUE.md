# Private checked Hepta artifact value projection

This distinct HIA entry takes exactly the 464-byte offline HAV1 frame,
including the explicit little-endian supplied time. It checks the
typed value and supplied window before emitting any bytes. After success
it computes the original 18-element canonical CBOR and domain digest
directly from the unchanged 456-byte prefix of that same borrowed buffer.
The supplied time is not part of the original typed bytes or digest.

The shared internal field-check and encode-prefix functions are mechanical
extractions from the two older entrants. Their existing f0 wrappers keep
their original extent rules, result status and ABI. New source and ELF
hashes are qualified separately; historical qualification is not replaced.
The new entry avoids input copies, aliasing and duplicated control logic.

Return statuses preserve the offline validator (0, 1–20, 100). After a
successful check only, lack of disjoint 520-byte output or 1,792-byte
scratch yields 102; an internal hash failure yields 103. The successful
output is 32 digest bytes, LE u64 length, exact canonical bytes. Every
refusal leaves the output untouched. Shape, status and capacity refusals
also leave the full scratch unchanged. Original locked public Rust
sequential validate_at then canonical value calls and both stock machine
emitters exercise the combined path and older standalone behavior.
This is a checked value projection, not an admission decision or signed
envelope. No clocks, keys, signers, trust, network or production path.
