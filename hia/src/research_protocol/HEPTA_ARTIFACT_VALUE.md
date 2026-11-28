# Private Hepta artifact handoff value

The private HIA entry emits exactly the original
HeptaArtifactAdmissionV1::canonical_bytes() and
HeptaArtifactAdmissionV1::admission_digest() for one typed inert value.
The presence flag selects null or one 32-byte parent. It does not run
semantic or time validation and never constructs a signed envelope.
A value output is not an admission verdict.

Input is exactly 456 bytes: HAV1, one parent presence byte (0/1),
three reserved zero bytes, four little-endian u64 values (generation,
payload length, created, expires), five 32-byte fields (operation key,
artifact, owner admission, family, source profile), the 32-byte parent
slot (ignored if absent), and seven more 32-byte fields (withdrawal scope,
withdrawal head, registry head, evaluation plan, task scope, export
permission, payload). The native entry uses existing shortest-width
CBOR heads and writes the original 18-element array in source order.
It hashes the emitted CBOR privately with the exact original research
domain, BE u32 domain length, and BE u64 CBOR length.

Input, output and scratch are disjoint. Output requires 520 and scratch
1,792 bytes. Success publishes 32 digest bytes, LE u64 CBOR length, and
CBOR, leaving remaining output unchanged. Wire/capacity refusal publishes
nothing and changes no scratch. No training, clock, network, signer,
authorization, registry change, artifact access or production path occurs.

Tests link the unchanged locked Rust library and call only its public
value functions on generated numeric/digest fields. Both stock emitters
compare full canonical bytes and exact digest, plus private ABI guards.
