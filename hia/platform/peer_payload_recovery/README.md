# Native recovery ACK codec

[`recovery_ack.hepta`](../../src/peer_lease/recovery_ack.hepta) implements the fixed acknowledgement encoding and decoding from
`trnm-peer-lease/src/payload_recovery/part_04_io_ack.rs`. The 188-byte file format,
SHA-256 domain, big-endian stored integers, exact-length checks, checksum and
revision/digest checks are unchanged. Byte operations and hashing use the
existing [peer value helpers](../../src/peer_lease/values.hepta) and canonical
[SHA-256 implementation](../../src/crypto/sha256_stream.hepta).

Recovery targets, acknowledgement constructors, status variants and status
projections already belong to the [native peer value owner](../../src/peer_lease/README.md).
This codec does not introduce a second constructor or perform filesystem
publication. The durable recovery owner, immutable ACK publication, process
locking, recovery socket and Body maximum-index qualification remain open.
Encoding or decoding a checksum is not an acknowledgement by Core.

## Exact original behavior

The internal `prk_ack_encode` consumes an already typed acknowledgement and a
namespace digest. Like the original private `encode_ack`, it does not call the
target or acknowledgement constructor again. Remote identity, direction,
session, generation, sequence, frame kind and payload length are target fields
that the fixed ACK file does not serialize. The retained record index, record
hash and frame fingerprint bind the stored acknowledgement to its target.

The internal `prk_ack_decode` first checks the exact 188-byte extent, magic,
version and three reserved bytes. It then verifies SHA-256 over the original
domain, the big-endian eight-byte prefix length and the complete 156-byte
prefix. Only after the checksum matches does it reject a zero safety revision
or zero Core acknowledgement digest. It returns all seven original `AckFactsV1`
fields. Namespace digest, record index, record hash and frame fingerprint may
be zero here, as in the original decoder. The original `read_ack` separately
compares the decoded namespace and target; that owner operation is not claimed
by this codec.

## Private native test boundary

The entry is `f0(input: readbuf, output: mutbuf, scratch: mutbuf) -> u32`.
Borrowed buffers are private, valid and disjoint. Inputs start with a
little-endian `u64` operation. The scratch buffer must contain at least 4,352
bytes; all internal staging, hash state and results stay within that extent.
No allocation, host hash implementation or host business callback is used.

| Operation | Remaining input | Successful payload |
| --- | --- | --- |
| 1: encode | 32-byte namespace digest, 176-byte target in the existing value getter order, `u64` revision, 32-byte Core ack digest | Exact 188-byte ACK file |
| 2: decode | Exact original ACK file | 176 bytes of decoded facts |

The target order is index, record hash, remote identity, direction, session,
generation, sequence, frame kind, payload length and frame fingerprint.
Integer fields in this transport are little-endian `u64`; direction must be 1
or 2, frame kind must fit `u8`, and payload length must fit `u32`. These checks
only establish the original Rust types. Semantic construction remains in the
existing value owner. The decoded facts order is namespace digest, index,
record hash, frame fingerprint, revision, Core ack digest and acknowledgement
hash. The two integer fields use little-endian `u64` in the test transport.

Successful output is an eight-byte little-endian payload length followed by
the complete payload. The original stored file remains big-endian. Return 3
means the original `AckLedgerCorrupt` error. Returns 100, 101 and 102 mean a
malformed transport, insufficient scratch and insufficient complete-output
capacity. Every nonzero result preserves the complete caller output.
Malformed transport and wrong decoder length are rejected before scratch is
used. Scratch admission precedes the decoder's semantic checks, and semantic
failure precedes output-capacity refusal.

The internal helpers use the fixed disjoint layout selected by `f0`: input at
2,048, staged result at 3,072 and hash preimage at 4,096. They do not claim a
public arbitrary-offset or aliased-buffer API.

## Verification

The five methods in [test_peer_payload_ack.py](../../tests/test_peer_payload_ack.py)
are discovered by the existing `general` component partition. They build the
unchanged original crate with its complete feature set and locked offline
dependencies, append a transport-only hook to a private source copy, and call
the actual original `encode_ack` and `decode_ack`. The hook does not compute
the hash or reproduce decoder decisions. The original crate sources are
checked before and after all observations.

Coverage includes every encoded field byte, all decoder byte/bit mutations,
every truncation, trailing data, rehashed invalid headers, constructor-invalid
but typed raw values, zero fields that the original decoder accepts, full
integer domains, seeded arbitrary values, complete output-capacity boundaries
and scratch admission. An independent `hashlib.sha256` check verifies every
successfully encoded file. A second actual native module constructs recovery
targets and acknowledgements through the existing private value owner; its
getter output feeds the codec and is compared with the original public methods.

With the pinned compiler and Rust environment configured, run:

```sh
python3 -B -m unittest hia.tests.test_peer_payload_ack -v
```

Setting `HIA_RECOVERY_ACK_OUTPUT` to a fresh absolute directory outside the
checkout retains original source identities, append-only instrumentation,
fresh Cargo and adapter outputs, native libraries, actual reference process
inputs/outputs and the final observation report. This optional capture does
not change the cases, limits or implementations. The codec slice does not
replace the original 121-test Peer process qualification or any existing
Body/recovery owner deadline.
