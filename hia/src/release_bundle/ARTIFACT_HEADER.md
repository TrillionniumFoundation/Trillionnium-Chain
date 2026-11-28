# RAC1 release-artifact metadata header

The [native encoder](artifact_header.hepta) reproduces the private
[Rust RAC1 serializer](../../../trillionnium/crates/trnm-release-bundle/src/content_v1.rs)
and the original typed artifact metadata predicate. This is the header only:

```text
"RAC1" || be64(name length) || name || be64(media type length) || media type
       || be64(artifact size) || executable byte || content digest
       || platform digest || source-path digest
```

The private native call accepts a different in-memory framing, not a new RAC1
wire form. Input contains `le16(name length)`, `le16(media type length)`,
`le64(artifact size)`, an executable byte (0 or 1), three ordered 32-byte
digests, then name and media type. No padding or trailing bytes are allowed.
The text fields contain 1–512 and 1–256 printable ASCII bytes respectively,
including spaces. The size is between one byte and 128 GiB inclusive, and each
digest must contain at least one nonzero byte. Equivalently, the size admits
`1 <= artifact_size_bytes <= 137438953472`. Input and output buffers are
separate caller-owned regions.

`f0(readbuf,mutbuf,mutbuf)->u32` returns 127–893 bytes written,
`0xffffffff` for invalid metadata or framing, or `0xfffffffe` if valid
metadata cannot fit. Invalid input takes precedence over insufficient
capacity. Refusals leave output untouched; success preserves its suffix.
Scratch is unused. No raw artifact data or authorization enters this call.

[Tests](../../tests/test_release_artifact_header.py) compile the original
Rust field declarations, validation and encoder as an oracle. The original
Rust callers, artifact bytes and file I/O, content commitment and signature
paths, CLI and production routing remain unchanged.

The first adapter setup stopped before native compilation because the validator
signature occurs on several ReleaseBundle types. The final adapter first
selects the original `ArtifactEntryV0` implementation and then its validator.
The second Rust-only setup exposed a missing `Copy` derive in the test
adapter; the final adapter includes the original derives for both types.
Core then rejected an unbound typed result from the final copy call
(`E_HIA_TYPE`); the final source returns the actual copy cursor.
