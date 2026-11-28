# ReleaseArtifact raw SHA-256 lifecycle

[The legacy locator in ReleaseBundle](../../../trillionnium/crates/trnm-release-bundle/src/content_v1.rs)
is SHA-256 of the raw artifact alone. It excludes RAC1 metadata and the CCH1
context. [The native component](raw_artifact_sha256.hepta) reuses the repository's
[full SHA-256 helpers](../crypto/sha256_stream.hepta). It does not call that
module's transport-scoped entry, whose total input limit is 2,098,176 bytes.

The private borrowed entry `f0(frame, digest, state)` uses disjoint regions.
Keep the same exclusive, in-process state across calls. The state is opaque;
it is neither a portable checkpoint nor a trusted message from another party.
The first 1,208 bytes are the shared SHA-256 state, followed by 16 bytes for
the lifecycle marker and declared artifact size. The minimum state extent
is 1,224 bytes; any additional state bytes remain untouched.

| Frame | Operation |
| --- | --- |
| `00 || le64(raw_byte_length)` | Initialize or explicitly restart, discarding prior hash progress. Admits 1 through 137,438,953,472 (128 GiB), matching `ArtifactEntryV0`. |
| `01 || raw_bytes` | Append exactly those bytes, including a no-op for an empty chunk; the cumulative feed must not exceed the declared size. |
| `02` | Require exact cumulative size, then write the 32-byte digest. Any additional digest-buffer bytes stay untouched. |

Success returns `0`. `100` refuses a malformed frame or undersized state,
`101` an uninitialized, finalized or inconsistent state, `102` an invalid
declared length, overfeed or premature final, and `103` inadequate digest
capacity. Refusals do not modify the frame, digest or state; retrying final
after a short output is safe. New input and repeated final are refused after
final until explicit reinitialization. Restart is not a memory-erasure API.

The bound is cumulative, not a promise that the 1 MiB foreign borrowed-buffer
profile accepts a single large frame. Dual x86-64 machine tests use the pinned
selfhost binary and the explicit direct emitter without fallback. They preserve
state while feeding multiple admitted buffers, compare two partitions of
2,098,177 bytes, and cover padding transitions, interposed empty feeds,
restarts and atomic refusals. The tests compile the original Rust
`LegacyHashReader` body and size constant, using a capture sink at the
`sha2` update interface; hashlib hashes the captured bytes, with a fixed
known-answer control. This is not execution of the original external `sha2`
crate or the full original artifact observer. Tests exercise 128 GiB declaration
admission, not hashing a 128 GiB file.

```sh
python3 -B -m unittest -v hia.tests.test_release_raw_artifact_sha256
```

Exact byte-count matching checks only supplied bytes. It does not observe EOF,
reserve an I/O budget, open files, prove immutable custody, compare the caller's
locator, grant release/quorum authority, or drive a production path. Matching the
legacy SHA-256 label never substitutes for the full SHA-512 content commitment.
