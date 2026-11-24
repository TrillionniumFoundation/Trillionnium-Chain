# Release held-descriptor check-only policy

The original
[Unix Rust adapter](../../../trillionnium/crates/trnm-release-bundle/src/content_v1.rs)
accepts an already retained file handle. Before reading it checks regular file,
declared raw length and offset zero. It observes RAC1 plus the exact bytes from
that handle, charges the encoded byte count plus the EOF probe, rejects the
legacy SHA-256 mismatch, and only then compares before and after descriptor
metadata. It does not reopen a path or re-resolve a directory root. A completed
rename of the opened file or its directory before the first sample does not
redirect the held read.

The bounded native entry `file_descriptor.hepta` consumes only typed private
records. For an `RFD1` frame, the little-endian 32-bit operation determines
two distinct stages:

- **1, 88 bytes:** declared raw length and observed offset, each little-endian
  u64, followed by one 64-byte stat record. The native precheck requires a
  regular file, exact raw extent, and offset zero.
- **2, 136 bytes:** two 64-byte stat records for the same retained descriptor,
  before and after byte/locator observation. The native postcheck compares all
  eight fields. This operation alone does not establish that a read occurred.

Each record contains dev u64, ino u64, mode u32, four reserved zero bytes,
len u64, mtime seconds and nanoseconds as i64, and ctime seconds and nanoseconds
as i64, all little-endian. The status is 0 for matched predicates, 100 for a
malformed private record, and 101 for a failed descriptor predicate. No result
or scratch bytes are written, and no caller-supplied PASS enters either stage.

[Qualification](../../tests/test_release_file_descriptor.py) runs the actual
unchanged Rust observer body and typed Rust reader on fresh disposable Unix
descriptors with pinned rustc. Standalone digest adapters use independent
coreutils; this is not a whole locked production Cargo build. The comparison
uses a different held file on the shadow side, with actual stat/offset from
that descriptor and RAC1/CCH1, raw SHA-256 and strong SHA-512 computed by the
pinned HIA backends from observed bytes. The original scope and monotone
reservation, offset, failure order, old locator comparison and strong claim
bytes must match. The tests cover ordinary file and containing-directory
renames completed before the first sample, refused nonregular/offset/size
inputs, legacy mismatch, and each stat field independently.

HIA's currently pinned borrowed-buffer ABI neither acquires the descriptor nor
performs stat/read/seek. Python owns the strictly synthetic host IO boundary
here. Matching observations do not prove an immutable snapshot or fresh
pathname/root custody, and this is not a production reader or a release
authorization. The Rust boundary remains authoritative.
