# Native TCV1 version commitment

The commitment is exactly the original Rust SHA-512 of the 29-byte domain
`TRNM/Cell/CompleteVersion/v1\0` followed by the complete canonical TCV1
bytes. It is a content digest, not a signature, trusted snapshot pin or
authorization decision.

The optional entry uses the same immutable input loan throughout one call.
It checks the full existing TCV1 syntax and declared relationships before
hashing and performs no intermediate result publication. The private
non-publishing validator is mechanically derived from the exact already
qualified TCV1 entry CFG, with the same original helper bodies and order.
The regression derives it again from the pinned source, rejects a stale
source, and compares every derived byte. The previous source and three-loan
ABI remain unchanged.

The unchanged shared input extent is 1 MiB; Rust-only evidence above that
boundary is not HIA coverage. A caller supplies disjoint buffers and at
least 131,232 bytes of scratch. On success the first 100 output bytes are
the environment closure ID (32), the original manifest count (little-endian
u32), and the version commitment (64). On refusal no output is written.

The SHA-512 context uses its existing first 1,512 bytes and its original
digest location. In private scratch the validated TCV1 environment ID lives
at 15,992; the fixed domain begins at 16,032. The implementation streams
the domain and the immutable source directly, without staging a second
copy of the TCV1 input. The exact Rust differential includes a full 512
member version, a valid version at the shared extent, padding boundary
cases, and compound parse/semantic refusals. It never loads or verifies
actual payload, files, weights, owner state, signatures or live services.

```sh
python3 -B -m unittest -v hia.tests.test_cell_version_commitment
```

The real original differential uses the same locked `HIA_M09_SHA2_RLIB`
as the complete-version test.
