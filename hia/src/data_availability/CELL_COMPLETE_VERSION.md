# Native bounded TCV1 declared metadata

One stock native call consumes the actual TCV1 byte format in an immutable
loan of at most 1 MiB. It uses the original canonical TMR1, TCD1 and TCM1
parsers. The complete Rust envelope accepts metadata up to 8 MiB; no relation
above the common native limit is claimed.

The wrapper checks nested frame and manifest syntax in wire order and refuses
any suffix **before** semantic validation. It then checks the computed
environment closure ID and model family, requires Configuration-only
environment members, and merges the two original releases' already-sorted
cell-ID lists. A shared ID is counted once for coverage, but its declaration
must agree with both closures, model first. Every original TCM1 ID is computed
from its own canonical bytes. Its context, declared payload digest and length
must agree with the appropriate file metadata. The canonical TCV1 byte
length condition needs no second accounting pass: the immutable input was
exactly consumed and its checked cap is stricter than the original 8 MiB.

On success the first 36 output bytes are the actual environment TCD1 ID and
a 32-bit little-endian manifest count. Refusal never writes to the output.
The caller supplies disjoint buffers and at least 16,032 bytes of private
workspace. A compact model role-offset table starts at scratch byte 13,944
and the environment ID is retained at 15,992 before later manifest hashes.
The code never accepts an identity, lookup offset, or decision from a host.

The original Rust oracle isolates the unchanged real `decode`, `new`,
`validate`, `encode` and `commitment` methods. Fixtures include an exact
1 MiB ordinary valid frame, all 512 manifest slots, and an original Rust
success one byte above the shared limit. Neither original Rust-only hash
observation nor environment ID is a native version commitment. This codec
does not open files or weights, check actual payloads, validate an owner or
loader, run any executable, or change storage, authority or production.

```sh
python3 -B -m unittest -v hia.tests.test_cell_complete_version
```

The locked original reference requires the same verified
`HIA_M09_SHA2_RLIB` as the adjacent TMR/TMA/EVB tests.
