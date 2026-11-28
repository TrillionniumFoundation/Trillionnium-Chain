# BEP52 immutable piece comparison

The private `f0(readbuf,mutbuf,mutbuf) -> u32` accepts one immutable loan:
the complete [BPB1 binding request](BEP52_BINDING_VALUE.md), one raw
[CBP1 proof](BEP52_CHUNK_PROOF_VALUE.md) without its wrapper mode byte,
the caller-supplied piece bytes, then a big-endian u32 BPB1 extent and a
big-endian u16 CBP1 extent. The two extents are checked before computing
any span. The output loan is never read or written. Success returns 0.

Native HIA checks the original TCM1 and independent context and manifest
pins, the original piece geometry, and the CBP1 structure. The proof
must repeat the exact manifest identity, the canonical infohash derived
from the validated declaration, and the leaf count. The selected original
TCM1 row supplies the exact length and expected digest. HIA checks the
physical piece length, recomputes SHA-256 on the exact supplied bytes,
then folds the supplied siblings bottom-up with the index-determined
orientation. The result must match the separately computed declared
piece root.

This routine requires 1,760 plus 32 scratch bytes per padded leaf, up to
526,048 bytes. The full 16,384-row TCM1, maximum-depth proof and a
physical 16 KiB piece fit the existing stock 1 MiB input loan. No
execution profile or bound changes. Scratch bytes beyond the required
arena remain untouched. BPB1 and CBP1 statuses retain their original
shape meanings; 40–44 identify proof pins, coverage, physical length,
physical digest and final root respectively. ABI statuses 100, 102 and
103 mean framing failure, insufficient scratch and internal hashing.

The scoped output is a comparison of local immutable supplied bytes.
It neither proves possession or availability nor accesses a file, a
provider, a peer, a transport, or storage. It does not authorize, load,
or materialize a model or evaluate its full payload.
