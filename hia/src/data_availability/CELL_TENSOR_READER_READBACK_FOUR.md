# 4 MiB immutable Safetensors readback

This independent value-only candidate retains 16,384 tensors, 1,024 metadata
keys, the 1 MiB raw JSON limit, exact declaration/layout checks, and the
original 114-byte result. Its whole private frame may now be 4 MiB.

Stock Direct `f1` borrows five read-only physical ranges: declarations plus
the LE64 prefix, the whole JSON header, and three successive data ranges.
Each is at most 1 MiB; there are seven disjoint borrowed buffers including
output and scratch, within the stock eight-range guard. Stock Selfhost
`f0` borrows the same logical frame contiguously via the existing private
fixture mode. The shared profile requires declarations plus LE64 at most
1 MiB and body at most 3 MiB. Header offsets still fit the exact old compact
representation, and the old numeric intervals and 840,192-byte scratch
layout don't change. All prior entry points and stock limits stay unchanged.

The new reader uses the already published parameterized native SHA-256
functions with an explicit candidate-local 4 MiB bound. The original LE64,
header and three body ranges are consumed once, in argument order, by one
native SHA state. No hash, byte counter, layout verdict or authoritative
state is supplied by the caller. Original within-profile rejection order
is preserved. A native-only logical overflow returns 210; impossible
physical segmentation (including a contiguous body over 3 MiB) returns
225. The original can accept those otherwise valid containers.

The frozen public Rust `verify_reader` over owned synthetic `Cursor`
bytes is compared against both stock emitters, including a full 4 MiB
frame with exact 1 MiB JSON, 16,384 tensors, 1,024 metadata keys and a
rank-eight tensor. Tests distinguish extent, interval and digest failures:
one-byte extent changes, wrong physical splits, same-size header or tail
changes, and swapped body ranges. Uneven segment boundaries preserve
the original digest. Live scratch and capacity checks show the selected
digest and sorted intervals remain exact without any partial output.
This is an immutable-memory profile, not file streaming, real storage,
model loading, deadlines, activation or production authority.
