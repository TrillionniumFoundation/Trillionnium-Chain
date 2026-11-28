# Immutable name-selected Safetensors F32 bits

This private observation reads one F32 element by index from a canonically
named tensor. It validates the complete original selected-file contract,
model root, header, roster, ordered range coverage and raw-container SHA-256
on the same immutable reader loans. Only then does it resolve the tensor
by exact UTF-8 name and obtain its dtype and range from the matched declared
record and native validated layout. There are no caller-supplied file
coordinates, dtype, prior verification or authority markers.

The request is LE64 unsigned element index followed by a 1–255-byte exact
UTF-8 tensor name. Stock contiguous `f0` appends the request and its LE16
length outside the reader frame; Direct `f1` receives it as the sixth
read-only loan, after the ordinary five reader loans and before the two
mutable loans. The logical frame remains at most 4 MiB; the stock Selfhost
fixture may hold the additional 265-byte suffix and the Direct per-loan
cap remains 1 MiB. The request uses 272 bytes of private temporary scratch
beyond the existing 840,192-byte checked-range owner, without sharing the
immutable loans or changing the previous endpoints.

The original `read_f32` first refuses non-F32 declared dtype (244), then
checks multiplication of the index by four (245 on overflow), then bounds
the resulting four-byte logical range (243). Name misses (226) come
before these checks, and the prior verified-file errors come before name
lookup. A too-small output (102) is checked last; no refusal modifies
output. Success writes four raw little-endian bytes, including exact
negative zero, subnormal, infinity and quiet or signaling NaN patterns.
It neither converts nor normalizes these bits, evaluates no float math
and retains no pointers, ownership or data.

The isolated frozen Rust witness uses an inert Cursor for actual
`verify_reader_layout`, binds those exact ranges to immutable locally
owned chunks of the very same input, and calls the original
`.tensor(name).read_f32(index).to_bits()`. A distinctive nonfinite word
crosses an original 16 KiB backing boundary and all three Direct body
loans on independently chosen valid cuts. Both stock emitters match exact
original statuses and bit patterns, with identical before/after non-test
Rust library bytes. The published byte-window and coordinate-based TVB
artifact remain unchanged. No storage, resident manager, loader, owner,
deadline policy, training, network or production action is provided.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_tensor_reader_readback_f32
```
