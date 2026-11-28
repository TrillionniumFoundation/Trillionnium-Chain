# Bounded immutable resident-tensor byte operations

`trnm_cell_tensor_view_bytes_v1.f0` projects an ordinary, complete immutable
byte loan. The caller supplies the backing bytes and numerical view
coordinates. The entry bounds checks those coordinates and reproduces the
original view operations; it does **not** admit or authenticate any file,
parse a safetensors header, read a store, infer dtype from opaque input, or
produce a loader / execution / ownership token.

The 40-byte header precedes the backing bytes; the complete loan is at most
1 MiB. Header fields are `TVB1`, operation u8, dtype u8 (1 F32, 2 F16,
3 BF16), reserved u16=0, private chunk width u32, tensor start u32, positive
tensor byte length u32, reserved u32=0, argument u64, and requested bytes u64.
Integers are little-endian. The effective chunk width is a single loan-sized
chunk or an original power-of-two chunk width of at least 16,384 bytes.
View extents are checked before reading or writing. Start need not be aligned.

* Operation 0: both request fields are zero. Return the u32 segment count,
  that many u32 segment lengths, and exact tensor bytes in segment order.
* Operation 1: the request specifies byte offset and requested amount. Copy
  only the exact requested bytes, including an empty copy at the end.
* Operation 2: the argument is the element index, requested bytes is zero.
  Validate F32 dtype, then multiplication overflow, then byte range. Return
  the four exact little-endian F32 bits, including unaligned values,
  negative zero, subnormals, infinities and NaN payloads. There is no
  floating-point evaluation or normalization in this entry.

All capacities are checked before publication; every refusal leaves output
untouched. Input and unused scratch are unchanged; successful calls leave
the output suffix untouched. The test obtains genuine read-only views by
the original committed synthetic public residency method under private
disposable SQLite fixtures, then compares the actual original
`segments`, `copy_bytes` and `read_f32().to_bits()` with both native emitters.
The local synthetic residency step is test plumbing only.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_tensor_view_bytes
```
