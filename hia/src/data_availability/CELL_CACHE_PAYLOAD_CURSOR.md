# Offline cache payload cursor arithmetic

`trnm_cell_cache_payload_cursor_v1.f0` observes the arithmetic of the
original `CachePayloadReader` over one loan of at most 1 MiB. The request
is an operation byte, a little-endian u64 current position, a little-endian
64-bit operation argument, and the exact original TCM1 manifest.
The complete manifest is checked by the published original-parity TCM1
decoder before either arithmetic branch. No backing or chunk bytes,
manifest authority, or previously verified state is claimed.

* Operation 0 is `SeekFrom::Start`: the argument is an unsigned absolute
  logical cursor. Operations 1 and 2 are End and Current, with the
  argument interpreted as signed i64 relative to declared size or current
  position. The result is an LE64 next cursor. The u64 representability
  check matches the original i128 addition and conversion. A beyond-EOF
  position is legal; underflow and overflow return 246 without output.
* Operation 3 is the original **one-chunk read arithmetic only**, with an
  unsigned requested count. It returns four LE64 values: row index, offset
  within that row, count, and projected next cursor. Addressing uses the
  first validated row's actual width and the selected row's declared size.
  Empty requests or positions at/beyond EOF return zero index, offset and
  count with the original unchanged position. A nonempty plan never crosses
  the selected row. The count is conditional on the original reader later
  obtaining an exact verified row, not a successful read or a durable
  handle.

Malformed call envelopes return 100, original TCM1 errors are unchanged,
and insufficient output capacity returns 102 without any partial write.
Output suffix, input and the unused scratch buffer are unchanged. The
planner needs no model payload memory: tests reach an original 16,384-row,
64-GiB declared manifest and exercise source-proven tail sizes, empty/EOF
and the exact signed/unsigned arithmetic boundaries.

The offline Rust comparator builds the locked unchanged crate, invokes
the genuine TCM1 decoder, and mechanically extracts the exact frozen
`tensor_reader.rs` Seek and Read arithmetic statements. The pure witness
excludes both deadline checks, the cache lookup, the actual byte copy and
I/O. The observed row extent uses `expected.size` instead of
`cached_bytes.len()` only under the original checked equality. The test
does not construct a reader or a store. Both stock emitters are checked
against it. Actual cache hashes, missing payload errors, cache replacement,
cursor lifetime, deadline/cancellation and reader ownership remain
outside this operation.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_cache_payload_cursor
```
