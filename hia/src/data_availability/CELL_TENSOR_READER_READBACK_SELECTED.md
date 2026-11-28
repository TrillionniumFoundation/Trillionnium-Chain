# Immutable name-selected Safetensors bytes

This private bounded value operation reads one tensor, by exact UTF-8 name,
from the selected declaration's own immutable container. It validates the
complete original contract/root binding, header, tensor roster, ranges,
coverage and native raw-container SHA-256 before resolving the name in the
selected file's canonical declaration order. A successful result is LE64
tensor length followed by those exact bytes, not a view, coordinate,
capability or loader token. The caller does not supply an offset, an ordinal,
a previously verified marker, or a digest calculation result.

* `f0`: the ordinary contiguous reader frame, followed by the exact name
  bytes and their LE16 size. The final selector is outside the logical
  reader frame and is never hashed as file material. The Direct per-loan
  limit remains 1 MiB including this selector; the stock Selfhost fixture
  takes the same logical 4 MiB reader frame and at most 257 selector bytes.
* Direct `f1`: the ordinary five reader loans plus one independent read-only
  name loan, followed by output and scratch. The three immutable body loans
  may cut the selected tensor arbitrarily; byte order is preserved across
  all three. The logical reader frame remains at most 4 MiB, with its
  existing 1 MiB header, 16,384 tensors, 1,024 metadata keys and 3 MiB body.
* Only a valid 1–255-byte UTF-8 query can match. Different spelling or
  normalization is a miss, not an alias. A query miss or invalid query
  returns 226 after the complete reader succeeds. Status 102 covers
  insufficient output and selected payloads greater than 1 MiB minus 8.
  Other reader failure statuses keep the original reader order.
* Output is never modified on refusal. The final range is checked against
  the same logical verified file length, and full capacity is checked
  before writing the eight-byte size or any payload byte. Output suffix
  canaries are left intact. Scratch is mutable temporary work, never a
  source of trusted caller data: this entry fills the extra nonoverlapping
  264 bytes starting at 840,192 with its own bounded selector length and
  bytes, and the existing verified parser owns the core range tables.

The frozen Rust comparator calls the unchanged private
`verify_reader_layout` on an inert `Cursor`, then observes the exact
canonical named range in that same slice. Its disclosed temporary
`cfg(test)` witness is absent from the byte-identical non-test build.
Tests include non-physical declaration order, a second selected file,
non-normalized UTF-8, three-way body cuts, exact physical input and output
limits and late-digest/short-output atomicity. Independent public reader,
range-observer and coordinate-based TVB1 entrypoints remain unchanged.
No storage, owner, live file, TensorView, networking, loader/context
admission, time policy or production integration is provided.
