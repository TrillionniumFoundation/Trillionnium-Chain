# Private CellState canonical value
`cell_state_value.hepta` projects the public original Rust
`cell_native_v1::canonical(&CellState)` into compact sorted-key JSON for
the `optimizer: None` subset. This is not `validate_state`: empty text,
any signed i64 memory value, and any u64 scalar are canonical values here.
It does not validate digests, model association or install a state. It
does not infer, train, iterate a runtime, or establish authority.

The immutable input begins with `CSV1\0\0\0\0`, followed by ten
little-endian u64 words: the five lengths (cell ID, model artifact, RNG
seed, schema, scope), the memory element count, then generation,
remaining steps, RNG counter and sequence. Exactly that many
little-endian two's-complement i64 words and the five consecutive
strings follow. Each text is at most 256 ASCII bytes, including
ordinary JSON escape characters, and memory has up to 32 values.
The closed frame extent is 88 through 1,624 bytes.

The disjoint work arena is 8,704 bytes: worst-case text expands to
7,680 bytes; signed memory occupies up to 671 bytes including commas;
four u64 values occupy at most 80 bytes. Fixed punctuation, names and
output length fit in the remaining 273 bytes. Output is eight-byte
little-endian JSON length followed by exactly the JSON bytes; the
unwritten suffix is preserved. Status 1 is private wire/ASCII
refusal; 102 is unavailable work or output capacity. Neither publishes
output. A short output may leave staged bytes in private scratch.
