# Bounded Safetensors header JSON

This standalone immutable candidate translates the original private
`TensorHeader` visitor. It takes the JSON header bytes only, not the raw file,
contract, model root or owner observations. The previous framing entry is
unchanged. This is not a verified file layout: dtype remains a decoded string
(even an empty or unrecognized string), dimensions and offsets remain unsigned
u64 values, and no order or geometry is imposed on the offset values.
Comparing that result with the contract, checking coverage and final digest,
and implementing reader/clock semantics are separate steps.

The stock candidate profile allows up to 131,072 input bytes, 128 tensors,
64 metadata pairs, and 291,072 bytes of scratch. Status 218 means outside that
private implementation profile, not invalid original JSON. The original has
higher independent bounds (1 MiB raw framing, 16,384 tensors, 1,024 metadata
pairs). Status 217 means failure of the scoped JSON visitor; 102 means
insufficient scratch or output. Output is atomic. On success, it consists of a
LE64 tensor count and records ordered as Rust's `BTreeMap<String, …>`: LE64
name length and decoded UTF-8 name, LE64 dtype length and decoded UTF-8 dtype,
LE64 rank, rank LE64 dimensions, then two LE64 offsets. Metadata is validated
but omitted just as in the original projection.

Parsing reuses the existing pinned whitespace, UTF-8 and JSON string/escape
functions, including decoding surrogate pairs. Duplicates compare the actual
decoded names, not a truncated or probabilistic identity. Per-tensor names are
nonempty, at most 255 decoded bytes, and may not contain control characters.
The special `__metadata__` object allows unique keys of at most 255 decoded
bytes and string values of at most 16,384 decoded bytes. No normalization is
applied. Shape rank is at most eight. Each tensor requires exactly the three
named fields, in any order, and the offsets array must have exactly two u64s.
Trailing JSON is not accepted.

Work is linear in raw JSON/token bytes plus bounded decoded-key comparisons:
no tensor or metadata table can exceed its private cap. Scratch has separate
metadata rows, sorted tensor indices, fixed tensor rows, a kept-string arena
whose used bytes are bounded by input bytes, and a full-input-sized transient
decoded string region; no silent truncation or aliasing of caller output.
Scope growth may replace the bounded insertion/duplicate index independently of
the grammar.

The differential uses pinned Rust and actual locked Serde/serde_json built from
the original DA package, then compiles the original byte-for-byte private
visitor definitions and `valid_name` in an isolated temporary comparator. The
test does not modify any tracked Rust, call a store or loader, or claim
production verification or authority.
