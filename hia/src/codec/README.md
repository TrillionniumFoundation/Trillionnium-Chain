# Shared JSON byte primitives

[json_primitives.hepta](json_primitives.hepta) is the single source for four
private helpers shared by typed Value, the typed Node owner and response
encoding. Each function body is byte-identical to the corresponding function
in `state/json_value.hepta` at `d82dfe0a4b3b927eb876c812b306775f28ecb42e`.
The extraction changes composition and ownership, not the arithmetic or grammar.

| Function | Result | Caller obligations |
| --- | --- | --- |
| `value_utf8(input, start, length)` | 1 for complete canonical UTF-8, 0 for an invalid sequence | Validate the entire borrowed interval and addition before calling. No ASCII-only M06 rule is applied here. |
| `value_integer_size(bits, signed)` | Exact decimal byte count, including a minus sign when required | `signed` is 0 for u64 or 1 for i64 two's-complement bits. |
| `value_word(output, start, count, word)` | Number of emitted bytes | Validate the output interval and `count <= 8`; bytes come from the little-endian word. |
| `value_integer_write(output, start, bits, signed)` | Exact decimal byte count | Supply the full measured interval and the same checked signed selector. |

The UTF-8 helper rejects overlong sequences, isolated continuation bytes,
surrogates, values above U+10FFFF and truncated multibyte sequences. Integer
output handles the complete u64 range and i64 minimum without signed overflow.
These helpers do not expose an independently validated foreign pointer ABI,
allocate owners, authenticate input, parse JSON text or authorize a state write.

Every consumer lists the precise functions in [components.json](../../components.json).
The source is self-contained: only `value_integer_write` calls another helper,
`value_integer_size`. There are no implicit or recursive imports, no duplicate
production bodies and no change to the pinned compiler or Core limits. The
complete composed caller is admitted and compiled with the original guards.

Actual extraction and native String/Value replay observations are retained in
[json-primitives-extraction.json](../../qualification/json-primitives-extraction.json).
The original Rust comparison remains a separate mandatory CI obligation.
