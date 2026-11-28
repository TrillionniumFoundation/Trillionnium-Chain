# Private CellNative source-snippet canonical value
This entry projects the original public `canonical(&SourceSnippet)` or
`canonical(&Vec<SourceSnippet>)` to exact sorted-key compact JSON, using
the original field types. It does not call the original private source
decoder: `content_hex` is inert ASCII text, not interpreted as hex or
UTF-8-encoded source. This establishes no origin, source entitlement,
admission, training eligibility, or production state.

The input is an eight-byte magic, `CSS1\0\0\0\0` for one object and
`CSB1\0\0\0\0` for an ordered list, followed by one little-endian
u64 count (exactly 1 for CSS1; 0 through 8 for CSB1). Each row has four
little-endian u64 words: content length (max 8192), ID length (max 256),
origin length (max 256), and the u8 label (0 through 255 in a u64 slot),
followed immediately by the three ASCII byte spans in order. Exact
extent is checked before any output, capped at 69,904 bytes.

The caller provides 419,328 bytes of disjoint private scratch. At most
69,632 text bytes can expand by up to 6×; the remaining arena covers
field names, enclosing punctuation, label decimal and an eight-byte
length. The output is a little-endian u64 JSON length followed by the
compact JSON and an untouched suffix. Status 1 is private frame/ASCII
refusal; 102 is insufficient output or scratch. No failure publishes
output. A short output may leave staged bytes in private scratch.
