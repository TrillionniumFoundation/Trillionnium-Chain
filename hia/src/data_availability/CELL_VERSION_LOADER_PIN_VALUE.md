# Immutable loader context and pin value conversion

This native entry ports two public original _value_ operations:
`CellVersionLoaderPinV3::from_context` (mode zero) and
`CellVersionLoaderPinV3::loader_context` (mode one). The first sorts the
roles by their original enum order and preserves duplicates. The second
clones the supplied pin's role sequence without reordering or removing
entries. A direction change therefore does not undo an earlier sort.

The private fixture adapter begins with `NVLP0001`, a mode byte, a
big-endian u16 family length, and big-endian u16 role count. Next come
the opaque 32-byte closure ID; the five 32-byte context fields (base,
parent, tokenizer, layout, runtime); the unsigned big-endian u64
selected generation; the 32-byte loader profile; and big-endian u64
payload and chunk caps. The family UTF-8 bytes and original typed role
bytes follow this fixed 261-byte prefix. Family length is at most 4,096
and role count at most 1,024 in the bounded native adapter. Unknown modes,
non-UTF-8 strings, absent/trailing bytes and bytes that are not original
role codes (1 through 6) are refused at the adapter only.

The output is the same-sized byte representation with exactly the role
behavior above. Suffix bytes remain unchanged. All validation precedes
writes. The third stock ABI loan is unused. Within this immutable
value conversion, empty or repeated role vectors, empty or otherwise
non-policy UTF-8 family strings, and zero caps are copied or sorted.
These conversions are distinct from the original private policy checks;
they do not open a loader, establish identity, authenticate an anchor,
or admit a catalog, owner or retention action.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_version_loader_pin_value
```
