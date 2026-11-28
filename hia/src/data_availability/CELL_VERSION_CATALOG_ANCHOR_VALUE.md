# Immutable CVA3 anchor value

This native value-only entry for the original
`CellVersionCatalogAnchorV3` reads a borrowed 44-byte canonical wire
value: `CVA3`, an unsigned big-endian generation, and a 32-byte
declared commitment. The original generation range is 0–384 inclusive.
A partial tag is incomplete, a complete wrong tag takes precedence over
body truncation, and a complete correctly tagged frame must consume all
bytes, use a permitted generation, and have a nonzero commitment.

The first 84 output bytes contain the generation getter as unsigned
little-endian u64, the exact 32 declared commitment bytes, and the
44-byte canonical re-encoding. The stock ABI scratch loan is unused. For a refusal or
short output, the output is unchanged; the suffix past 84 bytes is
unchanged on success. No argument is mutated other than the selected
output prefix.

This is not a fresh hash, an authenticated anchor, a retention
decision, or a catalog owner call. It does not read external state or
store, update, reconcile or adopt anything.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_version_catalog_anchor_value
```
