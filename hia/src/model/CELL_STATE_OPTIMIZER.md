# Private CellState with original momentum optimizer
`cell_state_optimizer.hepta` emits the exact original compact sorted-key
`canonical(&CellState)` bytes for a fixed-size, typed `optimizer: Some`
profile. This is serialization, not `validate_state` or the optimizer
algorithm. It does not train, install, execute, or authorize anything.

The wire is the prior CellState format with magic `CSO1\0\0\0\0` and a
mandatory 24,680-byte suffix after the five ASCII strings. The suffix
contains four consecutive row-major matrices, three rows of 257 signed
little-endian i64 per matrix: base first, then three ordered deltas. An
unsigned little-endian u64 step is last. The optimizer schema is implicitly
the exact original momentum schema literal. Original arbitrary matrix
geometries and alternative optimizer schema strings are out of scope.
The complete input is 24,768 through 26,304 bytes.

The caller supplies 73,728 bytes of private work; 3,084 signed numbers
take at most 61,680 decimal bytes plus fewer than 3,123 matrix separators
and brackets, leaving room for the state and fixed optimizer metadata.
The output is a little-endian u64 JSON length followed by exactly those
bytes. Status 1 refuses input; 102 refuses capacity. Neither publishes
output (a short output may leave staged bytes in private scratch).
The previous `CSV1` entry retains its own magic, extent, 8,704-byte work
bound and null-optimizer ABI. Both entry points share staged serialization
and the signed-decimal row loop.
