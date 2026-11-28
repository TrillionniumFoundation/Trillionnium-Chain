# TCV1 declared model and environment relation

`cell_version_environment.hepta` is the first semantic relation in Rust
`CellVersionManifestV1::validate`, not a replacement for `TCV1`. It takes one
immutable, private qualification frame, two mutable loans, and no caller
digest, authority decision, or prior-validation signal:

```
EVB1 | u32be model_bytes | canonical TMR1 | u32be environment_bytes | canonical TCD1
```

The frame must be exactly consumed and at most 1 MiB. Both existing canonical
value parsers run on slices of the same original loan. The operation uses
13,944 bytes of private scratch. It computes the actual environment closure
ID as SHA-256 over `trnm.cell-dependency-closure.v1\0` and the full canonical
environment wire. It requires this ID to equal the model's declared runtime
ID, and requires exact model/environment family bytes to match. Only then does
it require every environment file to be `Configuration`. Other context words
are not compared by this stage. A successful result writes exactly the 32-byte
environment ID; any refusal leaves the output unchanged.

Codes 84 and 85 are the declared binding and role refusals in original semantic
order; 100 is private-frame refusal and 102 is insufficient native workspace or
output. Nested parser failures use their existing status numbers. This private
frame checks its own boundaries before decoding nested data; it does not order
errors for incomplete, malformed, or uncovered TCM1 children in a real TCV1.

The comparison uses the source-fingerprinted unchanged Rust validate prefix and
independent complete Rust TCV1 constructor/decoder controls. Those controls
include the checked-in vector, a binding-vs-role-vs-coverage conflict, a
role-vs-coverage conflict, and later manifest/whole-wire predicates. They do
not link cache, loader, or network methods. Run with the repository's pinned
two native emitters and the verified original SHA-2 lock graph:

```sh
python3 -B -m unittest -v hia.tests.test_cell_version_environment
```

The actual original Rust comparison requires `HIA_M09_SHA2_RLIB` as in the
adjacent manifest qualifications; the normal native fixture checks remain.
Full TCV1 manifest coverage and per-file descriptor links, complete version
SHA-512 identity, CTS1, authority pins, assembly/loading, storage, payload
readback, and production routing are not supplied by this operation.
