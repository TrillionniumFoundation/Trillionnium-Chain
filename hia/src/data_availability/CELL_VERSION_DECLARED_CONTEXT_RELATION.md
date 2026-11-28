# Immutable TCV1 declared-context comparison

This finite kernel implements the pure comparison in the unchanged
`CellVersionManifestV1::verify_for_loader` for canonical bounded metadata.
It does not load anything and returns only a status, not an authorization,
owner attestation, trust decision, cached proof, or full TCA3 result.

One immutable input loan contains, in order:

- Exact canonical original TCV1 bytes.
- A 64-byte expected version commitment. Native code recomputes original
  domain SHA-512 over the TCV1 prefix itself.
- Two frames, model and environment in original order, with 32-bit big-endian
  lengths and existing `VRLC0001` descriptor contents (no per-frame footer).
- A 32-bit big-endian length of the TCV1 prefix.

The shared compiled extent remains 1 MiB for the **entire** loan; larger Rust
values outside that loan are not qualified. Scratch is 131,232 bytes. The
immutable input and output buffer do not change. The local ABI refuses
unsupported frames and lack of scratch; the original typed error order within
scope is canonical version validate, commitment, model context, environment
context, then either declared chunk cap. Status 65 means version commitment
mismatch, 66 means one closure's chunk budget was insufficient, and 60–64
are the already used TCD1 relation errors.

The existing canonical TCV1 validator is mechanically reused with its extent
argument isolated from the borrowed suffix. The two TCD1 adapters admit the
extent of each embedded closure before hashing its exact unchanged bytes.
Canonical version validation already matches every sorted TCM1 to its
declared membership; the final merge counts each original chunk roster in its
own closure, without borrowing another closure's budget. Count accumulation
cannot overflow because the validated original limits contain at most 512
manifest frames and at most `MAX_CHUNKS` (a bounded u32) per manifest. The
merge advances both sides for equal identifiers as in the original membership
rule; ordinary original fixtures use distinct model/environment contexts, and
no self-referential shared identity fixture is inferred from them.

The real local comparison invokes public unchanged locked Cargo decode,
commitment and declared comparison on synthetic metadata. Neither this test
nor the kernel reads files, payloads, a cache or any live loader. This also
does not establish root/pin provenance, deployment readiness, or qualification
of other Cell gates.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_version_declared_context_relation
```
