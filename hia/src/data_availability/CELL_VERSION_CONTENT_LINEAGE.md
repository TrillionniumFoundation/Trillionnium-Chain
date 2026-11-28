# Bounded native TCV3 declared content lineage

`trnm_cell_version_content_lineage_v3.f0` takes a read-only TCV3 envelope
of at most 1 MiB (the unchanged Rust wire bound is 32 MiB). It preserves the
original maximum of 16 declared versions. It validates the embedded canonical
TCV2/TCV1/TMR1/TCM1 declarations directly within the same immutable loan;
neither version commitments nor legacy model aliases are supplied separately.

First it parses the complete declared member sequence and checks the suffix.
Then it checks root index order, recomputes each member's TCV2 commitment for
strict ordering, and computes each TMR1 ID and refuses duplicates. Only then
does it resolve each parent in canonical member/parent order and check its
exact family and strictly smaller unsigned generation. Strict descent means
a cycle is impossible; at most 16 nodes means the original longest-depth
bound of 16 already holds. The final graph pass requires every node to be
reachable from the declared roots. No inferred edges or implicit roots.

Provide disjoint input, at least 72 output bytes and 133,280 bytes of scratch.
Success yields the little-endian u32 counts (versions then roots) and the
64-byte SHA-512 commitment of the original TCV3 domain and exact canonical
wire. Every refusal leaves output intact, all calls retain immutable input
and output/scratch suffixes. Scratch may change on refusal. No payload/cache,
live readback, pin authority, selection of CURRENT, or permission to use a model
is provided by the codec.

The mechanically relocated TCV2 body is checked against the unchanged
published source, and both pinned native emitters are compared with the
unchanged public Cargo-locked Rust `decode`, `encode`, and `commitment`.
The test includes positive native 1 MiB, original Rust 1 MiB+1, all 16
roots, a full 16-node chain and a shared-parent diamond.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_version_content_lineage
```
