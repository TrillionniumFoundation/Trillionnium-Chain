# Fixed W1 binary and generated constraint audit evidence

This directory accompanies the
[semantic boundary audit](../../docs/security/W1_QROM_SEMANTICS_AUDIT_20261107.md).
It is separate from the earlier fixed QROM implementation-map evidence.

- [report.json](report.json) records the independent fixed R0BF-to-image
  reconstruction, 208 page digests, a concrete uncommitted-ELF-byte example,
  the shared Poseidon2 input vector, and generated constraint degree bounds.
- [zkr-programs.json](zkr-programs.json) records the separate full official ZIP
  audit: all 32 named program byte digests and shapes, the default 27-program
  membership, canonical field words, and the capacity inequality at `po2=18`.
  It marks the catalog control IDs as declared, not recomputed from bytecode.
- [control-id-join.json](control-id-join.json) and
  [control-ids-all27.json](control-ids-all27.json) are independent later-stage
  native reconstructions of the actual FRI code commitments. All 27 default
  programs and the tree rebuilt from their computed IDs match the fixed
  catalog/root. [control-id-execution.json](control-id-execution.json) binds
  these observed runs to source, generated constants, binary and job identities.
  The [control-ID note](../../docs/security/W1_ZKR_CONTROL_ID_RECOMPUTATION_20261107.md)
  explains exactly which commitment sub-obligation this closes.
- The six complete `.crate` files are the exact Cargo release archives named
  by the checked lockfiles. Their SHA-256 digests are checked before reading
  any member. Keeping complete archives makes selected-source membership
  independently inspectable without trusting a separately copied source text.
- [LICENSE-RISC0](LICENSE-RISC0) is the upstream Apache-2.0 license.

The archive identities and individual source-member hashes are in the report's
`provenance` section and are enforced by
[w1_qrom_semantics_audit.py](../../scripts/w1_qrom_semantics_audit.py).
`risc0-build-3.0.3` has its own older VCS commit; the other five selected
archives identify commit `8c215e2f4ccdd935f0517bf05d90f1ae032840a9`.

The report closes byte reconstruction, release-kernel equality and generated
constraint degree bounds. The later native report additionally closes the
fixed bytecode-to-control-ID/root reconstruction. Compiler correctness, intended execution semantics,
all reachable traces, zero-control-digest exclusion, cryptographic receipt
verification and the complete QROM/resource claims remain outside this result.
