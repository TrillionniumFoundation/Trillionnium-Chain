# X230 PQ original untracked tests — exact-source preservation (HOLD / NOT_RUN)

This folder preserves **three original, untracked Rust test-source files** from an X230 historical local worktree. It is a **quarantined research source archive**, not a production module or an accepted patch. It does not change any Cargo module wiring, original tested source, runtime policy, consensus settings, workflow, or deployment.

## Source identity and parent contract

- Original host alias: `x230` (read-only origin inspection on 2026-11-11).
- Original worktree: `/home/qian/trillionnium-review-source/pq-full-20261103-4502`.
- Original repository origin: `https://github.com/TrillionniumFoundation/Trillionnium-Chain.git`.
- Original branch: `fix/chain-pq-full-20261103-4502`; original HEAD: `3f3a5c5017367eefc0970d512920a6eaa4a29c35`.
- Original HEAD parent: `12fe5f2c1f19704fe7eb635dede6839ed8b1e91e`; grandparent: `1c7e8ab7cd6a321cad4e6c7f7e8a197d7b3be14c`. This original stack was **not rebased, rewritten or cherry-picked**.
- GitHub default `main` was `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0` at branch creation. The original HEAD diverges from that branch; the standalone publication branch intentionally does **not** assert old-tree runtime compatibility.
- The original worktree also had 12 tracked modifications, several other untracked files, hidden lock files, and uploader records, all **excluded**. These three test files were untracked; their byte identity does not by itself establish a passed runtime or a tested commit.

| Original relative path within `trillionnium/crates/` | Preserved basename | Git Blob SHA-1 | SHA-256 | Bytes |
| --- | --- | --- | --- | ---: |
| `trnm-protocol/src/pon_wire/state_root_arithmetic/exact_input_tests.rs` | `exact_input_tests.rs` | `5a68faa6f0481ff7b64f25183848803e6c43bcd1` | `6e7186632d337bd6f2d72a464910b041a7423cc3f24fb4445763c9925ec245df` | 4905 |
| `trnm-mvcc-fee/src/pon_commitment/config_root_arithmetic_tests.rs` | `config_root_arithmetic_tests.rs` | `336d8d27a154ab10c209e4b4a1cc0a201a06ae16` | `159f754b2b1302a5a8a0f6a349e1ed0ff6429c5c2cd9ef816524c5cec7c7d0e1` | 8252 |
| `trnm-mvcc-fee/src/pon_executor/canonical_string_tests.rs` | `canonical_string_tests.rs` | `98a44c711baec71e629c6f62069adb74fc27c1db` | `445c4602aa6a3f3097f5bd632be2a6aaaa7d75c11bb78838dfda8b040c5cfa11` | 3454 |

## Relation to existing recovery PRs

Existing [Draft PR #899](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/899) already preserves the exact original `exact_inputs.rs` **implementation** blob `8d6d8f64cc5789ac78bf4bf27bdafa228c9e2be5`; existing [Draft PR #902](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/902) already preserves the exact original `canonical_cell.rs` **implementation** blob `4669d2e13bce8212634c16b8217845e3d737b8b5`. Neither implementation is duplicated here. These tests are complementary historical files; no cross-PR execution compatibility is asserted.

## Qualification and security status

**HOLD / NOT_RUN.** Full byte-for-byte GitHub readback of the three newly published test-source files matched the local original Git Blob IDs. A bounded source inspection found no obvious private-key/token literal in these three files, but this is **not** a complete secrets/privacy certification. No native `cargo test` or current-main integration test has been executed against this candidate. X230 reported `rustfmt: not found`, so formatting validation is also **NOT_RUN**. Standalone test source references old in-repository types, fixtures and module context; no claims of successful compile, improved PoN security, post-quantum guarantees, or deployment readiness are made.

**Adoption gate:** independent reviewer must bind exact current code/config/dependencies/evaluator identities, review all source and any related credentials, wire tests under a new explicitly approved candidate, execute real positive and negative tests plus unchanged original CI, and preserve any failures or HOLD decisions. This Draft PR must not be merged as product qualification merely because its files are archived or CI happens to pass.
