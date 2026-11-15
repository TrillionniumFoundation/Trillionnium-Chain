# One observed PR #688 head, prepared without retargeting native source

Observed once at **2026-11-05 10:29:36 UTC**:

- Branch: `fix/chain-six-axis-performance-20261103`.
- PR: open and draft.
- Remote commit: `cbead1508ce8b6d9deb2a86b4bc3181da09694e7`.
- Remote tree: `624c8aad419ee05dc71a4aac507abea429018289`.
- Source under native validation remains
  `1d6a9f9b5e8abd9e86457f45199a4922f9376360`, tree
  `4a0314e72ebc45659986d03e7ca2f96cab9399ea`.

The exact GitHub comparison reports 21 commits ahead, 0 behind, and merge base
equal to `1d6a9f9b…`. All 21 returned raw commits were independently SHA-checked
locally, and their tree/parent headers match the fixed API metadata. One verified
ancestor path is:

`cbead150 → 22ef717 → f3a597f → bdab616 → 32c3d63 → 13a9d30 → 1d6a9f9`.

## Complete file delta

The API's 168 paths exactly match a comparison of the two full local Git trees;
there are no omitted or extra paths. The complete path/status/before-blob/after-blob
list is `chain-remote-cbead-paths.tsv`, also retained in
`chain-remote-cbead-prepared.json`.

| Category | Paths |
| --- | ---: |
| Evidence | 111 |
| Documentation | 7 |
| Configuration | 1 |
| Formal research and tests | 13 |
| CI scripts and tests | 14 |
| Runtime scripts and tests | 8 |
| Rust sources, examples and tests | 13 |
| Distributed source inventory | 1 |
| **Total** | **168** |

The changed Rust source/example/test paths are:

- `trillionnium/crates/trnm-crypto-primitives/examples/pon_routed_int257_grouped.rs`
- `trillionnium/crates/trnm-crypto-primitives/examples/pon_shared_material_v1.rs`
- `trillionnium/crates/trnm-crypto-primitives/src/lib.rs`
- `trillionnium/crates/trnm-crypto-primitives/src/pon_routed_int257_grouped.rs`
- `trillionnium/crates/trnm-crypto-primitives/src/pon_work/legal_attempt.rs`
- `trillionnium/crates/trnm-data-availability/src/cell/delta.rs`
- `trillionnium/crates/trnm-data-availability/src/cell/delta_network_tests.rs`
- `trillionnium/crates/trnm-data-availability/src/cell/delta_tests.rs`
- `trillionnium/crates/trnm-data-availability/src/cell/discovery.rs`
- `trillionnium/crates/trnm-data-availability/src/cell/discovery/directory.rs`
- `trillionnium/crates/trnm-data-availability/src/cell/discovery/directory_deadline_tests.rs`
- `trillionnium/crates/trnm-data-availability/src/cell/discovery/directory_wait.rs`
- `trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/directory.rs`

## Preservation findings

All 203 Node `src/**` and `tests/pool_mining.rs` entries preserve their exact
`1d6a…` modes and blob IDs. Of the original 14 delivered paths, 11 remain exactly
equal. The three subsequently composed paths are the PQ corpus, CI job script
and distributed source inventory. The original runtime-release test command is
still present once; the CI script's new changes are additional commands.

The observed corpus retains every prior required path and pinned path. Its 521
pins all match this observed remote tree; required paths increased from 420 to
440, and pins from 502 to 521. The corpus assertions are unchanged. These are
source-registration observations, not new native, scientific or deployment
acceptance results.

## Prepared Git material and immutable native scope

Imported 229 missing objects (11,494,803 raw bytes) from existing local peer Git
object stores. Each imported object's type/length/raw bytes was hashed before
`git hash-object` and its returned object ID was checked. No peer worktree bytes
were copied. The complete observed tree and its blobs are now locally available;
the original API metadata, verified raw head commit and import list are retained.

There was no checkout, patch application, index write, ref update, native build
or native test. Before/after HEAD, raw index SHA-256 and clean-status observations
are identical. This task did not reread the floating branch after the single
observation.

**Any forthcoming native result is attributed only to fixed `1d6a…`.** The new
remote crypto/data-availability sources and runtime inputs prevent transferring
that result to `cbead…`. Exact Node-file preservation does not establish equality
of its dependency graph's behavior. An evidence-only follow-up should preserve
all observed peer paths and retain these separate source identities; it must not
relabel old receipts as executions of a later publication head.
