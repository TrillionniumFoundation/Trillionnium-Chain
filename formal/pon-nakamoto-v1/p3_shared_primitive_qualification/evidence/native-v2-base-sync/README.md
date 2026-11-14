# Native v2 base-sync integration observations

This is a fresh full integration/performance campaign after merging the target
branch into the tagged SHA3 worktree without committing. Historical native-v1
evidence remains immutable. This campaign adds no profile change, pruned-model
extension, security-bit claim or QROM qualification; HOLD_NO_GO remains.

The captured candidate identity is:
HEAD cfef87ff6e09f998cb8fc5d3165fce8ac9eb2da1
MERGE_HEAD 09fbc0f45151a68a1bf205641171840fbf309882
index tree 26785a22b3118c718f71c1774dc1c1961db410e9

merge-source-before.json and merge-source-after.json also record the actual
crate source digests and tracked diff. They matched after the entire campaign.
These are candidate observations, not claims of a later exact-commit gate.

The 8 fresh full W1 prepare/prove/fresh independent verify chains ran ABBA for
each of retained and dense inputs. All passed. Rebuilt A/B/wire executables
were hashed and remained unchanged. Rust 1.95, CPUs 0..7, Rayon 8, no extra
Rust flags, same target directory and per-stage resource recording were used.
The host was not exclusive. All 68 release tests, strict release all-targets
all-features Clippy, 71 actual-file structural controls and 11 complete
verifier controls passed. The 31 independent SHA3 vectors remain in the tests.

All raw logs, source snapshots, phase records, resource output, source input
provenance, prepared statements, full proofs and negative-control bytes are
retained. Binary files are stored by uncompressed SHA-256 as deterministic
gzip objects. A byte-identical object can also exist in native-v1; it is
retained here independently, while Git may deduplicate identical blobs.
Only v1 input bytes were reused to run the campaign. Every v2 proof and
measurement was freshly generated. Payload comparison reports equality as
a regression fact, without importing historical timing results.

To restore the complete original observation layout into a new directory:

    python3 materialize_native_evidence.py --output /absolute/new/directory

file-index.json and the materializer validate every byte count and SHA-256.
The restored input-fixtures directory contains both complete input cases;
the abba-v2 and receive-controls-v2 directories retain their raw observations.
Historical absolute paths and candidate IDs in logs are intentionally retained.

## Driver measurement-state scope

The retained v2 run_tagged_sha3_abba.py deliberately reads MERGE_HEAD and
records git write-tree. Its source_snapshot also serves the adjacent historical
receiver script. These exact drivers describe the measured uncommitted merge
state and are preserved unchanged. After the merge is committed, MERGE_HEAD
no longer exists; use the unchanged native-v1 receiver/helper for a new final
commit replay, pointing --benchmark at the materialized abba-v2 and using the
newly rebuilt binaries. Record that replay with its own commit and binary
identities. Do not relabel or rewrite these historical v2 driver observations.
