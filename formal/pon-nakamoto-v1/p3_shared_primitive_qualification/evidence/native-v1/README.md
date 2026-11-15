# Native observation bytes

Historical native evidence for the tagged SHA3-512 research profile. The ABBA
manifest records 8 full W1 preparations/proofs/fresh independent verifications.
A is the untouched original packed-carry runner and B is the new tagged profile.
Qualification remains HOLD_NO_GO; this is not a security-bit or QROM proof.

All original logs, phase events, resource reports, source/binary snapshots,
input provenance, failures, prepared statements, complete proof bytes and
mutated negative-control bytes are retained. Binary files are deduplicated by
their uncompressed SHA-256 and stored as deterministic gzip objects. The
file-index.json maps every original relative path to exact retained bytes.
No compiled executable is committed. The final-source-identities file records
the executable hashes and the sole post-ABBA code addition: a controls example.

To restore the original relative layout into a new temporary directory:

    python3 materialize_native_evidence.py --output /absolute/new/directory

Every restored file is checked for its exact byte count and SHA-256. The
resulting input-fixtures directory is self-contained for both retained and
dense cases. Dense source paths in fixture-provenance.json are provenance,
not an instruction to read the unmerged worktree. Only copied input bytes
were reused; the implementations and all proofs/measurements are from this
current worktree.

Raw reports retain historical absolute paths, timestamps and base commit.
They must not be rewritten as evidence of a later exact-commit build.
Rebuilding for a later gate gets a new source and binary identity. Use the
restored abba-v1/00-retained-A and 01-retained-B proofs (or the dense A/B
proofs) with the independent verifier and the native controls example.

Resources were CPUs 0..7 and RAYON_NUM_THREADS=8 on the same host, with
per-stage timeout/resource capture; the host was not exclusively reserved.
The 8 benchmark rounds all passed; controls add 56 Rust tests (45 retained
plus 11 new), 31 independent Python SHA3 reference vectors, 71 structural
controls and 11 complete-verifier controls. These are finite regression
observations, not universal input/security/rejection-cost guarantees.
