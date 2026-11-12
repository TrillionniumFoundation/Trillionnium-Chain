# AI395 incentive execution on frozen bac6 — HOLD

The fresh AI395 component campaign completed **31 Rust tests**, followed by
**8 pure Python oracle tests, 5 native differential tests, an independent split
receipt check and 6 rejecting receipt mutations** in the repository-pinned
scientific environment. The split reward counterexample remains observable.
Economic and production acceptance remain false.

## Source, run and original evidence

- Tested commit: bac6b7659bd7e2d633e25c2da0add60f6a10c7fb.
- Tested tree: 371c3f55de7940e276496efe2008b537ba4d8268.
- One native run ID:
  incentive-bac6b7659bd7e2d633e25c2da0add60f6a10c7fb-20261112-v1.
- Full source observations: 28,327 tracked files and 2,578,801,275 bytes.
  Native before/after lists agree exactly, including Git blobs and file modes.
  The later pinned-Python observation independently agrees on each path, size
  and SHA-256. Missing and mismatched file counts are zero.
- Native campaign: 2026-11-12 01:33:22–01:38:38 UTC.
- [Original archive](incentive-bac6b7659bd7-raw-20261112.tar.xz):
  1,882,840 bytes, 109 regular members, 28,288,909 uncompressed artifact bytes;
  SHA-256 3d543e24395320c860d342f396ad492baa76365128be1ee91a296ffc23ca09c9.
- [Archive identity and recovery provenance](manifest.json),
  [all member identities](archive-manifest.json),
  [13 native observation identities](native-observations.json),
  [original export result](export-result.json), and
  [version-pinned transfer observations](transfer-receipt.json).

This is an evidence publication for that exact source. It does not transfer
native qualification to its publication commit, a later integration head, main,
a different feature set or a running network. The
[earlier 70-file record](../../../chain-incentive-counterexamples-20261112/README.md)
remains unchanged, including its original warnings, failures and unknown runs.

## Actual commands and counts

The absolute Cargo and RUSTC executables came from Rust 1.95.0 under
/home/qq/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/.
CARGO_HOME was /home/qq/.cargo. All native commands shared the task's
trillionnium/target directory, used package default features, and retained the
Cargo test/dev profiles. No ambient Rust flag, compiler wrapper, cross target
or debug-profile override was present.

Every native command used --locked --manifest-path trillionnium/Cargo.toml
-j 2 and ended with -- --nocapture. Original argv, stdout/stderr, clean source
observations, duration and exit receipts are in the archive.

| Package and selection | Actual results | Exit |
| --- | ---: | ---: |
| trnm-mvcc-fee: evaluation_quorum_v2 + model_evolution_v5 integration tests | 9 + 4 | 0 |
| trnm-mvcc-fee: library model_composition_v4:: selection | 5 | 0 |
| trnm-pon-node: public_evaluation + model_composition_v4 integration tests | 8 + 5 | 0 |

Preflight and locked Cargo metadata also exited 0. The public-evaluation suite
includes the strengthened complete-roster test's 144 commit-order/reveal-order/
worker combinations and 12 missing-evaluator cases. Those are subcases, not
156 additional tests. The five-test V4 Node suite includes the split
counterexample.

The native run produced exactly **13 distinct V4 files**: one collection of
42 arithmetic cases, nine releases and three claims. All identify the same
native run. Both input inventories and the original hashes of all 13 files
agree across the pinned Python phase.

The unchanged formal/pon-nakamoto-v1/requirements.txt pins NumPy **1.26.4** and
cryptography **50.0.2**. An isolated Python **3.12.16** environment was installed
from those bytes. The installation report, freeze, imported versions and pip
check are retained. In that environment:

| Entry point | Actual result | Exit |
| --- | ---: | ---: |
| test_model_composition_oracle.py -v | 8 pure tests | 0 |
| test_model_composition.py -v | 5 differential tests over the same 13 inputs | 0 |
| verify_incentive_split_receipt.py | Counterexample reproduced; 46 signed envelopes checked | 0 |
| check_receipt_mutations.py | 6 unique mutations rejected | 0 |

Earlier system Python 3.14.4 / cryptography 46.0.5 observations are retained
separately. **They do not qualify the pinned scientific dependency gate.**
Preparing the pinned environment did not repeat native execution or change
the run ID. This subset does not claim the entire protocol-contract CI lane.

## Split counterexample and limits

The split test uses ordinary Node::open to initialize genesis, then executes
contiguous signed M06 commands. It observes admission, truthful complete-roster
commit/reveal, authorized funded publication and actual claims. It does not
establish ordinary Node transaction submission, PNW1 chain verification or
independent History confirmation for this split sequence; all three flags
remain false.

The same complete model can be represented as (A, B) or (A+Z, -Z, B).
The two aliases are explicitly known to share a source. Full model bytes and
artifact identity are unchanged, while the known source's actual ledger increase
changes:

| Observation | Original | Split |
| --- | ---: | ---: |
| Known-source gross claims | 66,666 | 96,551 |
| All charged own-account transaction fees | 6,615 | 9,686 |
| Actual combined account increase | 60,051 | 86,865 |
| Total claims | 99,999 | 99,999 |
| Unclaimed budget dust | 1 | 1 |

The difference is **+26,814 development ledger units after the recorded fees**.
The known source uses two intakes within the unchanged four-intake limit and
reserves 96,551 units within the unchanged 100,000-unit cap. Thus the observation
does not claim a source-cap bypass. It requires the public 25-row material,
two admitted keys, the other contributor, truthful full-roster evaluators and
an authorized funding publisher. Real-world acquisition, training and serving
costs were not measured. Unknown common control, public reward eligibility,
generalization, Shapley fairness and economic security remain unqualified.

The 25-row saturation statement belongs to this V4 fixture. It is not asserted
as a ceiling for later owner-pinned task-window profiles, including V5.
The test preserves the existing reward rule; it does not implement a source
grouping fix or turn the counterexample into a defense success.

The fresh compact native split JSON is 195,038 bytes with SHA-256
2a790986b2106b288f1e0343f7b25b2391702dbb5a75b313b951c1ab04fc71fd.
Its parsed JSON equals the earlier 819-source receipt, whose pretty-printed
serialization is 199,212 bytes with SHA-256
07c11a04880eab6303a66000d23082748a8f8568f8e1defe92d91c0a8b30db40.
The two execution sources and byte identities remain separate.

Signature, complete-model, claim, source-reservation, account-balance and
missing-reveal transcript mutations are rejected. This missing-reveal mutation
is rejected for nonce continuity; that one control does not prove every
missing-reveal rule.

## Independent artifact verification and preserved failure

The standard-library [archive reader](verify_archive.py) verifies the full SHA,
all member identities, unique safe regular paths, three full source observations,
actual test counts, command exits and source identities, pinned dependency
versions, 13 unique native inputs, split scope/arithmetic, six mutation results
and three complete PTY byte streams. It extracts no files and does not rerun
signatures, model evaluation, Rust or the chain.

From the repository root:

    python3 evidence/chain-system-security-20261111-306929/ai395/incentives/verify_archive.py

The recorded [verification output](independent-verification.json) additionally
compares the retained earlier native split receipt using --previous-receipt.
Its original cloud run exited 0 in 2.2772595019996515 seconds; the output was
11,398 bytes with SHA-256
941ef2ae5a34433b0ba72b0b8839ad16d2d414a997e27fae54fb712f731079a2.

The [first reader](verify_archive-first.py) assumed account-delta fields were
JSON numbers, but the native receipt serializes canonical decimal strings.
It reached that check and exited 1 with a TypeError.
The [original stderr](verification-first.stderr.log) is preserved exactly.
The correction validates and parses that existing representation; it changes no
native source, receipt, reward rule, threshold or scientific comparison.

## Recovery provenance after cloud execution disconnected

This README and the outer manifest were **newly reconstructed** after the cloud
environment disconnected before any commit identity was confirmed. They do not
claim the original uncommitted README/manifest hashes.

The original remote raw archive was copied without regeneration. Its previously
verified SHA and all original member hashes are retained. Both reader sources
were recovered from complete tool inputs and match their earlier exact hashes:

- First reader: 16,735 bytes, SHA-256
  c64eef24c59b8fdc06b2610175be8b294f90821ce197838816803f5cac99886e.
- Corrected reader: 17,050 bytes, SHA-256
  8a026362dc8045eb7f528231fd4cecee5fb5e2a47390714136587e75fc728331.
- Original first stderr: 566 bytes, SHA-256
  c7ec57fa353bf2ea166fb9109e863191480443210177d9767cbcacf1866b4c46.

The two original cloud command receipts were reconstructed from the complete
fields printed by their actual tool returns. Their individual original file
hashes had not been retained, and are not claimed. They describe the original
cloud executions, not a new execution on AI395. The transfer receipt was
reconstructed from its preserved structured controller payload.

A separate AI395 archive-only recheck uses the recovered corrected reader.
Its [new execution receipt](recovery-recheck.receipt.json) records that new
process; it is not counted as another native test or Python scientific method.
The generated verification JSON must match the original 11,398-byte output SHA.
[Per-file recovery provenance](recovery-manifest.json) distinguishes hash-matched
original bytes, deterministic reproduction and newly reconstructed metadata.

The three scientific/native execution PTYs each have authoritative exit 0,
complete capture and no capture error. Initial acknowledgement/read timeouts
and their same-operation reconciliation remain in the archive. Transfer pins
one remote version and verifies every range and the full hash. A missing
acknowledgement did not authorize a second native run.

The archive omits installed environments, Python caches and native ELF files.
Executable hashes in it are post-execution observations, not pre-execution
binary attestations. **HOLD remains in force**: no activation, reward-rule
alteration or whole-chain security acceptance follows.
