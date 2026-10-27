# PQL10 — PQ source-completeness fail-closed regression

Status: **research only / HOLD_NO_GO**. Stacked on PQL9 PR #489 at exact commit `8679d86a75b4d5822d89180888bc8c2db4dc64d2`. This does not change PoN W1/PNW1, installed classical signatures, mining, Chainwork, transaction limits, key custody, Hepta Final-use, activation or the installed node.

## Reproduced source-integrity blocker

The PQL9 corpus marked `formal/pon-nakamoto-v1/pqg_native_verify.c` as a REQUIRED path but omitted it from `pinned_blobs`. Git tree object `d052f0cb49b413105cb60d9f752e21c01f3bb2be` exists at the frozen PQL9 commit. The source-integrity checker categorically refuses a required unpinned source. Thus the 95/95 existing hashes were consistent but the 28-required-path gate could not pass.

This patch records the original unchanged PQG1 verifier's exact Git blob, increasing the source set to 96, and adds an enumeration guard for top-level `pq_*`, `pqg_*` and `pql*` C/Python implementations plus PQ-named Rust protocol/crypto sources. New unpinned research implementations now fail before any claim of completeness. Source material is still hashed against exact checked-out bytes; it is not enough to enumerate filenames.

## Observations and limits

- On GitHub's frozen PQL9 tree, 95/95 previously pinned blobs matched; the previously unpinned mandatory C source's object was `d052f0cb49b413105cb60d9f752e21c01f3bb2be`.
- The updated manifest has 96 source pins and covers all 28 mandatory paths; 27 enumerated PQ research implementation files have a pin.
- A separate local isolated Python fixture executed four tests of the new enumeration helper, all passed (positive, missing C pin, added Python/C/Rust entries, symlink directory refusal). **This was not the exact repository unit-test suite**.
- Required exact-tree verification remains `python3 scripts/ci/check_pq_research_integration.py` and `python3 -m unittest -v scripts/ci/test_pq_research_integration.py`, plus all previous crypto, Rust, multi-host and fault campaigns. No complete checkout or Rust toolchain was available in the present working container; these remain **NOT_RUN**, not implicit passes.

The checker still trusts its externally supplied Git checkout and pinned expected SHAs. Same-UID concurrent filesystem replacement, malicious Git refs, a compromised verifier, production consensus, independent PQ key custody, quantum PoN hardness, operator independence, real remote Hepta authority and physical rollback are **not** solved. No activation or independent acceptance flag is promoted.
