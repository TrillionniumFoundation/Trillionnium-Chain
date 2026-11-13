# Library source custody — PQL3 and PCS1 (research, HOLD_NO_GO)

This isolated archive preserves four original text files identified in ChatGPT Library, without modifying production modules. It is not a consensus implementation, safety proof, activation approval, or deployable Chain patch. The original source files were independently SHA-256 and Git Blob checked from Library, then checked again from GitHub's exact Git blob API. The Git blobs were already present in the repository object store, but not counted as durably published until this branch commit and Draft PR are read back.

| Exact Library original | Archive path | Bytes | SHA-256 | Git Blob |
| --- | --- | ---: | --- | --- |
| `pq-cell-swarm-tests-final.py` | `pq-cell-swarm-tests-final.py` | 11981 | `f8f9302abb214c97876c7b3b05c6ab4137fecd936e087fe805dc3d3c4f716c9a` | `86f056ef41f7754c1eee2b15ae03f0542dcd7110` |
| `pql3-research-python-source.md` | `pq_pql2_fork_recovery.py` | 17785 | `b3b466fdf8f914151282dfc914f884244d2e99632b9be351f69048c5665c955b` | `746033850d362eeda5830c74b491bb8d9144d1a7` |
| `pql3-research-python-tests.md` | `test_pq_pql2_fork_recovery.py` | 16134 | `1f9c21051f20da250376662829dd26d9a81a875cdb05bf6a9717078714f90a94` | `5294e584265d2f0b7e2c390618872f8fe9bd626a` |
| `pql3-documentation-transfer.md` | `pql3-documentation-transfer.md` | 6189 | `9fe3e63be5e904ae0b5006ffe123d6381b9175615c1e3f37e31dcdca902c3094` | `ea33515144baa609a02c200e8be8979c7ef16fbb` |

Original bytes are kept unchanged. The two `.md` files above contain literal Python source and tests (not fenced Markdown), and are archived with `.py` paths so they can be checked and run without transformation. `ast.parse` succeeded for all three Python files. Regex screening of each of the four text originals found no email addresses, Gmail authors, home-directory paths, known key prefixes, or private-key PEM markers. This is a targeted screening, not a complete secret-detection guarantee.

For independent PQL3 testing in an isolated, non-production environment, from this directory:

```sh
python3 -m unittest -v test_pq_pql2_fork_recovery.py
```

The PCS1 peer-process test may need native signing/runtime prerequisites and local loopback ports; it is preserved verbatim, not run as a production or consensus service here. Tests alone cannot establish PQ signature admission, fork-choice safety, old nonce/liability migration, four-second confirmation, or full operational correctness. Recheck current upstream PRs and dependencies before any adoption.

This archive does not change main, grant FinalUse, relax any safety gate, or justify ChatGPT Library deletion. Missing archive members and the original dot worktrees remain OPEN; the present four objects must not be counted as published until the branch and Draft PR Git tree, HEAD and per-path blobs have been read back.
