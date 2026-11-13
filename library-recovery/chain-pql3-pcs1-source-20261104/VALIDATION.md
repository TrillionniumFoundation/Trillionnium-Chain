# Independent research reproduction — 2026-11-04

Scope: source-only PQL3 reference in this isolated Draft PR; not production Chain admission, FinalUse, old-chain migration, real PQ signing, or consensus performance verification.

Input byte identities (both independently matched original Library SHA-256 and immutable Git Blob):
- `pq_pql2_fork_recovery.py`: SHA-256 `b3b466fdf8f914151282dfc914f884244d2e99632b9be351f69048c5665c955b`
- `test_pq_pql2_fork_recovery.py`: SHA-256 `1f9c21051f20da250376662829dd26d9a81a875cdb05bf6a9717078714f90a94`

Independent sandbox: Python 3.13.5, Linux x86_64, SQLite from standard Python library, temporary test databases, no production service.

```sh
cd library-recovery/chain-pql3-pcs1-source-20261104
python3 -m unittest -v test_pq_pql2_fork_recovery.py
```

Observed: **21 tests, 21 PASS, 0 FAIL**; the suite completed locally. No raw test log is uploaded. PCS1 peer-process tests were only parsed for syntax, not run. GitHub Actions status is not implied. The suite itself states that rollback without an external monotonic anchor remains undetectable. All product security/science/performance gates remain unchanged, and the original Library remains retained.
