# Five-claim composition: selected-source lifetime survey

This successor binds the existing twenty selected source paths to implementation
commit `f2375a08f4458f842b96d30215adcd5380270f1d`. It records source identity, not execution of a native binary,
cryptographic verification, a lifetime bound, model benefit, or production acceptance.

The 2026-11-09 current report and 2026-11-10 account-boundary report remain
unchanged historical records. This input is byte-identical to the account-boundary
input (SHA-256 `a6e43a5c55e71154592a3489f566995e7961b91611e15d40a18a948a495f9f89`).
All query limits, independent qualification fields, unknown bounds, mathematical
accounting and acceptance refusals retain their prior values.

Only the selected-source base commit and the reviewed store/consensus source
identities, byte counts and anchor locations change. The saved report is formed
from the independently fixed historical report and these exact Git objects.
The retained test separately reconstructs the historical report, then applies
literal reviewed values and compares both this fixture and the actual reader
output in full. Passing that comparison establishes selected-source consistency.

Reproduce from this composed checkout:

```sh
python3 scripts/w1_lifetime_ledger.py --input evidence/pon-w1-lifetime-five-claims-20261111/project-input.json
python3 scripts/ci/test_w1_lifetime_ledger.py
```

The actual native implementation remains full W1 recomputation. This source
survey does not activate a succinct verifier or close work-cost, independent
model benefit, adoption custody, or ordinary FinalUse obligations.
