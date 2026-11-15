# PQ Root terminal History: affirmative-evidence classification (HOLD)

Base: #884 exact commit `c26807d576bacc02e7e32b5293743f15b568b659` (original 3×30s campaign remains **0/3**); only the diagnostic and its unit tests changed. This is **not** a real service fix or a new native campaign.

## Controlled regression

On authorized Hepta runtime host `ai395`, extracted the exact base Git blobs without changing any shared checkout. Added two negative tests to that **unmodified analyzer**: a claimed clean import with all four terminal stages never entered, and one with successful native stages but outer transport failed. Both were incorrectly labeled `no_terminal_import_failure` (**17 tests, 2 failures**; complete original output in `pre-fix-negative.log`).

Patched to require `status == "ok"`, absent transport/client errors, and explicit `started == completed == accepted == True` for **all four** required terminal stages. Added an additional transport-error negative check. **18/18 Python tests pass** and `py_compile` succeeds (exact log `patched-18-tests.log`).

Unmodified source blobs: `7586a9c5ec306c1111bc3dcfd892352690c9fa0f` and `09a1783682117fdc52cf53c3a4ff63aa562ba52d`.
Published patched Git blobs were compared to the host-tested bytes via `git hash-object`: `9fb5c1e178239955d795e3eae901eb028642f832` and `aacd92c2932d958abcba31e8bc4e9b30926f2884`, respectively. SHA-256 for the patched source files and exact logs appears in `audit.json`.

No new native acceptance execution, no Host checkpoint weakening, no modified workload or budgets, no artificial external evidence, no production permission, and no cryptographic bound. Root remains `HOLD_NO_GO / DENY_ALL`.
