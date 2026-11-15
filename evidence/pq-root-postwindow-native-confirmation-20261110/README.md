# Original PQ Root 30 s campaign: reported native confirmation after deadline (HOLD)

Scope: the existing **read-only** original-campaign failure inspector, stacked on Draft #886 exact `80f4b50b1a2933aac37d016bd86ff8c76d3e50fe`.

A fresh readback of #887's native Actions 42897622391, artifact 13800988598, ZIP SHA-256 `033ed670b3d930ea7bf76ad90b6917954b0bf89c6e05c0159b8216dd9e37b9ef`, verifies 1,765/1,765 payload members and three runner-to-report digests. It finds **0/3 successful original campaigns, 0/9 successful phases**. There are 8/9 terminal `PUBLIC_REQUEST_DEADLINE` imports, but run 2 from-zero had no failed import: it reported native depth-six `confirmed=true` at **30.192354 s** after the exact original 30 s window, and remains a failure. Other phases had six reported in-window confirmations. The source report at #887 is distinct from this audit code change at #886.

This PR adds a *diagnostic-only* count/list of qualifying **reported** native confirmations whose ended time is after the original deadline. Unknown/inconsistent timestamps remain unknown or conflict; they never qualify. A native report value is not independently reverified cryptographic evidence. No original protocol, native workload, permission, CPU/RAM/swap/PID cap, 30-second window, or gate changes.

Host `ai395` frozen #886 checkout: before exact source SHA-256 recorded in `validation.json`, Python native-diagnostic tests expanded from 18 to **20/20 PASS**, py_compile PASS, git diff --check PASS. No original fixed-Host campaign was run here; host lacks `/sys/fs/cgroup/trnmponpublic.slice`.

**HOLD_NO_GO / DENY_ALL**. Missing independent custody, non-co-restored fresh lower bound, real M15/FinalUse provider/funds/reorg reconciliation, versioned secure migration and whole-life eight-domain PQ actual bound. `actual_lifetime_failure_bound=null`, `production_activation=false`.

Primary source: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42897622391
