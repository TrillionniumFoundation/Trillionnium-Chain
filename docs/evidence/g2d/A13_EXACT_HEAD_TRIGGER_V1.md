# A13 exact-head trusted-runner trigger v1

This evidence-only commit requests exact-head replay of
`G2D_EXECUTION_MVCC_FEE_V1` after the bounded Rust worker-pool, full-target
package gate, clean upstream stacking and machine-readable handoff updates.

It changes no protocol authority, application JMT authority, settlement
movement, production, activation, release or normative-freeze truth.

Required workflow:

```text
TRNM G2D deterministic execution MVCC fee v1 gate
```

Only a completed successful run whose `headSha` equals this branch tip is green
evidence. Skipped, stale, queued, in-progress and failed runs are not green.
