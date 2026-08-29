# A07 exact-head trusted-runner trigger v1

This evidence-only commit requests exact-head replay of the
`G1_R5_NATIVE_NETWORK_CAMPAIGN_V1` v2 tooling after clean A06 stacking,
checked-in regenerated 4/7-validator fixtures, topology/workload/fault identity
binding and machine-readable handoff updates.

It does not authorize a validator campaign and changes no G1-R5 exit,
production, activation, release or normative-freeze truth.

Required workflow:

```text
TRNM G1-R5 native network campaign v2 gate
```

Only a completed successful run whose `headSha` equals this branch tip is green
evidence. Skipped, stale, queued, in-progress and failed runs are not green.
