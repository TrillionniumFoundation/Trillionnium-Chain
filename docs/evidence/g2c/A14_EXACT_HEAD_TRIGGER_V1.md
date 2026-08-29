# A14 exact-head trusted-runner trigger v1

This evidence-only commit requests exact-head replay of
`G2C_VERIFY_CHALLENGE_V1` after the closed seven-profile registry, exported
crate module, full-target package gate, challenge lifecycle, clean A13 stacking
and machine-readable handoff updates.

It changes no verification-profile activation, subjective-evidence authority,
Order finality, settlement movement, PoCO weight, production, release or
normative-freeze truth.

Required workflow:

```text
TRNM G2C profile registry and challenge v1 gate
```

Only a completed successful run whose `headSha` equals this branch tip is green
evidence. Skipped, stale, queued, in-progress and failed runs are not green.
