# One published pretrained attempt: retained failure

The [actual GitHub run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41951536925)
executed attempt **1** from intent
`6bdaf9598d72c118798eb51a03db2e1c0e7c8507`, whose sole parent is frozen source
`f388f46d9df150a3599b9d961b48918b3ff1fb48`. The campaign is spent. This case
contains its complete bounded observation artifact, the exact published
registration and the retained read-only audits. It contains no model weights.

## Result

The [ledger receipt](artifact/run/trial-checkpoint.json) and actual journal
record **spent 1 / maximum 1 / aborted**. Its three events are reserve-v2,
the first phase observation, and terminal abort. No child receipt was accepted,
no evaluation roster was frozen, and no assessment was produced.

The first `loader-1thread` child loaded the pinned 134,515,008-parameter
SmolLM2 model on CPU, converted the verified BF16 inventory to FP32, and
returned forward/greedy-decode observations for eight public training-fixture
requests. The [child receipt](artifact/run/loader-1thread/actual-receipt.json)
and [predictions](artifact/run/loader-1thread/predictions.json) remain intact.
The audit checks their identities and hashes; it does not independently rerun
the forward, decode or tokenizer or produce a new quality score.

The child returned exit code zero, but its
[supervisor observation](artifact/run/loader-1thread/supervisor.json) failed
with `rss-observation-unavailable`. At the missing sample the process was
running and its RSS fields were absent; the original 50 ms unproved-exit
window did not establish exit. A later zombie/pidfd-ready diagnostic cannot
reconstruct that missing sample. The strict failed result remains unchanged.

| Recorded partial cost | Actual value |
| --- | ---: |
| Supervisor wall | 22.862756740 s |
| Wait4 child CPU | 23.167982000 s |
| Observer CPU | 0.280697550 s |
| Sampled child peak RSS | 1,399,828,480 bytes |
| Wait4 child peak RSS | 1,438,318,592 bytes |

These memory observations are direct-child samples and a wait4 single-process
high-water including inherited waited-descendant accounting, not simultaneous
process-tree peak RSS. The missing sample prevents complete strict supervision.
The remaining eleven phases never started. No candidate training, control
comparison, complete release evaluation, lifecycle economics, accepted no-update,
adoption, reward or deployment conclusion exists.

## Exact retained bytes

- [Original artifact ZIP](artifact.zip): 55,433 bytes, SHA256
  `0890a0ff94f3ba2fc912b45805531c2058f4ca344f538133d863ab74f35ec924`.
- [Collection manifest](artifact/collection.json): 24 allowlisted files,
  zero collector omissions. Together with this manifest and the SQLite
  snapshot, the ZIP contains 26 files totaling 221,532 bytes.
- [Actual SQLite snapshot](artifact/ledger.sqlite3): 36,864 bytes, SHA256
  `c1d19a734b401faf69778f077b9ae2937da89a6c742e41625a087f30b8e48c46`.
- [Published registration](published-registration.json): 100,969 bytes,
  SHA256 `1bce00490405ab6c1e4eee3e2a9d8d45ba96a5efe3e61aa13b5b3f3977e26e1b`.
- [Original pilot log](artifact/original-pilot.log) and
  [abort record](artifact/run/abort.json) retain the failure and its complete
  returned phase observation.

The source and registration preserve the original policy, trial, material
manifest, CPU/four-thread/ten-step strict-v1 experiment and one-attempt budget.
The single-thread loader has its separately bound original subplan. Publication
and actual reservation have both consumed their allowances; a new filename,
host, branch, policy label or workflow attempt does not provide a refund.

## Read-only reproduction

[PORTABLE_REPLAY.md](PORTABLE_REPLAY.md) gives the exact input layout and
parameterized command for [portable_artifact_review.py](portable_artifact_review.py).
Use the frozen source, not the later PR composition. The verifier checks the
609 registered source hashes and four additional fixed configuration inputs,
then loads only the required verified source snapshot. SQLite is replayed from
detached immutable bytes; original evidence is not written or recovered.

[Portable validation](portable-replay-validation.json) records one read-only
execution and 203 successful evidence consistency checks. These are evidence
checks, not model tests or independent evaluator administration. The original
189 checks and substantive findings match the
[earlier complete audit](independent-artifact-review-final.json). The
[first audit parser failure](independent-artifact-review.json) and its
[original script](independent_artifact_review.first_run.py) remain unchanged.
No model library was imported and no experiment was repeated by either audit.

Full acceptance gates remain in [the gate record](../full-acceptance-gates.json)
and [the parent evidence document](../REPRODUCE.md). This aborted public pilot
does not establish independent custody, prospective evaluation, the complete
release, behavioral quarantine/rollback or current-generation FinalUse.
