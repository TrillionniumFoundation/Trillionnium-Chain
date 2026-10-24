# Four-priority audit: source-bound local observations

Measured published source: `3c63c8368187de895e1dc0df8bbc105c6f39f842`;
Git tree: `54d2f12c0d783f827d43bc626489f58ab75d7c31`.
This additive package retains observations from that source, not a claim that a later
packaging commit was itself measured. Each collection records clean source before and
after execution, source-input hashes, exact commands, environment and binary identity.
All observations came from the same operator on a controlled cloud CPU host.

These are historical, exact-source observations relative to the subsequent
CodeQL-driven test/helper naming edits. Those edits change the full measured-source
inventory even though they do not change production work primitives or wire behavior.
This package claims no new execution or whole-current-input match after those edits.
Original verification receipts describe the source at their recorded verification time;
their true-at-collection scope is preserved rather than rewritten as later-head proof.

## Retained results

- [Work cost packet](work-cost/README.md): 32 original observations and 64 paired
  prepared-cost observations, with every raw sample and original manifest unchanged.
  Paired samples span four classes, two targets and eight samples each; only the
  common development target enters the diagnosis. The proposed local diagnostic
  exits **2 (`not-accepted`)**, as expected, rather than passing the work-security gate.
  Every class fails the marginal invalid rejection/construction screen; modeled
  setup amortization is explicitly separate from executed multi-winner experiments.
- [Preview manifest](preview/manifest.json) and [raw samples](preview/samples.json):
  the warm component median falls from **82.383 ms to 45.024 ms (1.830×)**.
  The cold arm is separate: **3334.341 ms to 247.254 ms (13.486×)**.
  Four rotating arms retain eight samples per arm. The workload is 16 complete
  signed M06 transfer prefixes with commitments over 4,099 state keys, including
  4,096 inert synthetic padding entries. It excludes M05, SQLite, Node lock wait
  and concurrency; this is neither native-transaction-generated large-state
  evidence nor end-to-end TPS or physical memory/VRAM qualification.

Honest-service behavior, public ingress/hostile traffic, physical VRAM and independent
operators remain unmeasured. No positive model-efficacy result is supplied here.
No production, public-network, hardness, model or release acceptance is promoted.
The work diagnostic's `fresh_measurement:false` describes its summarization step;
its separately retained execution receipts establish the fresh input collection.

## Verification and limits

[manifest.json](manifest.json) SHA-256 binds every other package file, including all
nested original manifests; it intentionally excludes itself. Nested collector and
benchmark manifests remain unchanged. Their machine-local execution paths are
provenance, not relocatable output destinations. Packaging itself modifies no code,
configuration, runtime, tests or earlier evidence. Subsequent test/helper renaming
is a separate source change and does not update these measured identities.

From the repository root:

```sh
python3 scripts/pon_work_cost_report.py --verify evidence/pon-four-priority-audit-v1/work-cost --historical
```

This verifies retained bytes against the original measured source without rerunning
the experiment or asserting applicability to every input of a later head. A new
current-source measurement needs its own clean source and fresh execution receipts.

Hosted validation is separate: [the measured-source CI run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/36954322521)
is not a completed acceptance receipt in this package; this document asserts no
all-pass result. CodeQL triage identified public transaction-sequence helper arguments
labelled `nonce` as cryptographic-nonce false positives; subsequent helper naming
clarifications do not establish a new benchmark run or bypass cryptographic checks.
A local full Rust run was blocked by Unix-socket `EPERM`, including the escalated
attempt. Tests were not removed to bypass that blocker. Focused local checks,
strict Clippy and documentation checks do not substitute for full exact-head CI;
that status must be retrieved for the actual published head and prospective merge.
