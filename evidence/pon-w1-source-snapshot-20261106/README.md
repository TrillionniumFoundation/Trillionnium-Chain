# W1 source snapshots and saved-record reconciliation — 2026-11-06

## Outcome and scope

This continuation starts from
`d9fd07c473998bd236207c1b7db4233f0eafd7fe` and repairs two evidence-integrity
boundaries: the source mapper's hash/parse snapshot and the saved-v2 CI report
reader's reconciliation of actual retained records. It does not change a
cryptographic verifier, generate a proof, alter an admission rule, or qualify
W1 or the whole chain as PQ-128.

The previous real-positive-control repair has executed in the original CI.
It is not reopened as an outstanding always-reject vulnerability. The ordinary
Node consensus path remains the complete native PNW1 verifier; the retained
RISC Zero Succinct experiments are not Groth16 wrappers. The
[full STARK review](../../docs/security/W1_STARK_REVIEW_20261106.md) and
[whole-chain claim guard](../../docs/security/WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md)
retain the full-relation, hash-purpose, Fiat–Shamir, QROM, quantum-work and
system-admission obligations. The RISC Zero
[security model](https://dev.risczero.com/api/security-model)'s native/recursive
96/99-bit estimates are not a common W1 or chain-wide quantum security level.

## Source-map snapshot repair

Previously, `inspect_package` hashed a crate archive and reopened the same path
to parse it. A deterministic replacement after hashing, together with matching
replacement extracted source, made the mapper accept different source bytes
while reporting the original locked archive checksum. Related split reads
could pair a source digest with a later size, or pair parsed lockfile,
historical-log or manifest content with a later digest.

The mapper now reads bounded byte snapshots and hashes and parses those same
bytes. Crate archives are bounded at 16 MiB, selected files at 2 MiB and JSON
provenance at 64 KiB. The existing source reread still hashes the bytes it
decodes and refuses changes; that already-correct boundary is not a new defect.

The [independent red/green replay](w1_source_snapshot_red_green.json) retains
both implementations' actual outcomes. The old mapper accepts the
archive-plus-source substitution; the repaired mapper rejects it. A replacement
of the archive path alone leaves the new mapper's already-read original bytes
valid. Unchanged inputs continue to pass. Lockfile, provenance and size/hash
records now describe the same read. The repository test suite retains its
original seven controls and adds eight deterministic controls, for **15** total.

This is an evidence-provenance defect, not a demonstrated forged STARK or Node
bypass. The existing exact source-map comparison provides an additional
boundary, so this isolated reproduction does not establish a green whole-job
CI bypass.

## Saved-v2 report reconciliation

The old inline CI validator could accept an outer rejection while its nested
process record said success, an outer success while its process said failure,
a nested timeout, truncated verifier-output scans, or incomplete process
observation. These contradictions were reproduced against real retained
reports, not invented all-success proof records.

The [new gate](../../scripts/ci/w1_v2_controls_gate.py) checks the original
ordered **58** controls, unchanged declared **120-second** budget, aggregate
elapsed time and recorded completion flags against:

- The aggregate report, individual case result and individual process result.
- The exact verifier identity, original and mutated input bytes, mutation
  manifest, and recorded command paths.
- The actual stdout/stderr bytes and hashes, rejection layer and required
  rejection text, and the accepted receipt's actual stdout.
- Completion, return codes, timeout and output-scan status, session observation,
  cleanup, and absence of every recorded process group, including the child PID.

The existing **three named v2 Rust tests**, actual positive proof, original
57 negative controls, input mutations and rejection expectations are retained.
The new Python gate has **23** durable tests. Its independent real-CI replay
contains **19** inconsistent-record cases accepted by the old gate and rejected
by the new gate, plus three accepted cases: the unmodified actual report,
a legitimate `/proc` disappearance race, and truncated resource sampling with
complete verifier-output scans. The separately retained
`controls-3-repaired.tar.xz` positive observation also passes.

A clean expected rejection has `stage_process_complete=false` and a nonzero
exit; it is a successful negative control. A `proc_disappearance_races` entry
is not a process-scan error. Resource `sample_log_truncated` is not verifier
stdout/stderr truncation, and this gate does not certify resource measurement
completeness. The independent review's first, overstrict resource-sampling
expectation and the intermediate PID/group gap reproduction are retained
alongside the corrected final result.

These checks establish internal consistency of retained evidence, not an
independent attestation that historical execution occurred. Offline replay
explicitly uses the historical recorded paths; it does not rewrite them into
new execution claims or launch the historical verifier.

## Real locked-cache replay

[security-map.json](security-map.json) was generated by the repaired mapper
against **seven actual locked crate archives and 37 selected files**, using
four copied, hash-checked historical inputs and an existing local Cargo cache.
All copied input/script hashes were checked before and after. Every non-generator
field equals the earlier dated snapshot; only the generator digest changes.
The original source maps remain unchanged.

| Object | SHA-256 |
| --- | --- |
| Repaired mapper | `324dc1726fc5bfcfd79e5d78d890737bfdd3c5877d74e417d2ed8018254523b0` |
| New source map | `119f0a70d4b98a1ba39b185c6d214e9a1c8219be63784034f1986cbf686bd5d1` |
| Saved-v2 report gate | `49ef8c18ac19a3cce763d24aa3743ea11586b0cce3bd36ffd9390d450a7b175a` |

[The first remote replay record](remote-replay-first-attempt.json) preserves
the successful mapper command and a separate optional budget-calculator
invocation that exited 2 because the required target-bits argument was omitted.
The corrected optional invocation has an
[unresolved launch observation](optional-budget-launch.json): no remote job
directory or intended output was found, and reconciliation with the same
idempotency key retained `launch_unknown`. No replacement job was started
under a new key. The optional budget replay is **not** reported as passed.

The successful mapper replay has a narrower scope than a full repository
build. It does not compile a verifier or add an independent proof trial.

## Original exact-source CI readback

The original
[transparent-profile run 42239570130](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42239570130)
succeeded on both the `d9fd07c` head and its then-prospective merge. Head job
`127965973405` retains the three named v2 Rust tests and all 58 actual receipt
controls. Its verifier SHA-256 is
`2db9669a1c9196885da8908bcaf3da8ccea9684a3fe048fbe2f614cbb093d4ba`.

[original-ci-readback.json](original-ci-readback.json) records the source,
artifact ID, ZIP SHA-256 and exact selected-member hashes. The selected raw
records live in `original-ci/`; `v2-controls/result.json.gz` and
`v2-tests.log.gz` are lossless, deterministic compressions of the original
result and test log, not edited reports. Decompressed member hashes are
recorded in the readback JSON.

This success is scoped to the original source. The
[original workflow inventory](original-ci-workflows.json) records five
successful and six failed runs. The [job readbacks](original-ci-jobs.json)
retain the corresponding failed or cancelled stages. Required baseline runtime shards were
cancelled, and the original native fresh-challenge/public-service campaign
failed. They are not relabeled as successful because the transparent-profile
workflow passed. New combined-source CI must be judged on its own commit.

## Reproduction

The [local validation record](validation/source-ci/validation-commands.json)
binds each command, exit code and retained log to the tested source bytes.
All **128 W1 Python tests** passed. Workflow-contract replay also passed:
14 embedded Python blocks compiled, Bash syntax was valid, both fixed test
rosters rejected seven altered-log cases each, and each of the 19 required
steps was independently rejected when marked skipped. These were local
uncommitted-worktree observations; they are not substituted for future
combined-commit GitHub CI.

From the repository root, the retained Python controls require no prover:

```bash
python3 -m unittest discover -s scripts/ci -p 'test_w1_profile_source_map.py' -v
python3 -m unittest discover -s scripts/ci -p 'test_w1_v2_controls_gate.py' -v
python3 evidence/pon-w1-source-snapshot-20261106/verify_w1_source_snapshot.py --repo . --out /tmp/w1-snapshot-audit.json
```

The independent v2 report replay requires the complete extracted original CI
artifact. Its explicit artifact path preserves the separation between actual
retained records and the smaller selected-member readback in this directory.

```bash
python3 evidence/pon-w1-source-snapshot-20261106/verify_w1_v2_controls_gate.py --repo . --artifact /path/to/extracted-original-ci --out /tmp/w1-v2-record-audit.json
```

The [final independent replay](w1_v2_controls_gate_independent.json) and
[portable-script replay](w1_v2_controls_gate_portable_replay.json) retain the
individual results. Output paths in both independent scripts must be new;
historical evidence is never overwritten.

The workflow fixes the 15 mapper-test names and 23 report-gate-test names,
requires each exactly once with an ordinary `ok` result, and includes all
**19** named stages in final outcome checking. Skips, missing or duplicated
controls, expected failures, and failed required stages cannot satisfy that
finalizer. The source-map byte comparison uses the new snapshot above.

## Combined-source validation

The [combined validation index](combined/index.json) preserves the exact
local source commit, its GitHub publication with the identical tree, commands,
raw observations, and lossless archives of the complete logs. On tree
`15def345d2d033d9b57323d89ae6c5993c868fc3`, all **335 Python tests** passed:
128 W1, 43 source-integrity, 104 CI-contract, 38 PQ-integration and 22
whole-chain claim-guard tests. Repository validation passed with 3,585 local
links, and the claim guard retained HOLD. These counts do not add the 15
mapper or 23 report-gate controls a second time.

All four Rust manifest format checks passed. The native-cost crate's locked,
offline dependency graph resolved all 69 packages and 69 nodes. Both workspace
graph attempts (default and all features) exited 101 because the selected
offline cache lacks the newly locked `nix 0.30.1`; the original lock and raw
errors are retained. No partial graph or different crate version substitutes
for that missing result. Fresh Rust compilation, retained Rust execution and
strict Clippy remain pending exact-source CI.

The workspace format command's stderr reports rustup channel synchronization,
component downloads and automatic installation of the selected toolchain.
Cargo offline mode does not establish that rustup was offline; network
requests were not independently traced. The raw stderr and an additive
toolchain observation are retained without rewriting earlier records.

## Remaining claim boundary

The [source composition record](source-composition.json) preserves integration
head `840522d0b65b4989f1a2a1d09c0ad51af1a1956d`, including its 97 commits
after the common base. Only two text conflicts required reconciliation: the
corpus keeps all integration entries and the new W1 workflow pin (688 pins,
607 required paths), and the plan keeps both appended histories. W1 source
files had no concurrent content conflict. This composition does not transfer
older execution results to the combined source or qualify the integration
branch's other native changes.

All production, consensus-admission and quantum-soundness qualification flags
remain false. The repair supplies no new numerical W1 soundness bound, no
instantiated QROM theorem, no quantum work-cost qualification, no external
cryptographic signoff and no whole-chain PQ-128 claim. System-level required CI
and independent review remain separate acceptance gates.
