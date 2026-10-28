# Actual parent V4 task diagnostic: completed comparison, zero relative gain

The real SmolLM2-135M candidate trained from the pinned existing parent,
completed the frozen six-arm public comparison, traversed a bounded Cell
producer/consumer path, and executed another inference from the fetched
candidate bytes. The candidate tied the strongest controls. The prespecified
decision is **`nonpositive-gain-no-installation`**. This evidence does not close
the requested ordinary Hepta upgraded-child installation loop.

## Source and execution boundary

The executed source is `c86cabce381ff24f0e002693eb46d9b7a49e1690`, tree
`41ed261e8ff9c8fc490711214d2e11e2e7459f3d`, on
`9035171271e9f437b7224b53532f41a2b2894be7` (the original V3 objective source).
The [compressed source patch](source.patch.gz), frozen source hashes, original parent
descriptor, command records and raw results are retained. This is a separate
research continuation, not a replacement for the later V5 observer fix.

The new V4 namespace combines the existing V3 weighted answer/EOS objective
with the existing V2 exact task-admission link. Both preflight and the actual
loaded-model check require task admission to be the only contract difference.
V3 remains strict. Old receipt names cannot borrow V4 permissions. The original
training, tensor loading, byte export, resource limits and terminal wait/reap
owners remain in use. No missing RSS observation, failed child or unresolved
owned reap is converted into success by the new path.

The source parent is the real canonical generation-one zero-adapter material,
descriptor SHA-256
`b8d167dc6bf3c0b784167cd3862321330f9c8dcfdb84032f3f07d85f9fc3123b`.
It is explicitly a controlled fixed initial material, **not an admitted
CURRENT**. The actual candidate receipt verifies the original adapter readback,
the separate initial setup, and changed trained tensors. The source parent
descriptor and all frozen executable source hashes were unchanged at terminal.

Applying the V5 source to that same material is a separately retained negative:
the original verifier finds differences in `numeric/operator_contract`,
`tokenizer/behavior_contract` and `registration/target_admission`. The V4
admission-only link does not authorize that migration. This negative checked
real material and contract bytes but did not execute the 135M model under V5.

## Frozen public comparison

One prespecified candidate used seed 7, rank 4, alpha 8, ten AdamW steps and
learning rate 0.001. Each example assigned half the loss to its answer token
and one sixth to each of three EOS tokens. Actual receipts measured 526 input
tokens and forty positive-weight supervised positions. All four original
controls ran unchanged, followed by an actual reload/evaluation of the source
parent. The three trained arms matched steps and token counts; their compute
costs were measured independently.

All four calibration and four evaluation examples are public fixtures. Scores
are exact output-byte matches, averaged within each of two source groups and
then across groups. No case folding, answer extraction or new scoring rule was
introduced after observing predictions.

| Arm | Calibration | Evaluation | Training steps |
| --- | ---: | ---: | ---: |
| Existing-parent V4 candidate | 1/2 | 1/2 | 10 |
| Original current-backbone control | 0 | 0 | 0 |
| Original fresh budget-matched LoRA | 1/2 | 1/2 | 10 |
| Original budget-matched full tune | 1/2 | 1/2 | 10 |
| Original randomized rank-matched LoRA | 0 | 0 | 0 |
| Actual source-parent reload | 0 | 0 | 0 |

The candidate answered `yes` to all four evaluation prompts. That matches two
of four targets, including one in each source group. Fresh LoRA and full tune
produce the same evaluation score. The gain over the strongest control is
exactly **0**; the gain over the untrained source parent is **1/2**. The latter
does not establish useful neural reasoning or an independent quality gain.
The decision rule and six-arm roster were frozen before candidate execution.

## Actual costs and terminal observations

All eighteen required child stages ended successfully, with exit code zero,
resolved owned-child reap and the original `wait4` accounting. Their summed
observed child-stage wall time is 716.278496524 seconds; summed child CPU is
886.910930 seconds. These sums exclude orchestration gaps and the separate
Cell experiment. The full phase roster is in [summary.json](summary.json).

| Operation | Wall seconds | Child CPU seconds | `wait4` peak RSS bytes |
| --- | ---: | ---: | ---: |
| Train candidate from original parent | 91.586191 | 101.436077 | 3,068,059,648 |
| Evaluate candidate, eight requests | 47.488048 | 72.774683 | 1,154,572,288 |
| Train original fresh LoRA | 66.142450 | 74.007560 | 3,062,505,472 |
| Evaluate original fresh LoRA | 112.650186 | 131.420969 | 1,157,558,272 |
| Train original full tune | 88.537919 | 110.860443 | 6,080,528,384 |
| Evaluate original full tune | 40.295025 | 57.600012 | 1,544,146,944 |

Supported profiler operator FLOPs for candidate/fresh-LoRA/full-tune training
were respectively 289,144,352,528 / 289,144,351,496 / 430,775,813,284. These are
supported operator counts, not a count of all work. CPU is the exact owned
child's user-plus-system `wait4` total, including inherited waited-descendant
accounting. RSS is a maximum single-process high-water, not simultaneous
process-tree memory. The raw 50 ms observations and exit-gap reconciliation
records are retained.

This was one run on a shared host with affinity restricted to CPU 0 and 1.
Other work and the separately capped Cell readback overlapped some phases.
The source-parent arm uses eight independent load/infer processes; the other
arms evaluate eight requests per loaded process. These observations must not
be represented as an isolated hardware benchmark, equal total compute, or a
statistically established cost advantage.

## Candidate transport and next-task byte readback

A separate controlled run packed the exact candidate target contract,
adapter wrapper and trained tensor object into three Cell objects. A fresh
consumer cache fetched all three through the existing fixed native provider
binary. All fetched object hashes matched the producer bytes.

| Observation | Actual value |
| --- | ---: |
| Objects / chunks | 3 / 3 |
| Downloaded chunks / previously cached chunks | 3 / 0 |
| Payload bytes | 1,011,315 |
| Received response bytes | 1,012,185 |
| Connections / rejected responses | 6 / 0 |
| Fetch plus cache materialization seconds | 0.180327790 |
| Aggregate transfer limit seconds | 35 |
| Provider lifetime limit seconds | 45 |
| Provider terminal exit code | 0 |

The provider drained before the next task. The original inherited-runtime
owner then read the **fetched** candidate descriptor and tensors, performed a
real forward, and reported adapter
`763619f20b37cbced090ab258944bbefda81b52bd0ed4ad95e764bb893ef65b8`.
For the preselected next prompt, “Answer with only yes or no. Is 103 greater
than 102?”, the actual decoded output was `yes`. This child's wall time was
70.564454336 seconds, CPU 63.068274 seconds, and `wait4` RSS 1,152,724,992 bytes.
The original no-authority fields remained false.

The transport used separate producer/consumer processes and empty consumer
cache on **one controlled loopback host**. It reused the preexisting verified
backbone and existing fixed provider binary; that binary was not rebuilt here.
It is not evidence of independent physical nodes, cold acquisition of the full
backbone, native ordinary installation, or installed-child FinalUse.

## Validation and retained failures

The final exact-source check ran **71 distinct tests, 71 passed, zero failed,
zero skipped**: 58 parent/task/objective controls, 9 existing candidate-observer
controls and 4 CI-registration controls. The ten new V4 byte controls are part
of the 58, not an additional count. Earlier overlapping test invocations are
retained but are not added to the 71. This is Python boundary/gradient and
registration validation; no complete Rust workspace gate is claimed here.
The existing source-integrity negative suite separately passed 34/34 in
6.394 seconds; its intentional rejection receipts are retained in
`source-integrity.log`. The distributed source inventory, CI contract checker,
and README file-link checks passed. Executable source
remained byte-identical to the real-run source after adding this evidence.

The evidence preserves unsuccessful observations as separate attempts:

- The first real-run caller omitted `parent_contract` and failed before model
  dispatch. Commit `c86cabce381ff24f0e002693eb46d9b7a49e1690` fixes that caller;
  run 002 is a new attempt, not a rewritten run 001.
- A Cell caller initially rejected an unclean source checkout before effects.
  The identified unchanged V5 leftovers were verified before cleanup.
- The first native provider attempt was denied loopback binding by the sandbox
  with `Operation not permitted`. Its pack results, stderr and failed outcome
  remain. The separate bounded loopback attempt succeeded after approval.
- The system Python attempt had three missing-`torch` errors. The exact-source
  71-test run used the pinned existing model environment and preserved that
  earlier environment failure.
- A proposed Library upload of the full-tune checkpoint failed tool discovery
  under restricted networking; its follow-up escalation was rejected before
  execution because model export authorization was not established. No model
  payload is exported through this evidence archive as a workaround.

The archive also includes selected historical records from Hepta source
`bf32538ccb9b52e3e0a8e089983eea7e3940b6a5`, run `40517226441`: its scoped original
gate observed 1,840 passed and 35 failed tests; required outcomes remained false,
proposal rounds failed, and lint was skipped. Those are explicitly historical
observations, not a rerun or a result of the new V4 experiment. The complete
19,409,899-byte original Rust log is not in this archive; its original digest,
selected records and retained failure extract are included.

## Evidence contents and open completion conditions

[raw-evidence.tar.gz](raw-evidence.tar.gz) contains 230 verified members and is
612,788 bytes; SHA-256:
`8f7a2bc0cb805486eec36413b6616dc594075ccbae8ceaf5d242e3d28a3e5ad6`.
Every included member was reopened and checked against its recorded size and
SHA-256. [manifest.json](manifest.json) lists included files and nineteen
explicitly excluded tensor/cache entries. Full model weights and payload-bearing
caches remain local. The successful full-tune checkpoint is 538,090,376 bytes,
SHA-256 `0c2c599b2932677cd13d6e06140f2f8b451c2ff9d87d083b558615f317f75cf1`.
Two redundant incomplete byte-for-byte prefixes were reclaimed during the
original observation. A later [verified cleanup](unused-upload-prefix-cleanup.json)
reclaimed a third 289,931,264-byte unused upload prefix after checking every
visible process descriptor and comparing the prefix byte-for-byte. The complete
checkpoint remains intact with the hash above. The archive is not a complete model distribution.

The original Hepta prerequisite gates, authenticated actual CURRENT parent,
independent/longitudinal evaluation custody, positive eligible selection,
ordinary qualified-child installation and installed next-task FinalUse are
still open. The zero relative gain is itself sufficient to refuse this
candidate. Completing those requirements needs a genuinely qualifying candidate
and the original authenticated owners; successful public training and transport
receipts do not substitute for them.

## Publication packaging readback

A final independent readback checked all 230 archive members and all 397
recorded executable-source hashes against the actual files. The initial Git
whitespace check treated ordinary context-blank lines in the preserved raw
patch as newly added whitespace; that [failed check](initial-publication-whitespace.log.gz)
is retained. The separate patch is now gzip-encoded without changing any
decoded byte. The raw patch also remains inside the original archive. This
packaging change does not alter executable source or any experiment result.
