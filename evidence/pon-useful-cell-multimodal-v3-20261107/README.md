# Finite multimodal Cell V3: retained arithmetic controls

The final source passes **59 distinct tests**: the retained full run contains 58,
and the subsequent owner-snapshot behavior regression adds one. The final
eight controls each process four inputs with UTF-8 text, RGB8 images and PCM16LE
audio. They contain **96 unique complete W1 transcripts**, 12 per control.
Historical replay, live-window verification and a fresh Python process all
accept every final control. Rechecking a proof does not create another proof.

| Final control | Rows | Complete W1 transcripts | Observed behavior |
| --- | ---: | ---: | --- |
| sampled | 4 | 12 | Real SHA256 sampling and retained RNG counters |
| masked | 4 | 12 | Token, patch, frame, feature and legal-expert masks |
| training | 4 | 12 | Replayed integer backward/update; changed model artifact |
| successor-model-next-input | 4 | 12 | Updated model and state used on a different admitted input batch |
| tool-proposals | 4 | 12 | Four proposals; no tool execution or external delivery |
| abstain | 4 | 12 | Four abstentions; specified memory/budget transition |
| stopped | 4 | 12 | No memory, RNG, budget or optimizer update; sequence advances |
| exhausted-prefix | 4 | 12 | One emit followed by three STOP actions |

All-STOP still executes the frozen batch's forward graph and all 12 dense
proofs. STOP controls decision/state effects; this profile makes no claim that
STOP avoids the preceding computation. Each dense operator has its own actual
weight/input material, padded product, full W1 trace and task-bound challenge.
Lookup, preprocessing, pooling, nonlinearities, decisions and backward/update
use complete scalar replay. Backward is an explicitly defined integer
surrogate with frozen route and memory boundaries, not BPTT or the derivative
of a discontinuous integer function.

## Exact source and counting

The final program SHA256 is
`f111c873f7df1e9b440072bc8776e2ba4e34228ae1c106149cf83eca77c6e357`.
The parameter SHA256 is
`78be8c582c149d46053d8e0306774624cb2c9136fef56108bc6361a0013fd16d`.
The recorded runtime is CPython 3.12.14. Runtime identity is part of the pin.
The two verifier/executor sources and their executed repository dependencies
are included in the archive; source guards establish local consistency only.

The earlier `controls-attempt1` group belongs to program
`bfba421a366ce47f19431c0aa41cc050fca7ffbde7c43e903819e07420475f2c`.
Its separate 96 transcripts are retained and **are not added to the final 96**.
The final change snapshots the independently canonicalized owner's before-state
through the entire replay and W1 challenge sequence. A deterministic scheduling
control mutates the caller's original dictionary at replay entry and confirms
that the verifier continues to use the one admitted snapshot.

No failing process exit was observed in this new lane. All earlier run logs,
old pins and source fences remain in the archive. The earlier relation source
was recovered by removing the precise later snapshot block and matching its
previously retained SHA256; `RECOVERY.json` identifies that reconstruction.
The initial pre-test identity-only observation is retained without assigning
any proof or test result to it. Unit-test proof generation is not included in
the retained-control proof count.

## Files and reproduction

- [REVIEW.json](REVIEW.json) records test groups, final source hashes and explicit qualification limits.
- [PROOFS.json](PROOFS.json) lists every proof's byte count and SHA256, separately for both program pins.
- [MANIFEST.json](MANIFEST.json) lists the size and SHA256 of every archived payload file.
- [ARCHIVE.json](ARCHIVE.json) identifies [retained-runs.tar.gz](retained-runs.tar.gz).
- [PACKAGE.sha256](PACKAGE.sha256) covers the top-level evidence files.

Every archive member was read back and checked for an ordinary relative file
path, exact size and SHA256. `raw/controls-owner-snapshot/` contains the final
contracts, independent fixture-owner expected contexts, original bytes, full
witnesses, states, model artifacts, verification reports and cold-process logs.
`source-final/` contains the exact implementation and test/driver source.

From the matching source/runtime, the two explicit test modules are
`test_useful_cell_multimodal_execution_v3` and
`test_useful_cell_multimodal_relation_v3`, under `formal/pon-nakamoto-v1`.
The experiment driver accepts `--output` with a new directory or `--replay-case`
with an extracted case directory. It never overwrites an earlier output run.

## Qualification limits

The raw inputs and weights are generated arithmetic fixtures. The target is
`ff` repeated 32 times, a maximal correctness control. Timing/CPU observations
are retained observations, not work-cost qualification. The finite learned
byte/patch/frame encoders and fixed residual MLP/LoRA/head graph do not establish
support for arbitrary multimodal encoders, model graphs or production quality.

Origin claims and parent contexts are content-bound but not independently
authenticated by these fixture runs. The pure verifier grants no authorization,
does not consume a request, commit a checkpoint or grant/use FinalUse, and does
not establish ordinary Hepta/native Node admission, external delivery or actual
production adoption. The next-model control is a local arithmetic consumer,
not the real owner commit boundary. All corresponding qualification flags stay
false. No private Hepta source, records or credentials are included.
