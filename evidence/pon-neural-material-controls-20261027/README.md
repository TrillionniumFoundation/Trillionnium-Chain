# Real neural components and bounded runtime material declaration

Status: **PARTIAL / NO ADOPTION / I10 OPEN**. These observations do not establish
an ordinary Hepta installation, an ordinary next task, complete cold runtime
closure, independent evaluation, useful PoN chainwork, public rewards or activation.

## Source and retained evidence

The actual local model and Cell observations used unmodified Chain
`c96022b897c1235fdbdbfcfa32764403511c6aab` and the genuine Hepta source
`e1537d7deea32f29ec9612c0a7b90655b14aa904`. The source archive blobs, complete
Git trees and original commit bytes were independently verified; historical
evidence blobs were omitted from the local working checkout. No Hepta Rust native
consumer was built or invoked. Delivery is stacked on the existing public-input
candidate `7149e24207542dd393cdf0f9d462f5af5550e875`; the five affected existing
runtime/CI files match the executed c960 baseline byte for byte before this patch.

[Observations](observations.json) separate the actual phases and remaining gates.
[Raw evidence](raw-evidence.tar.gz) contains157 files /4,430,217 raw bytes, including
original successful and failed records, the actual learned adapters, plans,
material descriptors, commands and component test logs. Its SHA256 is
`1a504618bcdefb2b22929f06d3b4c92177bdc2f710aa78f789a4e8c9741998df`.
[Archive metadata](archive.json) and its internal `FILE_INVENTORY.json` bind every
retained file. Public base weights, wheels, large copied interpreter files and
Cell SQLite files are excluded from the compact archive and identified explicitly;
this archive is not a complete executable runtime distribution.

The source model is `HuggingFaceTB/SmolLM2-135M-Instruct` revision
`12fd25f77366fa6b3b4b768ec3050bf629380bac`. Its seven original public-file pins
and all31 CPU wheels were verified. The original dependency lock SHA256 remains
`178b2fe89a7bf58f2d127b195d82e4fa9b5c19d93cb3526d8789edf3df901017`.
The public-input artifact came from run40479075225 /artifact12722181123 at
`920e269a45cfecb5c610d9c70612a303459a2f1f`; all44 files /513,207,580 bytes matched
its inventory. The original downloaded material manifest's extra transport URL
field was explicitly projected to the original exact model-pin schema; model
bytes did not change, and both manifest hashes and the transformation are retained.

## Real local model observation

The original loader completed8 requests /64 forwards. The original V2 parent
training entry then completed10 optimizer steps,526 tokens and40 supervised tokens
using CPU FP32 and two threads. Direct tensor readback found60 A tensors and60 B
tensors changed from the prepared setup:230,400 FP32 values. The initial parent
artifact stayed unchanged. The learned adapter is
`d3b3e79ee9432f467881b9b7fd5eef1c6d2908da6fce73de9fd786f541094dc6`; its933,544-byte
safetensors SHA256 is
`eaa627e8937afa9f23fb8ab97c89d03f8e59748c6016cd610772bc594f81a90b`.

Training itself took68.797852 seconds; the original supervisor's complete child
wall was130.890587 seconds and its exact wait4 peak RSS was3,067,777,024 bytes.
The sampled peak is a separately recorded measure. The profiler reported
289,144,351,496 supported-operator FLOPs, which are neither total neural work nor
a consensus security lower bound. The original candidate observer completed
another8 requests /64 forwards with exact parent and candidate byte readback.

Every candidate output was `yes`: calibration2/4 and evaluation2/4. Decreasing
training loss and changed parameters do not establish model improvement. The
post-observation four-control comparison used the original pilot child and
supervisor, unchanged10 steps/two threads,1800-second/16GiB training caps and
600-second/8GiB inference caps. Current-backbone and fresh-LoRA preparation passed.
Full tune was killed by SIGKILL(-9) after85.434079 seconds; exact wait4/reap completed,
peak RSS was4,321,779,712 bytes, and `stop_reason` was null. It produced no successful
training receipt. The remaining control preparation and all control evaluations
were not executed. The verdict is **INCOMPLETE_NO_ADOPTION**, not zero measured gain
from a completed five-way comparison.

The shared host exposed an8GiB cgroup limit. Post-failure reads observed one OOM
kill, but no pre-execution counter baseline exists; the specific SIGKILL cause is
therefore not proved. No unknown host service was stopped. The failed cohort is
not retried or relabeled. An earlier outer-caller TypeError after the successful
loader is also preserved: the corrected caller supplied the two original family
roots and reused the saved loader result without reexecuting that phase.

## Cell failures and unexecuted installation

All attempts declared the same11 materials /269 chunks /272,189,870 payload bytes,
TCR1 root `0c3b841b42f507129d24bb3f335c90756e8057fb06883c9bf62d3100bfdd0cfd`.
The original35-second aggregate fetch,45-second provider,two workers,two fetch
requests and512MiB cache/main-DB limits stayed unchanged.

| Attempt | Build and observed result | Aggregate transfer |
| --- | --- | --- |
|001 | Unoptimized; local sandbox denied bind with EPERM | Not started |
|002 | Unoptimized; approved127.0.0.1 listener; verification deadline |35.080094959s, incomplete |
|003 | Optimized release; approved127.0.0.1 listener; connection reset at response header |2.074596833s, incomplete |

The release binary was independently built from the same unchanged source with
Rust1.95; SHA256 `480ffbafbf93307859c87872e807b90c218c4fb9e238be04e6ac88e3daa407e6`.
The dev binary SHA256 is
`904efe919ea58881628750c3ff4a3a769f6354e122329b434ace684795f53e1d`.
These failed samples establish no completed goodput or WAN availability result.
The original controller does not persist provider stdout/final service counters
on its failed path;003 has empty stderr and no server report. Its specific reset
cause remains unknown. Later diagnostic source changes must preserve this gap.

No transfer verified all members. Installation and the predeclared next backend
request were not reached. The original handoff's initialized `UNAVAILABLE` field
is a capability declaration, not evidence that an ordinary installation was
attempted and refused. Same-operator loopback would not satisfy independent custody
even if the transfer had completed.

## Runtime declaration source increment

The existing [Cell release owner](../../scripts/llm_cell_release.py) now exposes
bounded read-only declare/verify commands backed by
[the new material schema](../../scripts/llm_runtime_release.py). It binds declared
source/execution/model context, platform/ABI, exact file hashes/modes and directory
readback, original wheel bytes/RECORD/dependency markers/extras, and static ELF
loader dependencies. Wrong pins, missing/changed bytes, ambiguous libraries,
symlink/hardlink/FIFO paths, `.pth`, bytecode and observed mutation refuse. It
constructs no held namespace capability and grants no execution or installation.

This V1 accepts a canonical original-wheel extraction layout. It does **not**
accept the actual pip-installed Torch environment:31/31 top-level RECORD files
were rewritten, installer metadata was added, `distutils-precedence.pth` exists,
and setuptools contains12 vendored RECORDs. Reviewed installer/vendored metadata,
`.data` relocation, import policy, dynamic loading and the actual held namespace
remain OPEN. The cold CPython plus tiny test-wheel control is not a cold SmolLM
runtime result. The complete runtime-release extension must join the existing
M09/ResourceGrant/CURRENT/FinalUse owners before any I10 claim.

Material verification passed13 tests; the original Cell release suite passed8,
and four existing CI registration/refusal tests passed. The strict log reader
requires all13 exact runtime test names once with zero skips. Its first integration
attempt incorrectly used21(the combined13+8 count); the reader correctly refused.
The corrected count comes from the actual AST; no test/assertion was removed.
This preserved harness error is separate from the passing model-material controls.

## Fresh CI diagnostic, not a replacement receipt

[The dedicated workflow](../../.github/workflows/pon-model-controls-diagnostic.yml)
has one ubuntu24.04 job, the retained15-minute job ceiling and a stricter10-minute
outer model-step ceiling to leave time for partial evidence. It reuses the existing
public input fetcher and original hash-locked CPU environment, then calls only:

```sh
python -B scripts/llm_runtime_pilot.py run --materials MODEL \
  --output FRESH_OUTPUT --backend cpu --threads 2 --steps 10
```

That original owner freezes its own fresh five-participant roster before evaluation.
A new CI source/run/candidate must be reported separately from this local V2 parent
candidate. At this evidence freeze it is **NOT_RUN**. No success is inferred from
the workflow source or local unit tests. The original per-role caps stay unchanged;
the CI outer limits can only abort sooner. Timeout, absent receipt and partial work
remain failures. Compact raw results and actual learned safetensors are uploaded
separately when the runner reaches those steps. A failure before the source step
initializes its directory, or a hard job kill, can prevent complete retention;
`always()` is not a guarantee of artifact delivery or owned-child terminality.
