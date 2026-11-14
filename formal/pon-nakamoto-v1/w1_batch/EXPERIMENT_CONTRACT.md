# Bounded full W1 composition experiment contract

This contract records an experiment proposal, not an execution receipt.
A later [bounded Phase0 attempt5](../../../evidence/pon-w1-batch-build-20261028-r8/README.md)
compiled the guest and host; no batch guest execution or proving has occurred.
The original source-only observations remain historical. Future commands need an
external observer that records every failure, timeout, owned process birth/PID,
process-group kill, wait4 result and resource-accounting gap.

## Frozen relation, encoding and source

The leaf is the complete original image, words in little-endian order:

```text
4203990569 1706128024 889896351 2751765305
3434005897 1411617246 870515685 3215144349
```

Its source is `64be7c4ad51d432e7736ad135476262e23e968f5`; the retained complete
receipt SHA-256 is
`ca4d3c9f5159b7001abae7491604cadbbbfa97c0f93d90d5943e48936813ca2b`.
Its one original work ID is
`ccf544056c6df13a5ab4e6c021e587ff0008d92388270e64f72a6e2168a326cd`.
Reproving or repeatedly referencing these bytes does not increase that count.

The input is `TRNM-W1-BATCH-INPUT1\0`, u32-LE count, and count fixed-size
entries of 318-byte header followed by 16,818-byte full leaf journal. Count is
1 through 64; the guest rejects missing/trailing bytes. The output is
`TRNM-W1-BATCH-JOURNAL1\0`, the 32-byte fixed leaf image, u32-LE count, then
the full ordered journals. Its prefix is 59 bytes. Journal/header order,
canonical fields and distinct original identities are checked twice: in the
guest and after final host cryptographic verification.

The new batch image is derived by compiling the new source. It must be frozen
with source/tree, both locks, guest ELF hash and host binary hash before any
measurement. There is no predeclared imaginary image ID, and no manifest field
can override the compiled image. An independent verification-only build for
that frozen batch image is a later required gate; the shared source host alone
does not establish independent implementation agreement.

## Phase 0: actual baseline build and next host qualification

The [actual attempt5 packet](../../../evidence/pon-w1-batch-build-20261028-r8/README.md)
records a successful ordinary offline release build of the complete batch guest
and baseline host at source `401096e8f9eed84fcb4d78122a49fa5dd3aa88e9`.
The observed guard cost was 140.667001761 wall seconds and 138.300131 child CPU
seconds, with 371,240,960 bytes of target growth. Its guest is 308,184 bytes,
SHA-256 `734eb42893951b0915f86e4517a231b04279ace8f8d81ca2dd79d6ed95771219`.
The guest image words are
`[1000984451,3139256748,3364805072,2363167537,26593440,771198122,3700220126,2888495343]`.

This result followed three retained failed builds and a security-rejected
MSRV-only downgrade; proposed attempt4 did not run. The complete authenticated
official RISC Zero 1.91.1 compiler is now installed under
`/tmp/w1-risc0-1911-resources-r8/home`. Its exact acquisition, complete file
inventory and real version/target checks are in the
[acquisition packet](../../../evidence/pon-w1-rust1911-acquisition-20261028-r8/README.md).
The older compiler archive and all failures remain historical evidence. No old
compiler restoration or vulnerable lock downgrade is part of the current plan.

The retained Cargo cache is `/tmp/pure-pon-cargo-20261027`; the existing target
is `/tmp/trnm-w1-r2-target`. Both independent locks, SDK and builder 3.0.6,
native Rust 1.95.0 and the four-variable offline/single-job wrapper remain pinned.
No RISC Zero native `prove` feature/C++ prover build is required. The pinned
local backend remains `/tmp/pure-pon-risc0-3.0.3/r0vm`, SHA-256
`2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6`.

The new staged host source requires a separately measured normal native rebuild,
retained release workspace Rust tests and strict Clippy. That H0 proposal is
**180 wall seconds, 360 child CPU seconds, 2.5 GiB sampled process-tree RSS,
256 MiB target growth and a 1 GiB free-disk floor**. The
[staged pilot contract](STAGED_PILOT_CONTRACT.md) gives its exact scope. Any
actual guest rebuild is charged to that envelope and must reproduce the exact
previous guest bytes and image. Skip-build, image substitution, lock changes,
version-check overrides and automatic retries are prohibited. Only its actual
qualified new host hash can be bound to the later proof attempt.

## Phase 1: exactly one original leaf, real assumption resolution

Only after reviewing the new H0 host qualification, source, image and resource result, run
the following in a **new** output directory. No second complete leaf is proved.

```sh
env RAYON_NUM_THREADS=8 \
    /tmp/trnm-w1-r2-target/release/trnm-w1-batch-host \
    prove-staged --r0vm /tmp/pure-pon-risc0-3.0.3/r0vm \
    formal/pon-nakamoto-v1/w1_batch/examples/one-leaf.json \
    /tmp/trnm-w1-staged-r8-one-leaf/pilot
```

The host refuses `RISC0_DEV_MODE`, `BONSAI_API_URL`, `BONSAI_API_KEY` and
`RISC0_PROVER`; they must be absent, not silently changed to select a fallback.
Use at most the already observed eight-CPU resource class with no simultaneous
History benchmark. Proposed hard cap: **600 s wall**, **4,800 CPU-s**,
**3.5 GiB process-tree RSS**, **512 MiB newly written proof artifacts**, a
**1 GiB free-disk floor**, and one attempt. The guest session is additionally
capped at 2^24 cycles with 2^18-cycle segments. Caps are not a completion claim.
If any bound expires, terminate and reap the entire owned process group,
retain TIMEOUT/UNKNOWN as applicable, and stop. No automatic second attempt or
budget reset occurs after a restart.

There is no measured `resolve` cost yet. Historical source-bound observations
for other recursion operations are 59 lifts with median 20.279 s (max 25.082 s)
and 58 joins with median 20.506 s (max 25.391 s). Segment proving had median
57.654 s across 58 recorded continuation entries (max 69.985 s). An initial
engineering estimate for a one-segment aggregation is roughly one segment,
one lift and one resolve: order **1.5 to 3 minutes** if resolve has comparable
cost. That comparison is an **unmeasured hypothesis**, not a resolve benchmark;
more guest segments, compatibility failures, memory pressure or distinct
resolve complexity can invalidate it. The 600 s cap is a deliberate probe
budget and may fail to complete.

Retain the complete original leaf pipeline's cost ledger alongside the new
incremental aggregation ledger. The prior proof already incurred at least
**41,887.28597837 CPU-s** of observed pipeline work, with incomplete terminal
accounting. A cached proof is not free in an end-to-end proving comparison.
Do not add overlapping per-process lower bounds; use the actual accounting
boundaries and explicitly preserve missing supervisor/observer costs.

On success, invoke fresh processes for `verify`, `verify-many`, and `controls`
with the same one-leaf manifest and the saved `succinct.bin`. Preserve receipt,
input, journal, ELF, all stdout/stderr, full mutant bytes, and timings. The final
receipt must be Succinct, successful halt, exact compiled batch image and
journal, and empty assumptions. The output must reproduce all original leaf
public bytes. A valid original leaf receipt presented as the final batch is a
wrong-image negative, not an aggregate proof.

Required negative classes include repeated work ID, changed-product duplicate,
missing/extra/reordered entries, count overflow, altered header, leaf image,
domain, trace, ticket, carried ID, noncanonical C, truncated/trailing encoding,
Composite/Groth16/Fake receipt tags, mutated metadata/claim/seal, real valid
wrong-image proof, and a real unresolved conditional receipt. The source-only
public controls cover structural cases; the host has a first cryptographic
mutation suite. The new staged source saves and verifies a genuine unresolved
conditional receipt, observes final verification rejection and resolves it with
the actual original leaf. These added paths are **not yet compiled or executed**;
their source review cannot substitute for the required real controls or establish
Rust/native relation equivalence.

One successful pilot would close only the narrow **one-leaf composition works
under the measured source/backend/resource envelope** subtask. It closes
neither batch benefit, independent-input cost/tail behavior, quantum soundness,
full-block validity nor the user's complete work package 2A.

## Phase 2: benefit requires genuinely distinct work

The historical native full-replay median is 0.5543925 ms; hardened complete
receipt decode/verify median is 16.660953 ms. A constant-final-cost arithmetic
screen first crosses CPU at **31 distinct works**. Keeping all public journals
crosses bytes at **8 distinct works** under the same hypothetical fixed seal
size. These are screening calculations only. A 31-leaf actual batch adds
journal hashing/parsing and may fail CPU benefit; 32 leaves are still marginal.
Use 64 as an additional candidate only if real measured prerequisites justify
its much larger proving budget. Do not lower the relation to improve a ratio.

| Total distinct leaves | New full proofs needed (one exists) | Additional CPU reference | Sum of prior recorded-duration references | Raw final leaf receipts | Full archival size reference |
| --- | ---: | ---: | ---: | ---: | ---: |
| 31 | 30 | 349.06 core-hours | 55.94 hours | 7,963,466 B | 2,025,828,889 B |
| 32 | 31 | 360.70 core-hours | 57.80 hours | 8,220,352 B | 2,091,178,208 B |
| 64 | 63 | 733.03 core-hours | 117.47 hours | 16,440,704 B | 4,182,356,416 B |

The table multiplies the **one existing observation** (CPU lower-bound
41,887.28597837 s, recorded-duration sum 6,712.315070 s, archive 65,349,319 B).
These are planning references, not lower bounds for future inputs, a promise of
completion, a scalable throughput result or isolated end-to-end wall time.
Earlier failures/setup may amortize differently; new failures may cost more.
The existing proof's cost remains in the full campaign total. These campaigns
are not authorized by the one-leaf cap and cannot fit silently into the current
3.5 GiB spare disk or a single short execution window.

Generate every new leaf with the original frozen full guest and all original
constraints, and retain its original header/witness, work ID, real receipt and
complete failed/successful proving ledger. Predeclare inputs and batch order.
For each batch, measure the sum of **native verification of its actual unique
inputs**, and actual batch wire decoding, proof verification, all public bytes,
and still-required parent/task-window/M06/authorization work. Repeated work
IDs must reject before credit; use the cardinality of independently valid
original identities as the only work denominator. Multiplying one native
timing by 32 copies of the same receipt is an invalid comparison.

Compare generation CPU/wall/RSS, full and incremental aggregation costs,
receipt bytes, verifier CPU and all-observation latency under the frozen
workload. Include batch fill/wait time in service confirmation latency; do not
report only already-available batch verification. Repeated verification of one
saved batch supplies fixed-input sample quantiles, not independent proving
trials or production p99. The gate needs actual benefit without relation
omission or free work, and retains honest negative/no-benefit outcomes.
