# Fixed E Composite preflight boundary measurement

This is an offline measurement of the original `receipt_bounds.rs` from Chain
commit `974932be6dcfe830ce1ce92d58cb10e89cb8358d`, tree
`d4435ebdecac15e9a3fb2852eb1f835b336e452e`. Its Git blob is
`a35271781ae442c534b456dde3c930ecd034eb86`; SHA-256 is
`e4b5bea658dc06649e0b0c69f09bf3407d4eb64b73f382aac3be2a24da8d2d37`.
The std-only Rust harness imports that file directly. The Python owner refuses
another parser blob and checks the parser and harness bytes again after work.

## Scope and actual outcome

All input seals are explicitly synthetic, zero-filled grammar. No SDK, W1
execution, proof generation, receipt authentication or network operation occurs.
A shape passing preflight is not a valid proof. No production or global worst
invalid-proof claim follows from these measurements.

The final local observation passed 18 cases. Five exercise admitted shapes;
13 exercise malformed or refused inputs. Each case makes 11 individually timed
parser calls and one fixed 4096-call CPU batch: 73,926 parser calls in total.
Every parser allocation window recorded zero Rust global allocations,
reallocations, deallocations and requested bytes. Every case separately recorded
one actual input-construction allocation, serving as a live counter control.
There is also a black-box empty-loop reference with 4096 calls. Its raw CPU/wall
results are retained and are never subtracted from parser observations.

The maximum shape simultaneously reaches 134,217,728 bytes, 2048 segments and
268,435,456 padded cycles (2048 * 2^17), with each individual seal within its
262,144-word limit. A second case reaches four bytes below the total cap.
Negative cases mutate the last segment index, hash, cycle count, output option
or seal length, then the outer assumptions/journal length, last metadata byte,
and trailing byte. Other cases exceed total bytes, segment count or seal size.
The trailing-byte case starts four bytes below the total cap, so it reaches the
late trailing-field check instead of the early byte-budget refusal.

Selected actual observations on the local Linux x86_64 environment:

| Case | Parser wall median of 11 | Largest observed sample | Fixed-batch observed CPU / call |
|---|---:|---:|---:|
| Exact 128 MiB / 2048 / 2^28 admitted shape | 54.734 us | 190.870 us | 22.231 us |
| Last segment index invalid | 50.357 us | 300.324 us | 22.697 us |
| Outer assumptions invalid | 34.108 us | 239.316 us | 27.320 us |
| Final metadata byte missing | 105.124 us | 285.256 us | 35.507 us |

These are finite local samples, not hardware-independent limits or a global
maximum. The CPU column is one batch's raw CPU divided by 4096, including loop
and counter overhead. Very short paths still report zero batch CPU delta; their
amortized value is null and unresolved, never zero computational cost. Individual
call CPU values are retained raw without a claim of sufficient resolution.

The largest shape's input construction took 81,582,144 wall ns in its own
record. Its Vec requested 134,217,729 bytes (including one spare byte for bounded
negative mutations). Across all cases, maximum waited process RSS was 132,880
KiB. RSS includes the constructed input, runtime and output; it is not parser
allocation. The preflight skips seal payload slices and reads bounded headers,
claims and dimensions. Its timing is not a throughput measurement for hashing
all 128 MiB, generic bincode allocation, or cryptographic verification.

## Retained earlier slower invalid-input observation

`prior-default-sigchld-measurement.json` and
`prior-default-sigchld-raw-cases.jsonl` preserve the complete preceding batched
observation, including its actual **3,886,476 ns (3.886476 ms)** invalid-input
wall sample for `late_outer_assumptions`. That run also passed all 18 cases and
made 73,926 parser calls under the same runtime wall, address-space, output and
command-scheduling budgets. Its owner SHA-256 was
`0dab05df4cc71ba10e8580681bc28609056bae26d9f5bbaebcba1c4f99692224`;
the final owner SHA-256 is
`1d929d7bc46bfed6c86167425d125a5dc1c50a1777bf85f45c6b4dd120a9ac61`.
Both compile the identical Rust harness Git blob
`2c1e936037f2d161991d4f58ae5021cc91999f88`, SHA-256
`8e965321d852c6fb2649ca335e1f21bd50645a0b29c9bdb76c14750240922d11`,
and the identical original E parser blob recorded above.

The prior run used the fresh default-SIGCHLD CLI path and installed no signal
handler. Its report did not record a standalone signal-disposition snapshot;
all direct waitid/wait4 observations completed successfully. The final revision
adds an explicit pre-spawn refusal of a nondefault SIGCHLD disposition and makes
the deadline metadata/scope precise. It changes no Rust case, parser, threshold
or runtime budget. The new SIG_IGN control is an additional rejection control,
not a claim that the prior successful case processes used SIG_IGN.

The final run's largest observed invalid-input wall sample, 300,324 ns, does
not supersede the slower retained observation. Across these two retained
campaigns the largest observed invalid-input sample is 3.886476 ms; neither
that observed maximum nor either run's median is a global worst-case bound.
The difference also shows why these local sampled durations are not stable
hardware-independent costs. Both complete raw observation sets remain available.

## Reproduction and fixed limits

From a checkout containing these two harness files and the original E parser:

```sh
python3 scripts/ci/measure_w1_preflight_boundary_v1.py   --repository-root .   --rustc /absolute/path/to/rust-1.95.0/bin/rustc   --out /new/exclusive/observation-directory
```

The Linux 64-bit owner enforces 20 seconds and 512 MiB address space per case,
45 seconds and 2 GiB address space for compilation, a 90-second command-scheduling deadline,
and a 128 KiB per-file child output limit. The 90-second value is a command-
scheduling deadline; at most two seconds of child cleanup and parent durable
recording/hash/report finalization are outside that deadline. It is not an
end-to-end hard owner wall kill. Blocking kernel operations are not hard bounded.
Each case uses an exclusive process group, direct wait4 accounting, bounded
cleanup and separately durable records.
Inputs are only constructed in memory and are never written as 128 MiB files.
The final compiler invocation passed `-D warnings`; rustfmt check and Python
syntax parsing also passed. No full workspace Cargo or hosted CI qualification
is claimed by this isolated measurement.

Independent review identified that SIGCHLD=SIG_IGN could invalidate WNOWAIT PID
reservation through automatic reaping. The runner now refuses any nondefault
SIGCHLD disposition before spawn without changing the caller setting. An actual
SIG_IGN negative control confirmed pre-spawn refusal and preserved disposition;
its process record is retained. The complete 18-case campaign was rerun on this
final runner with unchanged limits and passed.

The first build failed because the same 128 KiB file limit also capped its
static ELF; the linker received SIGXFSZ. That genuine failed attempt is preserved
in the two `initial-build-failure` files. The successful build uses dynamic
compiler-owned std and symbol stripping, retaining all original harness limits.
The exact std library hash and before/after identity are recorded in
`measurement.json`. This is a local measurement environment, not a portable
binary release. The ELF is reproducible through the script and is not committed.

`measurement.json` contains every case's actual timing arrays, construction
measurements, process records, source identities, binary identity and limits.
`raw-cases.jsonl` contains the unmodified individually flushed Rust records.
The initial non-batched successful observation is retained in the local working
receipt directory, but the committed final result uses the CPU batch/control.

## Remaining P0 coverage gaps

E's actual Composite `audit` contains 16 finite negative cases based on a real
receipt and records one wall duration per case. It does not establish the
cryptographic worst invalid input throughout the 128 MiB / 2048 segment /
2^28-cycle envelope. Different cases time different entry paths; construction,
input read and some deserialization work are outside their timers. There is no
per-case CPU/RSS observation or independent case deadline. All negative-case
results are printed only after the entire audit, so a later timeout can prevent
publication of earlier case timings. The whole audit has a 900-second limit.

This harness addresses maximum-shape preflight and Rust allocation observations
only. It does not cover SDK allocation/RSS, all permitted SDK claim-variant
combinations, costly cryptographic late rejection, or malformed proof traffic
under concurrency. Those need separately bounded measurements, including a real
positive proof and same-source cryptographic negatives when available.

The E `pon-complete-w1-proof-research.yml` workflow has no network propagation
measurement step. Receipt file creation and GitHub artifact upload do not measure
protocol propagation. It does not report complete wire framing, sender/receiver
cost, receiver verification, throughput, backpressure or WAN behavior for the
new E proof. The old #534 Succinct loopback measurement has a different source
lineage; it cannot be relabeled as new E Composite propagation. The optional
PWAI0001 verifier accepts Succinct research certificates within 1 MiB, whereas
this Composite research host allows up to 128 MiB and does not define a new live
network packet codec. No network or admission limit is changed here.
