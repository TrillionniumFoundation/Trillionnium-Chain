# Complete W1 transparent-proof experiment, 2026-10-27

This evidence belongs to the [complete W1 research relation](../../details/W1_COMPLETE_RELATION_RESEARCH.md)
and its [isolated RISC Zero backend](../../../../../trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/README.md).
It does not activate a consensus profile, issue `VerifiedWork`, qualify public
ingress, establish useful model training, or qualify PQ128 security.

The guest retains the actual existing N=64, r=8, q=2^32-5 relation, all four noise
streams, all 512 ordered intermediate tiles, every SHA-256 transcript byte, and
the complete product corrections. The fixed synthetic input has 49,640 bytes;
its deterministic public journal has 228 bytes. The input's all-`ff` target is a
research context, not proof that the fixture is an eligible Chain block.

## Actual program identities

| Program | Image ID | Raw ELF SHA-256 |
| --- | --- | --- |
| Original integer-remainder implementation | `c4882af18d381d7a6c36cea135dbe417e730dd3522255d2a32c8942ef57dfa2d` | `4c7b9760f9a21355431ed0f1dcea4b68a4d88a69a592e892de8e2046b3874fe5` |
| Exact folded-reduction implementation | `3ea1bcbf7900a32be73d7e78102de085562893732473667e1f3af07e585696b4` | `651d8efabd091811fbf11b78e80793a4acb02b3c2eec95260373c58636d774b5` |

Both raw ELFs and their official program containers are retained here, together
with the exact input and journal. The original relation implementation is retained as
[baseline-full_relation.rs](baseline-full_relation.rs), exactly from commit
`576b3864256b61e8b5c27255f06b22ff7029dc84`. The initial guest harness was still
uncommitted and did not receive the complete 19-file build snapshot used later.
The baseline can be re-executed from its fixed program binary; a byte-identical
rebuild of its entire original harness is not claimed. The optimized execution/proof attempt
started from that HEAD with an explicitly dirty working tree. It was subsequently
committed as `9e9939b2d9ac97c7172ef141c9920225d2516236`. All 19 captured runtime
source-file hashes match that later commit exactly; see
[the correspondence record](runtime-source-to-commit.json). The later commit was
**not** the HEAD at the beginning of the run. The same complete tree is now
available as [the immutable observed-source commit](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/5c8cd8bd59cd9d8197617239664e66dd8b086baa),
with tree `fb4ec104a54451829f666cfba752083118f19f58`.

The [original runtime snapshot](w1-local-prover-source.json) and
[original embedded manifest](backend-manifest.local-prove.json) are retained
unchanged, including their then-uncommitted source marker and historical upstream
98-bit claim. Later metadata corrections do not retroactively change either
record or turn that claim into a measured security result.

## Measured execution, before proof acceptance

| Same fixed input | Guest user cycles | Segments | Segment limit | Executor wall time |
| --- | ---: | ---: | ---: | ---: |
| Integer-remainder baseline | 129,931,331 | 1,396 | 2^17 | 4.338421073 s |
| Exact folded reduction and byte-identical SHA-256 batching | 13,364,385 | 62 | 2^18 | 0.433733896 s |

These are actual executions, not cryptographic proof measurements. The two
segment limits differ because the original implementation was measured before
the exact arithmetic optimization. Cycle counts, execution times and segment
counts must therefore be kept distinct. Native differential controls cover the
full 70-bit reduction boundary and compare the original three native kernels;
the public journal remains byte-identical.

The successful optimized guest build, host build and six receipt-boundary tests
have their raw output and process records here. The failed first optimized build
(`w1-folded-build.*`, missing the compiler's required linker component) is also
retained. It must not be confused with the successful later
`guest-build-folded.*` observation.

## Proof, cost and security interpretation

**Actual local outcome: timeout, no completed receipt.** The proof process ran
from 09:20:13.228636 to 09:50:13.236978 UTC, lasting 1,800.008296722 seconds,
and returned 124 at its original cap. No receipt, independent proof-verification
time, proof size or late-seal rejection time was obtained locally. Those values
must remain unmeasured until an actual successful independent run provides them.
See [the unchanged process record](prove-folded.process.json) and raw stdout/stderr.

The external prover had consumed at least 3,353.82 seconds of user CPU and 11.78
seconds of system CPU at the direct 09:48:43.917913 UTC sample; its then-observed
high-water RSS was 2,421,596 KiB. These are observations before timeout, not final
whole-run totals. Terminating the process group prevented the host from reaping
its prover child, so the wrapper's `RUSAGE_CHILDREN` numbers omit that child.
The wrapper's 0.032417 seconds of user CPU and 16,512 KiB must **not** be reported
as the cost of the real prover. The separate
[live process samples](prove-folded.live-resource-samples.jsonl) preserve this
distinction. The shared cgroup recorded no OOM kill during this attempt.

The local proof attempt used an explicit 1,800-second cap and the exact
optimized image, a real local RISC Zero 3.0.6 prover, Composite receipts,
Poseidon2 commitments, and no development or elliptic-curve wrapper receipt.
The workflow's larger 5,400-second attempt is a separate run, not an extension
or replacement of the local record. Each run must retain its actual status.

### Same-input native measurements

The official Rust 1.95 release build ran four implementations sequentially,
31 actual calls per implementation, for 124 calls in total. This is not a
four-core parallel benchmark. All 31 raw samples per implementation are retained
in `native-benchmark.stdout.log`.

| Implementation | Minimum | Median | Maximum |
| --- | ---: | ---: | ---: |
| Existing production verifier | 0.524881 ms | 0.616760 ms | 1.101550 ms |
| Independent scalar reference | 0.530890 ms | 0.962600 ms | 3.559685 ms |
| Existing limb verifier | 0.456077 ms | 0.661677 ms | 2.805478 ms |
| Complete guest relation, native execution | 0.520905 ms | 0.623800 ms | 1.699402 ms |

The full benchmark process, including all four sequential groups, startup and
output, took 0.115105698 seconds wall time and 0.108847 seconds user CPU. The
separate one-call complete-relation body took 0.696500 ms and produced exactly
the guest's 228-byte journal. Its whole process took 4.219910 ms; process-level
CPU tick accounting is too coarse to isolate that sub-millisecond call.

For this input and machine, a production native median of 0.616760 ms beside a
real proof that did not finish in 1,800 seconds demonstrates the very high honest
proving latency of this VM candidate. It says nothing yet about an actual proof's
verification latency. No throughput gain, per-peer fair service, or cheap
worst-case proof rejection follows from the faster guest execution.

### What a completed proof would establish

A proof only counts after independent verification of the pinned image and the
complete expected journal. The caller still establishes the authorized parent,
task, target and network context. SHA-256 in W1 is separate from Poseidon2 in the
proof system. The upstream README, pinned calculator comments and current 3.0
security table quote differently scoped 98, 97/95 and 96-bit values; none is a
PQ128 qualification. Actual segment dimensions must be evaluated by the pinned
upstream formulas, with their conjectures, degree assumption and composition
limits reported explicitly.

The required cost comparison includes native verification, guest execution,
real proving, independent proof verification and invalid-proof rejection on the
same input. In particular, reusing a valid proof and changing a late seal is a
cheap attacker action. Its rejection cost cannot be compared with a hypothetical
attacker generating a fresh honest proof every time. Standalone parser bounds
also do not establish Node-wide fair service or a globally affordable budget.

All timings are observations under a shared host's load. The resource record
states the cgroup and concurrency settings and does not label a per-child maximum
RSS as a total cgroup peak. Raw failed and successful results remain authoritative;
the presence of source, a built guest, an execution or a workflow is not a claim
that a proof succeeded.

## Executed parameter-model calculation

The final executor reported **62 segments, each with po2=18**. The calculator
used that actual execution observation; no completed receipt was available
locally. Its report is explicitly `execution_only_metadata`. The original
upstream Rust formulas, seven hash-pinned source/license files, descriptor
harness, compiler output and numerical stdout are retained in
[soundness-profile](soundness-profile/soundness-observation.json). The harness
supplies only field and tap descriptors and does not implement a proof backend.

The inputs are BabyBear prime 2,013,265,921, extension degree 4, 50 FRI queries,
expansion 4, folding factor 16, final degree 256, tap widths 103/1/211 and maximum
combo size 6. The constraint degree 5 is the upstream calculator's hardcoded
assumption with a FIXME, not an independently proved AIR degree here. The field
is the proof-system field, separate from W1's q=4,294,967,291.

The following are the upstream **conditional numerical estimates**, in bits.
The proven-list-decoding column is a bound from that analysis; it does not
identify an attack with that computational cost. All three columns retain their
respective assumptions, and upstream f32 arithmetic is not a machine-checked
real-number bound.

| Allowed po2 | Toy conjecture | Proven list-decoding model | Strict conjecture |
| ---: | ---: | ---: | ---: |
| 13 | 99.93122 | 47.77387 | 85.05716 |
| 14 | 99.86557 | 47.75474 | 84.17544 |
| 15 | 99.74261 | 47.68069 | 83.08546 |
| 16 | 99.52425 | 47.41750 | 81.78512 |
| 17 | 99.16709 | 46.68021 | 80.27840 |
| 18 | 98.64242 | 45.30140 | 78.59309 |
| 19 | 97.95557 | 43.50985 | 76.77656 |
| 20 | 97.14198 | 41.56704 | 74.87678 |

For the actually executed 62 x 2^18 segmentation, summing the 62 conditional
segment error estimates yields respectively **92.68822, 39.34720 and 72.63889
bits**. This union calculation does not itself establish the adaptive
Fiat-Shamir, hash, QROM or cross-receipt multi-target argument.

The standalone host accepts po2=13..20, at most 2,048 segments, at most
268,435,456 padded cycles and at most 134,217,728 certificate bytes. To avoid
reporting only the honest example, the script also evaluates a conservative
superset: minimum per-segment estimate over the allowed dimensions, minus
log2(2,048). This gives **86.14198, 30.56704 and 63.87678 bits**, respectively.
It deliberately ignores the joint cycle and byte constraints. The combination
behind this looser estimate need not be feasible, and it is not an attack claim.

For the separate out-of-profile po2=24 reference, the actual toy formula gives
93.34174, while the pinned source comment says 95. The parameter-specific
calculation must therefore be reported independently of that comment and the
README/official-table headlines. No value in this section is a quantum-security
bit estimate or a PQ128 qualification.

## Final local validation scope

The final unchanged guest relation passed 11 selected native differential
controls under Rust 1.95 release. The final standalone host passed all six
receipt-boundary tests and strict all-target Clippy for both host and relation
crates. The stdout result reader passed five explicit positive/negative controls,
including missing and duplicate target-schema lines. The current manifest's
eight guest-source hashes matched their actual files. The actual baked program
passed the image/byte identity checker; the genuine timed-out proof log was
rejected by the full observation checker because it had no proof result.

These parser/source/compilation controls do not replace the pending actual
positive receipt and its 16 adversarial verification controls. The profile
remains **unqualified for production P0 admission and PQ128**. There is no Node
entry point or conversion to `VerifiedWork`.

Captured stdout is retained byte for byte, including Cargo's trailing blank
lines. Only those data files have local whitespace-diff attributes; source
formatting, compilation and all security checks remain active.
