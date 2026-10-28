# W1 batch Phase0 attempt5: real build, no proof execution

**The complete batch guest and host compiled successfully. No batch guest,
receipt verification or prover was executed.** Compilation closes the current
build blocker; the composition and practical-benefit gates remain unpassed.

## Frozen source and artifacts

The actual compiled source is commit
`401096e8f9eed84fcb4d78122a49fa5dd3aa88e9`, tree
`db0908a57db7675b22485c6ad712c8e19e4f38fa`. The raw
[source-before](attempt5/source-before.stdout) and
[source-after](attempt5/source-after.stdout) checks verified its tracked bytes.
The later evidence commit does not claim to be that compiled source commit.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| [Complete batch guest](attempt5/batch-guest.bin) | 308,184 | `734eb42893951b0915f86e4517a231b04279ace8f8d81ca2dd79d6ed95771219` |
| Native host before compression | 39,608,224 | `f077a55e73a18ff054d651aa878c755e16377319e534644f09c1f43cf1adeb19` |
| [Preserved host](attempt5/compiled-host.gz) | 11,496,239 | `fcdb5ccfbeea25b55bb1ba2a4dbb72f55872385d03c34706cabeaa417971da38` |

The host's complete decompression reproduced the original length and SHA-256,
as recorded in the [preservation receipt](attempt5/compiled-host-preservation.json).
The original host remains in the reused target. Neither artifact was executed
during preservation. The [generated methods](attempt5/generated-methods.rs)
bind the batch image to these eight SDK words:

```text
[1000984451, 3139256748, 3364805072, 2363167537,
 26593440, 771198122, 3700220126, 2888495343]
```

This new image is separate from the frozen complete-W1 leaf image. The original
leaf relation, image, work identity rules and existing proof remain unchanged.
The [build result](attempt5/build-result.json) records artifact and source
identities. It does not establish that the new guest executes correctly in the
pinned `r0vm 3.0.3` or that a composition proof verifies.

## One newly authorized, bounded attempt

The [predeclaration](attempt5-predeclaration.json),
[parent approval](attempt5-parent-authorization.json) and
[fresh admission](attempt5-start-admission.json) retain the original limits,
hashes and subsequent CPU-slot release. Three earlier failed builds and the
rejected, unexecuted attempt4 remain preserved. No old deadline was extended.

| Resource | Declared stop threshold | Actual observation |
| --- | ---: | ---: |
| Wall time | 900 s | 140.667001761 s |
| Child-tree CPU | 3,600 s | 138.300131 s |
| Sampled aggregate RSS | 2,684,354,560 B | 645,951,488 B peak |
| `wait4` single-process RSS | Same RSS threshold | 516,853,760 B peak |
| Reused target growth | 805,306,368 B | 371,240,960 B peak |
| Free disk floor | 1,073,741,824 B | 1,624,666,112 B at terminal sample |

Initial available space was 2,009,686,016 bytes. The unchanged namespace-safe
[supervisor result](attempt5/result.json) is `completed`, with command status
zero, no errors and no remaining owned process. A separate
[terminal readback](attempt5/terminal-readback.json) checked all 108 observed
host PID plus birth-time identities and found none alive. It did not equate
namespace-local numeric PIDs with `/proc` PIDs or signal any process. Sampled
stop triggers are not kernel cgroup hard limits.

The [raw build log](attempt5/build.stderr) records successful optimized release
compilation of methods, SDK 3.0.6, statement and host. The full supervised time
also includes source, archive, installed-tree and artifact checks.

## Toolchain and lock boundaries

The [preceding acquisition](../pon-w1-rust1911-acquisition-20261028-r8/README.md)
authenticated and completely installed official `r0.1.91.1`. Attempt5 checked
the exact settings, sole intended compiler, every installed regular-file hash,
complete membership and link containment before and after the build. The SDK
source, native toolchain and official archive also remained pinned.
The [observed nested invocation](attempt5/cargo-wrapper.jsonl) selected exactly
that compiler and `riscv32im-risc0-zkvm-elf`.

The wrapper restored only cache location, offline resolution, one Cargo job and
disabled incremental compilation after SDK sanitization. `HOME`, SDK `RUSTC`,
encoded flags and argument order were preserved. Its difference from the
earlier reviewed wrapper was an attempt label and a new log destination. The
[source review](attempt5-source-review.json) records this and an earlier
static-review parser error; that error did not execute a compiler.

No vulnerable downgrade, ignored MSRV, SDK patch, proof-version override,
download, alternate backend or compiler reinstallation occurred. Both restored
lock hashes remained unchanged:

- Native: `32953cbb86bb56186137507ee9e9bf59827bd8325c6e28c12b40d5c166fbfa4d`.
- Guest: `018423c898d09d0be7a7fbe207e4a1672c5b6f36202dda765a81da852c044d18`.

## Retained cost and next boundary

The [cumulative ledger](cumulative-cost-ledger.json) carries all earlier named
setup costs and failed builds, then adds admission, this full build and artifact
preservation: `199.820062543` measured wall seconds and `175.198563` captured
CPU seconds. Missing supervisor/source-review CPU remains unmeasured, not zero.
Original full-leaf proving cost remains in its separate ledger and must enter
any later end-to-end benefit comparison. This is a build result, not a proof
performance measurement.

The next host-only change must retain the real conditional receipt before
resolve: lift/join only this batch session's segments, check its cryptographic
integrity and complete claim, demonstrate actual final `verify` rejection for
the nonempty assumption, then resolve using the already verified original
leaf and require final `verify` success. An invalid proof or fabricated claim
cannot substitute for that negative control.

A new host source requires a native host rebuild and a new host hash. Guest
source, SDK, toolchain and methods need no semantic change; ordinary Cargo
caching may reuse the guest. The later declaration must detect and charge any
actual rebuild, and require the guest bytes/image to equal this preserved
artifact without using skip-build or version-check overrides. The proof pilot
is separately budgeted and remains unexecuted here. One existing leaf remains
one work identity; it cannot close a 31-distinct-work benefit denominator.
Quantum and independent WAN gates remain open.
