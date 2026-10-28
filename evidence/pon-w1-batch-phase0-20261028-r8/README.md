# W1 batch Phase0: three failed builds retained

**Status: build blocked; no batch image, guest execution, receipt verification,
or proof generation.** These records do not close the complete-W1 benefit gate.
The existing complete leaf proof remains one independently identified work.

The build source was clean commit
`b3f3fa57a4ed928a1eae61a97aecc4a9d90df467`, tree
`ffe37b67fa03820053214879c619b730d518d6c7`. Every attempt checked the same
committed source and independent locks before starting. The current packet is
later evidence about that source; its own eventual commit is not the build
source identity.

## Results and costs

| Attempt | Outcome | Wall seconds | Wait4 child CPU seconds | Peak sampled RSS bytes | Target growth bytes |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Sandbox refused the exact official dependency download | 1.564830 | 1.237808 | 31,526,912 | 0 |
| 2 | Compiler restored; nested SDK Cargo lost the intended cache and offline environment | 27.565342 | 16.077483 | 353,595,392 | 19,316,736 |
| 3 | Offline/cache/jobs wrapper worked; guest compiler rejected incompatible locked dependency MSRVs | 2.567531 | 1.920560 | 123,351,040 | 0 |

The build attempts sum to **31.697702 wall seconds and 19.235851 child CPU
seconds**. The separately approved checksum-bound dependency download used
0.108437 wall seconds and 0.045629 process CPU seconds. The read-only compiler
adoption check used 0.657004 wall seconds and 0.609292 process CPU seconds.
See [cumulative-ledger.json](cumulative-ledger.json) for unrounded values.
These measurements exclude the supervisor's own CPU, source-inspection and
development time, and the earlier original complete-leaf proof generation.
They are not end-to-end prover or verifier costs.

All attempts ended with no remaining owned processes and no supervisor errors.
The additional attempt3 host-PID/birth readback also found no surviving process.
Every failure is retained; no old deadline was extended and no attempt was
silently restarted with fresh credits. Each new attempt required a separately
declared budget and rationale.

## Attempt 1 and exact dependency restoration

[attempt1](attempt1/result.json) ended before restoration or compilation. The
failure was an operating-system permission error on a sandboxed network request,
not a rejection by automatic approval review.

The subsequent [download receipt](dependency-download/result.json) records the
explicitly approved official URL:

`https://static.crates.io/crates/risc0-build/risc0-build-3.0.6.crate`

It fetched 27,207 bytes under a 2 MiB bound and verified SHA-256
`bd8216cdd9f573808a94769767480b06ad1e74ae60841c9582fdf51b8e29ba53`
before placing the archive in the existing Cargo cache. The download script did
not execute Rust, a guest, or a prover.

## Attempt 2 and authenticated compiler adoption

[attempt2](attempt2/result.json) restored the retained official RISC0 Rust
1.88.0 compiler archive exactly once after checking its 490,849,318-byte size
and SHA-256
`222651797ba58f0bafd959191a48d23b35b3266d9e082fc49fb4d84733064fce`.
The extraction used the Python tar data filter. Native and guest version
commands passed. The build compiled `risc0-build 3.0.6` and the batch methods
build script, then failed when nested Cargo tried to obtain dependencies from
the default cache/network configuration.

The upstream SDK's `sanitized_cmd("cargo")` removes all `CARGO*` environment
variables. That also removes the intentionally selected `CARGO_HOME`, offline
mode, single-job bound, and disabled incremental compilation. The SDK source
was inspected and checked against its checksum-bound crate archive; it was not
patched.

Before attempt3, [the adoption check](attempt3-toolchain-adoption.json) hashed
both the original archive's `./bin/rustc` member and the already-restored
binary. Both were
`895b46e3d37c2265aa6069dd0976918b7dbc55279fbcb397f12e790f56ea959c`.
The compiler was not restored or overwritten again.

## Attempt 3: wrapper confirmed, MSRV refusal retained

The separately reviewed [Cargo wrapper](scripts/attempt3-cargo-wrapper.py)
restored exactly four intended values:

- `CARGO_HOME=/tmp/pure-pon-cargo-20261027`
- `CARGO_NET_OFFLINE=true`
- `CARGO_BUILD_JOBS=1`
- `CARGO_INCREMENTAL=0`

It checked and directly executed the fixed absolute Cargo binary with unchanged
arguments. It preserved `HOME`, the SDK-selected guest `RUSTC`, encoded compiler
flags, and all other environment entries. It neither changed the SDK nor
disabled version checks. The [actual invocation](attempt3/cargo-wrapper.jsonl)
records the wrapper and Cargo hashes, exact argument vector, and all four
restorations. [Static review](attempt3-static-review.json) is labeled source
inspection and AST parsing; it does not claim a Rust or cryptographic test.

The [compiler's raw refusal archive](../pon-r8-evidence-transport-20261028/original-records.zip) then identified:

| Locked package | Version | Required Rust | Official guest Rust |
| --- | --- | --- | --- |
| `enum-ordinalize` | 4.4.2 | 1.89 | 1.88.0-dev |
| `enum-ordinalize-derive` | 4.4.2 | 1.89 | 1.88.0-dev |
| `ruint` | 1.21.1 | 1.90 | 1.88.0-dev |

The refusal is retained as a failed build, with no `--ignore-rust-version` or
other compatibility bypass. Both lockfiles and the source stayed unchanged.

[Read-only diagnosis](attempt3/msrv-diagnosis.json) identifies already-cached
compatible candidates used by the original full-W1 guest: `ruint 1.15.0`
(declared Rust 1.65), `enum-ordinalize 4.3.0` and its derive crate `4.3.0`
(declared Rust 1.60). They satisfy the current upstream semver requirements.
This diagnosis has not changed a lock, run Cargo's resolver, or shown a successful
build. An exact guest-only lock update, retained resolver delta, and a separately
authorized new build would still be required. Native SDK 3.0.6 and the frozen
complete leaf image must stay pinned.

## Supervisor identity and limits

The three builds used [guard9981c3.py](scripts/guard9981c3.py), SHA-256
`9981c3a138c4aefb6c4662f1e2c4c05cf5ef26e302c46763a42a2366a6334217`.
Each attempt declared at most 900 wall seconds, 3,600 child CPU seconds,
2.5 GiB aggregate sampled RSS, 768 MiB target growth, and a 1 GiB free-disk
floor. GNU `timeout` provided an independent wall limit. CPU, RSS and disk
limits are sampled stop triggers rather than kernel cgroup hard limits.

The supervisor maps `/proc` host identities to its actual PID namespace through
`NSpid`, validates birth and namespace identities, and signals through pidfds.
It does not assume that `Popen.pid` names the same process under `/proc`.
It tracks reaped subtree CPU and checks wait4 peak RSS in addition to live
samples. Final controls cover normal completion, a detached child surviving its
leader and ignoring TERM, and a short RSS spike caught by wait4. A real existing
target scan control is also retained. Earlier controls, including the original
namespace-mapping failure, are preserved rather than discarded.

Supervisor success means that a command was observed and cleaned up under its
declared limits. It does not imply that the command built valid source, produced
a valid cryptographic proof, or met a throughput objective.

## Remaining gates

No new proof denominator exists. The sole existing complete W1 receipt has one
work ID and may not be repeated to claim multiple useful works. A successful
one-leaf composition pilot would only calibrate functionality and cost. It
would not close the practical benefit gate or replace the distinct-work
experiment described in the [experiment contract](../../formal/pon-nakamoto-v1/w1_batch/EXPERIMENT_CONTRACT.md).

The proposed staged pilot must preserve a genuinely conditional cryptographic
receipt, demonstrate that final `.verify(compiled_batch_image)` rejects its
unresolved assumptions, then resolve against the existing verified full leaf
and require unconditional verification. No claim-only leaf, omitted relation,
extra consensus weight, or unmeasured parent/task-window/M06/authorization
cost is permitted. That pilot has not run.
