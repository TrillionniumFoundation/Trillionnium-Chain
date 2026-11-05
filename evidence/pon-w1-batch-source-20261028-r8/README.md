# W1 batch source review, 2026-10-28 round 8

**This packet records source-only work. No new batch image, guest execution,
STARK verification or proof generation occurred in this packet.** The original
single-work proof remains valid and its practical-benefit result remains FAIL.
The new batch proposal remains UNMEASURED. One cached valid work is one work.

The isolated implementation and detailed follow-on budget are in the
[batch workspace](../../formal/pon-nakamoto-v1/w1_batch/README.md),
[execution contract](../../formal/pon-nakamoto-v1/w1_batch/EXPERIMENT_CONTRACT.md),
and [external-gate review](../../formal/pon-nakamoto-v1/w1_batch/EXTERNAL_GATES_REVIEW.md).
No production crate, consensus rule, sole development plan or global CI file
was changed by this branch. The source base is
`189ba3adfd9a22c7cfc1537eab535e9eb7c442df`.

## Actual source-only observations

[static-review/result.json](static-review/result.json) retains exact command
arguments, output hashes, file hashes, elapsed time and statuses:

| Check actually executed | Result |
| --- | --- |
| Independent Python public-byte/source-pin controls | 12 passed; no STARK verification |
| Rust formatting/parser check | Passed; not Rust compilation |
| Host Cargo metadata, offline/locked/no-deps | Passed |
| Guest Cargo metadata, offline/locked/no-deps | Passed |
| Local Markdown link targets in new workspace | No missing targets |
| Host or guest Rust compilation/tests/Clippy | NOT RUN |
| Guest execution, actual assumptions resolution, independent batch verifier | NOT RUN |
| New complete leaf proofs / production activation | 0 / false |

Every raw stdout and stderr is retained beside that result. The independent
controls preserve all original public journal bytes, reject repeated original
work identity (including 32 repeated receipts), and check count/domain/length/
range/header/ticket/order/identity. Synthetic different public headers are
explicitly unproven parser fixtures; they do not supply additional work.

The arithmetic screen reports 31 distinct works as a hypothetical CPU crossover
and 8 as a hypothetical byte crossover using the existing single-proof costs.
It labels final aggregation cost as assumed and unmeasured. It does not count
one repeated work 31 times, establish independent prover trials, or pass 2A.

## Independent locks and retained first failure

| Lock | Packages | SHA-256 |
| --- | ---: | --- |
| Host workspace | 279 | `32953cbb86bb56186137507ee9e9bf59827bd8325c6e28c12b40d5c166fbfa4d` |
| Guest workspace | 155 | `018423c898d09d0be7a7fbe207e4a1672c5b6f36202dda765a81da852c044d18` |

An initial attempt to pin the methods builder to 3.0.3 while using the hardened
3.0.6 client failed dependency resolution. The
[exact returned failure](initial-lock-resolution-failure.json) was copied from
the original tool return with return code 101; it was not rerun or relabelled
as success. All new SDK and builder pins were changed to 3.0.6, then both lock
resolutions succeeded offline. Only `risc0-build` 3.0.6 is absent from the
existing registry archive cache. It was not downloaded here. Successful
metadata/lock resolution does not mean that compilation has succeeded.

## Resource and external dependencies

The existing W1 target was inspected read-only. No new full target was created.
The guest compiler had already been reclaimed; its preserved original
[reclaim result](prior-compiler-result.json),
[declaration](prior-compiler-declaration.json), and
[restore observation](prior-compiler-original-restoration.json) are retained
byte for byte. No restoration was performed in this packet. The compiler
archive and original full proof/backend/binaries remain the existing assets.

[external-gates-readback.json](external-gates-readback.json) records the exact
scoped WAN search, hashes of four earlier multi-host reports and their explicit
independence declarations. It found only the existing preregistration contract,
reader and synthetic tests; no actual independent campaign manifest or operator
attestation was found in the inspected trees. All four earlier reports deny
independence. WAN remains **NOT_RUN / HOLD_NO_GO**. No endpoints, credentials,
login sessions or people were probed or contacted.

The quantum review records the missing concrete W1 cost lower bound, a
conditional sublinear-cost counterexample family, a bounded counterexample
search design, primary-source references and required reversible-circuit/
fault-tolerant resource evidence. It performs no quantum attack and does not
replace those obligations with an arithmetic simulation.
