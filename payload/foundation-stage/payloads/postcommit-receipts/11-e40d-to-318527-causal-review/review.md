# Original e40d confirmation failures and current runtime review

## Result and scope

The current candidate already includes a concrete reactor scheduling improvement and reviewed receiver changes. The preserved e40d observations do not establish that the current candidate passes the original confirmation target. This review found no further demonstrated, minimal source repair that can be recommended now while preserving all existing resource and verification checks. No Host execution, test, source edit or Git-object/ref write was performed.

The reviewed current source is `318527b4b2a07b5037d755547acd92e46ae3aded`, tree `91d6b1a45fc759ddf9cbc61f795a65d02d699fde`. The failing source is `e40d7071c4724e6600deef8a2820bf35c1982289`. The source identity table and full seven-path diff accompany this note. Five further relevant files are byte-identical. This is a bounded causal review of those paths and reached functions.

## What actually failed

Both cross-architecture jobs completed all five named native processes without timeout and passed service/sustained report acceptance. The subsequent confirmation report was correctly refused with `CONFIRMATION_TARGET`. The native test asserts safety/accounting invariants and separately writes the finite business result; its exit zero is not a confirmation-target pass.

| Original observation | arm64 | x64 |
| --- | ---: | ---: |
| Baseline confirmation latency | 1.796814117 s | 3.097787607 s |
| Pressure business start | 0.074572312 s | 0.096785765 s |
| Last of seven Submit ACKs | 1.169734494 s | 1.595749013 s |
| Successful History responses | 7 | 3 |
| Complete independent replays | 6 | 2 |
| Final replay start | 3.970797023 s | 3.801778450 s |
| Original window remaining at that start | 29.202977 ms | 198.221550 ms |
| Final replay return | 4.061828790 s | 4.000560367 s |
| Final retained error | PUBLIC_REQUEST_DEADLINE | PUBLIC_REQUEST_DEADLINE |
| Host calls inside final partial Work | 172 | 320 |

Both phases retain the original four-second window and sixteen pressure workers. These are different traces. In particular, the new x64 final replay starts with about 198 ms remaining and enters Work; it is not the earlier 332d prospective trace that started with about 2.5 ms remaining and failed in Context.

An ACK or successful History response is not independent business confirmation. `tests/public_v3_from_zero.rs::signed_confirmation_phase_with_builder` replays each page into an independent Node through `receive_public_page_from_before_observed` with the same absolute `end`. Confirmation additionally requires the real six-deep/work result before that deadline. The complete original confirmation function is unchanged between e40d and the reviewed current source; this test file gained only three separately named SP27 module declarations.

## Measured cost location

Every completed Work in both original reports contains 1,099 actual fresh Host checkpoint calls. In pressured arm64, completed Work uses about 28.3–29.0 ms of calling-thread CPU, while the associated Host intervals record about 26.6–27.3 ms. In pressured x64 the two completed Work spans use 70.975204 and 66.824845 ms, with Host intervals of 67.438088 and 63.597163 ms. The corresponding Host/Work CPU ratios are about 94% and 95%. These are nested measurements; adding them would double count.

The x64 three replay spans last 1.197171009, 0.702459788 and 0.198781917 seconds, but record only 80.804217, 76.706621 and 22.757894 ms of caller CPU. Its first import also records the original roughly 400 ms cold CPU wait. The second import does not repeat that wait. The final partial Work is refused after 320 Host checks. On arm64 the last partial Work is refused after 172 checks.

The reports establish costly repeated fresh Host observations and substantial wall time outside the calling thread's measured CPU. They do not independently identify the cause of each off-CPU interval, a particular syscall's cost, or a filesystem delay. Whole-suite cgroup counters must not be represented as per-replay measurements. The two jobs are not a controlled benchmark of ARM versus x64.

## Current source differences and actual applicability

| Current component | Exact reached behavior | Applicability to this failure |
| --- | --- | --- |
| PublicV3 reactor | Workers use bounded `recv_timeout(1 ms)`; native completion unparks the reactor; only a pass with no real progress parks for up to 1 ms. Existing deadlines, per-pass work and resource checks remain. | A real scheduling improvement is already selected. Historical e40d timing cannot quantify its current benefit or prove the four-second target. |
| r20 authenticated caller grants | At most two active mutation grants per authenticated caller, tied to the same connection/task lease and existing global reservations. | The pressure code rotates caller identities using `80 + ((attempt + worker * 37) % 150)`. A per-caller cap is not a new aggregate CPU allowance or a reduction of sixteen workers. This review does not infer grant concurrency solely from client-call intervals. |
| Host parent reader | Fresh parent descriptor per check; NOFOLLOW/NONBLOCK, regular-file validation, complete bounded reads, current boot/membership and all five limits, and final path identity fence. Scoped descriptors are local to one check/sample. | These are ownership/security refinements. They do not remove the 1,099 W1 checkpoint boundaries or cache their dynamic result. |
| Negative W1 cache | Current cheap statement checks precede optional proof hashing; a miss reuses only this invocation's checked inputs, preserving native error ordering. | May affect receiver rejection costs. Independent valid History replay directly calls the full W1 verifier and does not take this negative-cache path. |
| Node state/confirmation | Lazy reverse-path storage avoids an unnecessary temporary file; confirmation adds chainwork/storage-epoch integrity checks. | Already selected; neither establishes that a partially replayed independent chain is confirmed. |
| PQ CheckedConfig, ML-DSA expansion cache, research task-product/strategy helpers | Separate account/PQ or explicitly selected research paths. | The original confirmation uses classic development Settings and a 64-byte signed Envelope. No evidence places these optimizations on the observed independent W1 bottleneck. |

The actual independent replay chain at the reviewed source is:

1. `tests/public_v3_from_zero.rs::signed_confirmation_phase_with_builder` passes the unchanged absolute deadline to `receive_public_page_from_before_observed`.
2. `ingress/history_import.rs::verify_history_work` calls `WorkCheckedPacket::verify_with_progress`, invoking `history_checkpoint` with the original fresh resource check at every native W1 boundary and throughout refill waits.
3. `store.rs::WorkCheckedPacket::verify_with_progress` calls `pon_work::verify_with_progress` directly. It does not select `verify_with_rejection_cache_observed`.
4. `host_kernel_parent.rs::KernelBudget::checked_parent` reopens the actual parent, reads current boot/membership and limits, and fences the final identity. `Control::check` also retains deadline checks before and after that observation.

`ingress.rs`, the History importer, its observation and attribution modules, and `public_v3/scalar_cpu.rs` have identical Git blobs at e40d and 318527. Existing comments and code already remove a second adjacent Host observation where there was no intervening native work; that is not a new available optimization.

## Why no further patch is recommended from these records

The current hot reader already uses borrowed iterator parsing, stack buffers for ordinary small files, relative opens under a fresh per-call directory, and a same-stream fallback for long context input. There is no remaining demonstrated repeated heap parser or duplicate adjacent Host check in the reviewed path to remove.

Reusing current Host contents or descriptors across calls, reducing native checkpoint frequency, dropping EOF/regular-file/identity checks, changing cold-start credit, or granting priority before full native verification would change selected contracts. No such change is proposed. Replacing independent replay with a server response, extending the window, reducing workers, changing packets or relaxing acceptance is also outside the result.

The next acceptance evidence must come from the unchanged exact-head/prospective gate on the actual candidate. If it still fails, its current original report can determine whether the selected reactor improvement changed network delays and whether the Host observation cost remains dominant. Further optimization would need a specific repeated computation or syscall with a demonstrated safe equivalence and measured benefit; these older receipts alone do not supply that proof.

## Evidence

`causal-summary.json` preserves the extracted per-page source observations. `source-identities.json` records all twelve old/current paths, blob IDs, sizes and SHA256 values; `source-differences.patch` preserves the exact seven changed paths. `EVIDENCE_INDEX.json` binds these outputs and the original report/diagnosis hashes. Original raw inputs are referenced without replacement. The later root metadata-only checkpoint is recorded separately if its Rust subtree is confirmed unchanged.

All outcomes remain local observations. This review grants no production, consensus, fairness, throughput or work-profile qualification.
