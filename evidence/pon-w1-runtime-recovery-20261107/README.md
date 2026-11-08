# W1 funded generation and publication runtime continuation

This is a research implementation and observation record. It does not authorize
block admission, deploy a service, certify the original business budget, or
establish whole-system cryptographic security. The sole development plan remains
the [Chain development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

The recovered source baseline is commit
`b6c730c2a81b932266c9a8b93858e2641aafd9f7`, tree
`fa394c0870287c1e3a4408589a1e3b7677690b7f`. The separately reported old C1
candidate and its raw newly generated receipt were not recovered. Its reported
timings are not new observations of this continuation. No missing sequential
terminal result is inferred from its elapsed time.

## Four separate engineering gates

| Gate | Implemented or actually observed here | Qualification still required |
| --- | --- | --- |
| Actual winner and receiver | Existing full native `pon_work::prove` nonce search; timestamp at the actual ticket predicate; independent native replay; fixed input/header/external A/B commitments; original Linux monotonic deadline and boot; actual complete-receipt verification and cancellation controls | A fresh completed remote winner-to-receiver trial, complete process/resource ownership, and independent Node admission |
| Complete backend under matched resources | Bounded parallel segments, sequential/balanced recursion, explicit worker and Rayon plans, all-worker drain, complete claim continuity and strict seals; exact retained v2 guest build; 22 backend controls | Actual new complete generations and a matched sequential terminal observation; a finite sample does not establish population tail latency |
| Funded asynchronous execution | New GenerationV2 journal and persistent task fence; real existing NativeTask funding owner; M12 holds/effects; real POSIX target and normal Kaggle account wrapper interfaces; cold Pending reconciliation and ordinary once-only payment controls | Actual expensive generation through that owner; complete GPU/resource accounting; cross-V1 global service exclusivity and production live-chain qualification |
| Benefit and security | New forty-row ABBA using one complete historical v2 receipt, one native replay per A, one full independent proof verification per B; expected-artifacts remains independently bound | Verification and transmission benefit, original business budget, complete cryptographic/security conditions and production acceptance |

The gate values and raw-observation identities are recorded separately in
[observations.json](observations.json). A source check or short test cannot
change a missing full proof trial into a completed one.

## Actual ABBA result

The sequence is ten repetitions of A-B-B-A, twenty observations per arm, in one
bounded Hepta job requesting 200% CPU and 8 GiB, with `RAYON_NUM_THREADS=2`.
It uses the actual release independent verifier, fixed SDK 3.0.6 profile and
the same input, independent header and 64-byte external commitments throughout.
The host was not reserved exclusively; no business-resource equivalence is
claimed. The forty raw rows, immutable intent and result are in
[receiver-abba](receiver-abba/result.json).

| Measurement | Native full replay | Complete receipt verification |
| --- | ---: | ---: |
| Inner median | 2.5871055 ms | 34.7207115 ms |
| Inner descriptive p95, nearest rank | 2.752356 ms | 37.913853 ms |
| Inner descriptive p99, nearest rank | 2.801919 ms | 38.062633 ms |
| `wait4` CPU median | 5.065 ms | 39.011 ms |
| Observed supervisor/process outer median | 299.834858 ms | 301.745680 ms |

The proof/native inner-median ratio is **13.420678631**. The raw receipt is
257,014 bytes and the complete native input is 49,506 bytes: **5.191572739**
times as many bytes. These are raw payload sizes, not a complete network-envelope
or bandwidth experiment. Neither verification nor raw-payload benefit passed.

The outer process observation includes supervision and polling. Its approximately
0.30-second floor must not be interpreted as the verifier kernel's execution
time or as evidence that two very different inner costs are equivalent. All
p95/p99 entries above describe these repeated verifier calls on this fixed claim;
they are not proof-generation, WAN, admission or population tail estimates.

The historical receipt SHA256 is
`6c72828c9d05a62175e08fa3e7e1d0d5e85e785ad96b5beb5ec7a2e2490c26ee`.
The release verifier SHA256 for this observation is
`582b53d8607cca6ec228c18de8047e1d6564f0fd9cd3cdeafa06c66f460ad3d5`.
The original full-v2 evidence, its independent expected-artifacts selection and
the old 6,248.484106799-second fresh pipeline remain unchanged in
[the historical record](../pon-w1-full-v2-20261105/README.md).
That old pipeline duration is not a measured native-winner-to-WAN-publication clock.

## Actual receiver controls and cancellation boundary

[The real receiver control record](receiver-controls/summary.json) uses the actual
complete historical v2 receipt and actual independent release verifier. All seven
controls passed without skips: valid verification, corrupted receipt, wrong
independent artifacts, expired original deadline, actual post-ACK SIGTERM,
post-ACK SIGTERM with a real sidecar I/O collision, and actual cancellation after
the final ABBA row was persisted. A saved verified fact and an eligible completed
operation are separate records. Cancellation can retain the fact while vetoing
success, admission and payment.

The independent review also identified a nested cleanup window: equally sized
outer and inner TERM grace periods could let the outer observer kill the inner
controller before it killed a backend in a different session. An explicit outer
cleanup budget and an actual nested-session refusal control address that window;
cleanup time never extends proof eligibility. The funded local target additionally
inherits an owned child cgroup across `setsid`, and the outer resource owner checks
all descendant cgroups. A process-group sample alone is not complete resource
ownership. Unknown cleanup or usage retains the corresponding hold.

The original winner's raw intent and raw result, not merely a subsequently
self-consistent replacement record, must remain identical at the final handoff.
The receiving process independently verifies the raw succinct receipt against
the independently selected header and external A/B hashes. No receipt-shaped
JSON, provider `COMPLETE`, or successful transport substitutes for that verifier.

## Funded generation interface

The heavy research entry is explicitly selected from the real Node test ELF:

```text
store::async_w1_generation_v2::tests::heavy::funded_fresh_full_w1_generation
--exact --ignored --test-threads=1 --nocapture
```

It reads one immutable `TRNM_W1_FUNDED_CONFIG` declaration outside the source
tree, verifies the clean source and actual executable/file pins, observes a real
native winner, and binds the original deadline before expensive generation.
NativeTask V1 and its signed tags are unchanged. GenerationV2 uses a new stored
namespace and hashes, with a task fence next to the Node database; creating a
different generation journal cannot redispatch the same already fenced task.
Pending recovery observes the original effect and operation; it does not submit
a replacement provider request or award another entitlement.

The isolated research Node reserves 1,000 units with height deadline 20. It does
not automatically advance production blocks during proving. Therefore this
fixture does not establish that twenty live-chain heights can accommodate a
long proof. The current complete GPU usage observation is unknown, represented
as `null`, not zero. Even a strictly verified full proof therefore retains a
funded Pending state until all required owner/resource conditions are qualified.
Short real NativeTask payment controls and a paid expensive full generation are
different evidence categories.

## Retained guest and provider observations

The explicit `retained-v2-guest` build mode uses the actual 375,928-byte R0BF
ProgramBinary in the historical full-v2 record. It checks both SHA256
`25718312ec3c6f5219d832e3516adfb5f82983156f669c5e7daa15bd22d1798f`
and SDK-derived image ID. This is not a fresh guest compilation, an empty
`RISC0_SKIP_BUILD` substitute, a new guest image, or DevMode. Ordinary default
guest compilation remains available under its original requirements.

The normal Hepta Kaggle channel completed a real T4 resource probe. It observed
two 15,360-MiB Tesla T4 devices, four CPU-affinity entries, `cpu.max` of
`400000 100000` and a 32,212,254,720-byte memory limit. Actual CUDA allocation and
host/device roundtrip operations succeeded. The verified downloaded probe and
its provider artifact manifest are retained under [provider](provider/README.md).
Provider-list sizes conflicted with HTTP/body sizes; those warnings are retained.
The valid body lengths and hashes do not establish exclusive task resource ownership.

Official fixed v3.0.3 release sources show that the Linux bundled `r0vm` is built
without the CUDA feature. Allocating a T4 does not turn that binary into a CUDA
prover. The separately prepared CUDA build-only experiment keeps a new candidate
identity and does not replace the existing CPU pin. Its normal submission was
rejected by `NOTEBOOK_LIST_SCOPE`; the original request reconciled as
`REJECTED / NOT_SENT`, with `remote_effect_unknown=false`. No CUDA build or W1
proof ran for that request. No account guard or credential scope was changed.

The Colab attempt encountered its existing fixed-profile destination conflict
and a guarded release refusal. A later normal reconciliation reported
`FIXED_RUNTIME_NOT_FOUND`. This is retained as an observation, not relabelled as
a successful controlled release or as a completed proof job.

## Validation and retained failures

The curated [validation record](validation/README.md) preserves raw commands,
exit status, source identities, and unsuccessful observations. Observed component
checks include the 240 native all-target/all-feature tests, two independent
verifier tests, 22 staged backend tests, ten M12 GenerationV2 tests, six real Node
integration controls, and the explicit heavy test remaining ignored in ordinary
test selection. Counts from overlapping or repeated invocations are not added
to manufacture an independent population.

The first all-target native Clippy attempt used system OpenSSL 3.0.13 and failed
at the existing optional PQ adapter's unavailable API. The unchanged repository
preparation script built pinned OpenSSL 3.5.9 in an isolated directory and passed
real ML-DSA-65 sign/verify/wrong-message smoke. Strict Clippy and all 240 native
tests then passed. No system OpenSSL or PQ test threshold was changed.

Other retained failures include the initial backend lock-edge mismatch, original
Clippy findings, cancellation-fixture fsync timing failures, CI duplicate-lane
negative controls, the stale current inline source pin, and provider guard
refusals. Corrected runs have their own records; failures are not overwritten.

Original business limits, adversarial pressure, confirmations, full AIR and
recursion assumptions, Fiat-Shamir/QROM bounds, complete encoding/compiler
semantics, adversarial preprocessing and hardware advantages, whole-chain PQ,
data availability and useful model-work qualifications remain independent gates.
No activation flag is changed by this continuation.
