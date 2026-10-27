# Pure PoN work packages — execution and acceptance record

Date: 2026-10-27. **Overall: HOLD / NO_GO.** This record describes implemented
source, actual experiments, discovered regressions and remaining exits. It
does not claim that all seven work packages passed, that the chain is quantum
resistant, or that Hepta has a qualified autonomous product loop.

The [sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
owns the sequence. Pure PoN remains the selected consensus: full verified work
and original cumulative-work fork choice. This execution introduces no stake,
evaluation-vote, BFT, TEE or hash-only consensus alternative. Signature, model
quality and data-availability observations add no chainwork.

## Results against the requested exits

| Package | Implemented and actually observed | Verdict against the requested exit |
| --- | --- | --- |
| **1 — freeze work and security model** | Exact original W1 relation, sole work identity, target-inclusive weight, adversary freedoms and unproved assumptions documented | **Specification frozen.** Work hardness, usefulness and physical quantum cost are not proved |
| **2A — complete succinct W1 proof** | Complete native relation in an actual guest; native equivalence and parser controls; one real local recursive-STARK attempt; all original input, guest and process observations retained | **NO_GO:** 0/1 completed receipts at the original 3,600 s limit; proof size, real crypto-verifier cost and prover tail remain unavailable |
| **2B — History/CPU/out-of-lock work** | Shared History decode/full W1 outside Node mutex, original deadlines/CPU identity, real kill cuts and original finite service campaign; an additional M06 prototype was adversarially reviewed | **PARTIAL / NO_GO:** original exhausted-budget and confirmation exits did not pass; M06 remains a separate blocked prototype, not integrated |
| **2C — quantum PoN and DAA** | Eleven conditional models, pinned ASERT integer vectors, 109,190 retained rows, bounded and extended counterexamples | **Research evidence only:** no native attack packets, QPU run or physical reversible-oracle estimate |
| **3 — PQ native integration** | Versioned TPQ1 wire, real in-process ML-DSA-65 provider, strict context/key checks, isolated pinned provider preparation, actual native crypto tests and owner inventory | **PARTIAL / NO_GO:** native application authorization owners, accounts, migration, reorg/nonces and transport have not all migrated |
| **4 — real Cell/Hepta loop** | Actual three-generation SmolLM training; complete Cell publication; publisher stopped; fresh consumer fetched from replica; real model loaded; actual future comparison | **Explicit NO_UPDATE:** 16/32 versus 16/32, no action improvement. Original Hepta owner CI wiring is a separate candidate; product install/independent acceptance remains open |
| **5 — independent WAN** | Preregistration and complete-denominator reader plus nine synthetic controls | **NOT RUN:** no three independently administered deployments or original 72-hour campaign evidence |

## 1. The frozen work contract is explicit about what it does not prove

[PURE_PON_WORK_SECURITY_MODEL_V1](../../docs/protocol/pon-nakamoto-v1/details/PURE_PON_WORK_SECURITY_MODEL_V1.md)
fixes PNH1/PNW1 framing, the original finite-field/noise/transcript relation,
header-derived challenge, unique block identity and existing work credit. It
enumerates task/header/nonce/time/parent choices, preprocessing, amortization,
structured inputs, specialized hardware, Sybils, networking and quantum-oracle
assumptions. Receipt encodings and signature randomness cannot become extra
logical work identities.

Correct arithmetic and a correct trace do not prove that work was freshly
performed at a specified physical cost, that useful training occurred, or that
a model improved. Those are separate unresolved claims. The new proof code
also remains outside the native Node dependency graph and admission path.

## 2A. Actual proving failed the declared experiment limit

[Complete W1 evidence](../pon-w1-full-proof-20261027/README.md) retains the
single real local attempt and every missing measurement. The prover process
was terminated at **3,600.081 seconds**, after the original 3,600-second limit.
No cryptographic receipt completed. Its last `/proc` sample establishes at
least **7,182.52 CPU seconds** and a single-process lifetime high-water RSS of
**2,478,088,192 bytes**. Direct-host `wait4` omitted the terminated external
prover; that small original rusage is explicitly not treated as total cost.

The same complete saved input passed **1,000 native verifications**, with a
sample median of **0.6938035 ms**, observed nearest-rank p99 of **1.559635 ms**
and maximum of **6.346603 ms**. Valid guest execution consumed **12,693,395 user
cycles in 59 segments**, but guest execution is not proof generation.

A separate code review caught recursive Composite receipt parsing before
the Succinct gate. The successor rejects non-Succinct fixed-int wire tags
before general deserialization; the actual 4,096-level negative control and
wire-bound test passed. Original guest dependency, compiler-wrapper and client
build failures remain retained. No fake/dev/remote receipt substituted for the
timed-out proof. This specific implementation and configuration did not
establish an advantage over complete native verification.

## 2B. Keep the successful local controls separate from the failed service gate

[Original History observations](../pon-native-history-deadline-20261027/README.md)
retain the native source, four real SIGKILL cuts and all **130** original service
attempts. All 32 honest probes and 16 honest mutations completed, and the finite
campaign's maximum honest probe gap including restart was **45.102914 ms**.
That campaign did not establish budget exhaustion.

The original from-zero runner executed all five named Rust tests successfully,
but its complete reader verdict was **FAIL**. Both original confirmation modes
completed zero independent confirmations and retained 32
`PUBLIC_HOST_KERNEL_PARENT` observations. Two sustained hostile phases rejected
471/471 and 460/460 calls; minimum observed stored credit remained about 1.862
and 1.890 CPU seconds, with zero CPU-budget refusals. Those are not saturated
service results.

The original A03 preflight refused this host's actual 8-CPU/8-GiB/nice-0 profile
against the unchanged required 4-CPU/16-GiB/nice-10 profile. The three-run matrix
was not executed. No smaller workload, lowered limit, invented confirmation or
synthetic process replaced that physical gate.

Two inherited tests asserted that a foreign CPU domain did not require stopping
the mismatched caller, contrary to the existing error classification. The
standalone test correction preserves original-listener health, zero foreign
reservations and zero unauthorized W1 work; **both actual native controls
passed**, including two real loopback listeners. It changes no runtime policy.

### M06 prototype remains isolated after adversarial review

The separate M06 experiment prepares a private single-use snapshot, executes
outside the writer mutex and revalidates inside `BEGIN IMMEDIATE`. It preserves
the full existing parent/successor/delta/ancestry/readback checks. It does not
create a second CPU account or let caller-provided results become capabilities.

Review exposed several issues before integration: a local two-second wait did
not cover nested mutex acquisition; a new 8 MiB acceleration cap could reject
previously valid large states; and exact activation replay could be blocked by
the original authenticated request entrance. Their repairs and actual test
results belong to the separate source-bound prototype, not this integrated
candidate.

The decisive remaining issue is **owner-driven online reconciliation**. If a
requester disappears after a valid reorganization intent becomes durable,
successful exact-client retry does not show that other honest clients recover.
The recovery concurrency slot is not a CPU budget or durable authorization;
conditional peer polling is not an independent bounded reconciler. Legacy,
protected-V3 and continuous modes have different existing resource/authorization
owners. A new generic account or an unlimited activation after deadline would
not satisfy the requested repair. The M06 prototype is therefore **BLOCKED and
not merged into the integrated source or its ancestry**.

Its preliminary real 1,024-transfer cost observation also showed approximately
23 ms preparation, 7 ms detached computation and 108 ms commit. SQL and complete
state/readback work remain substantial. Those provisional component timings
are not a throughput claim and not large-state or exhausted-budget acceptance.

## 2C. Conditional counterexamples, not a quantum attack demonstration

[Quantum/DAA evidence](../pon-quantum-daa-research-20261027/README.md) preserves
all eleven runs, including failed bounded schedules and later extended ones.
Under the explicitly assumed square-root query-cost curve, the periodic model
and some extended short-half-life ASERT schedules overtake the honest credited
work and catch up in modeled time. A bounded schedule that fails to catch up
does not prove the DAA safe. Adding a fixed proof delay also fails to supply a
general defense in the extended conditional model.

Fixed probability plus mandatory variable work closes this particular credit
distortion only under the stated joint-cost assumptions. A sublinear joint-cost
counterexample is retained. No implementation has established those physical
assumptions for the original W1 circuit. Logical gates, logical/physical qubits,
fault-tolerance costs, preprocessing and sustained device rates remain unknown,
not zero. The reported 2.838 seconds Python CPU time measures the simulator.

## 3. A real PQ primitive is not whole-chain PQ authorization

[PQ provider and owner review](../pon-pq-native-provider-20261027/README.md)
contains the actual pinned OpenSSL 3.5.9 build, ML-DSA-65 sign/verify controls,
native adapter and source inventory. The adapter verifies the exact TPQ1 context
and independently pinned canonical key; its internal verification has no
classical-signature alternative.

The review found **no native application owner consuming the new PQ observation**.
The TPQ1 signed frame is **3,487 bytes**, already larger than the existing
**2,048-byte whole PNX transaction limit**. Changing the crypto call alone cannot
preserve that wire. Accounts/key registration, version activation, migration,
durable nonce/effect ownership, reorganization, network roles and all other
production authorization owners need a coordinated new-format transition.
Randomized signatures must not create new operation IDs or PoN credit.

The owner inventory is an audit aid, not a complete formal call graph or a count
of vulnerabilities. Its lexical matches include tests. The main native
authorization paths remain classical, and mining/DAA and proof-system quantum
soundness are separate unresolved obligations. **Whole-chain PQ is false.**

## 4. Real model data moved and ran; the comparison legally chose no update

[Real model/Cell observations](../smollm-cell-replica-research-v1/README.md)
pin SmolLM2-135M-Instruct and all seven base-file hashes. Three generations each
performed ten actual CPU training steps, inheriting their real parent adapters.
The complete release comprised **11 Cells, 269 chunks and 272,190,131 payload
bytes**. A fresh replica fetched from the publisher; the publisher was stopped
and reaped; its original endpoint refused a negative request; a fresh consumer
then fetched every required byte from the replica. The replica was subsequently
stopped and cache-only materialization completed. The real CPU model worker
loaded the retrieved candidate.

The actual comparison executed 32 parent and 32 candidate forwards. Both
scored **16/32**; all 32 logits digests changed, but no selected action improved.
The result is **NO_UPDATE**, not an invented gain. This is one controlled model
comparison and is not independent efficacy or product-adoption evidence.

The optimized transport first exposed a transient capacity reset. The
[bounded retry repair](../cell-transient-capacity-retry-v1/README.md) allows at
most one retry before a complete response header, under the same original byte,
connection and deadline budgets. It does not retry bad bodies, digests or
timeouts. All **141 native library tests** passed. Actual optimized replay
completed the two hops in approximately **3.55 s and 2.73 s**; those local results
are not WAN throughput and do not isolate the retry as the cause of speed.
The original failed run and the separate post-success metadata-wrapper failure
remain retained.

The Hepta candidate wires the **existing original FinalUse and holdout owner
tests** into the existing x64 head/merge CI lanes, with pinned model material,
actual three-generation preparation, complete receipts and conservative resource
preflight. The old profiles, budgets and ARM lanes are preserved. No Hepta Rust,
Cargo or Bazel execution occurred locally. Static reader tests and source review
do not supply an actual CI execution, product issuer, install authority,
independent cohort or production model acceptance.

## 5. No independent WAN run has been fabricated

[WAN accounting contract](../../docs/protocol/pon-nakamoto-v1/details/WAN_EVIDENCE_ACCOUNTING_V1.md)
requires at least three independent administrators/failure domains and at least
72 hours. Its reader retains all scheduled operations, missing observations,
failures, timeouts and resource costs. It measures confirmation from scheduled
time, not a later client start; duplicate retries cannot inflate the denominator.
Each operator/cohort must meet its own frozen floor.

All nine reader controls are synthetic. The workspace has no supplied
independently operated deployment/monitoring environments for this campaign.
Multi-process loopback, different port numbers and one operator's replicas do
not satisfy independence. Package 5 remains **NOT RUN**.

## Integration validation and publication scope

[Integration validation](integration-validation.json) retains original logs,
source/binary identities, failures and actual scopes. On the integrated native
source, the locked 25-package workspace passed strict Clippy with every target
and feature and warnings denied; formatting passed. The 91 CI-contract and 34
negative source-integrity tests passed. The repository checker passed with
1,232 local links and 19 normal dependency edges at its recorded source. The
earlier crypto/protocol run retained 164 passing test executions and two ignored
tests; those are not re-counted as new executions on this report commit.

The full inherited native suite and security findings have not all been closed.
Hosted final-source checks and actual source-head/base-merge pairs need their own
results. Publication metadata preserves original measured commit identities and
maps them to same-tree API-created commits; original raw commits and source
bundles are retained. No main merge, force update, self-approval, production
activation or independent-acceptance promotion is authorized by these results.
