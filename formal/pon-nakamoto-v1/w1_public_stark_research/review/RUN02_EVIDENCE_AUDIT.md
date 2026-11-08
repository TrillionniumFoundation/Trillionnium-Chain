# Final run02 evidence audit

**Result: no mismatch found in the reviewed numeric and cost claims. Qualification remains HOLD_NO_GO.** This audit concerns `retained-native-02`, including the final prefix-extraction and slow-ordinary-negative additions. It does not substitute run01 observations for run02.

## Exact reviewed versions

| File | SHA-256 |
|---|---|
| Final `ROUND_REPORT.md` | `0957eebeb51244d5cbf01911e6e534a726730bb456f310fee070b06aef64084a` |
| Final `MEASUREMENTS.json` | `2c7ce8171a72d41369b7ef391ec9326151edf20808378e193e881e497f6fd229` |
| `RUN02_EVIDENCE_AUDIT.json` | `5907db129a4f3b9bf41b3615c06245a9809262f15e3ae8ad9da61601a4596983` |

The machine-readable audit contains **132 record, arithmetic, identity, and scope comparisons; zero mismatches**. This is an audit comparison count, not a new unit-test count. It includes all eight `MEASUREMENTS.json` input-receipt hashes, source and fixture identities, proof-report agreement, derived statistics, prefix observations, and the largest ordinary negative's phase list.

No new prover or verifier execution, native benchmark, source test, or attack generation was performed. No frozen selected file, root report, measurement record, or remote runtime file was changed. Only independent audit files were written.

## Final numbers

| Quantity | Independently recomputed run02 value |
|---|---:|
| Native retained FullLimb warm median, 150 calls | 1.913279 ms |
| STARK fresh-verifier internal process median, three runs | 940.944317 ms |
| STARK fresh-verifier external median | 0.9482037830166519 s |
| Internal median / native warm median | 491.7967097323496× |
| External median / native warm median | 495.5909634803141× |
| Median sum of both independent key setups | 582.997263 ms |
| Median sum of both proof-check phases | 299.892722 ms |
| Public-witness prepare external wall | 0.02544837398454547 s |
| Prover complete external wall | 21.196110212942585 s |
| Prover complete internal process wall | 21.180277754 s |
| Sum of recorded prover phases | 21.130528090 s |
| Prover peak resident set | 2,381,440 KiB |
| Maximum positive-verifier peak resident set | 132,996 KiB |
| Prepare + prove + median external verifier | 22.169762369943783 s |
| Retained prefix reconstruction median | 2.448736 ms |
| Synthetic component sum including that prefix median | 22.172211105943784 s |

The paired phase sums are computed within each verifier run before taking their median. In general, summing separately computed phase medians is different: here all six separate phase medians sum to 909.415355 ms, while the median of their per-run sums is 909.019299 ms. Neither is the complete process median. The final root report correctly uses the median of the two setup sums and the median of the two proof-check sums.

The same-fixture native denominator is 1.913279 ms. The five-fixture pooled native median must not replace it. Native calls are warm, single-threaded, and timed with input files already loaded; STARK observations use fresh processes, bounded file processing, independent preprocessing, and a request for eight Rayon threads. The ratios describe these explicit boundaries, not an equal-thread microbenchmark or production Node throughput.

## Three artifact identities and payloads

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| `statement.bin` | 377,290 | `d8b06f64c5e3ff0242e1fe30110280be56fe9eca9cfb55086f7ed7ab5bdb3b6c` |
| `sha.proof.bin` | 4,356,101 | `ca4867c63de4f0d247930944d4c47d87342a4945a399abe9f8a57eba2502e33c` |
| `arith.proof.bin` | 530,885 | `cfce6e90bd1f171ab6d202e70f2e442f8a88e490a22c806275dde2af1d6cf204` |

All three SHA values agree across run01's retained prover record, run02 generation/prover records, and all three run02 successful-verifier records. Byte counts agree in the run02 generation/prover/verifier records. The prepared statement SHA also agrees before proof generation. The final binary and SHA-wrapper source identities agree with run02 provenance:

- Binary: `7700eff6ea4a3ff1f8f6551c323ac5b90b2bb5a96d1eaeca41e108bc54a7e3fc`.
- SHA wrapper: `a5e4d045eede07e01474225d5568326f2d6abdf0aae8246311bd9084a9b137fa`.

This local audit received small records, not the three new binary artifacts. It therefore independently verifies **receipt SHA consistency**, not a fresh local rehash of those artifact files. The original raw/prefix/expected-header/artifact fixture bytes were available and were independently rehashed against run02 provenance. All four match.

The two proof files total **4,886,986 B**. The statement plus both proofs totals **5,264,276 B**, or exactly `5,264,276 / 49,506 = 106.33612087423747...` times the original raw W1 input. These are file payloads; network framing and separately supplied trusted expected inputs are not added to this comparison. The construction has not demonstrated wire-size reduction.

## Ordinary and typed-late negatives remain separate

All three positive processes accepted; all eleven ordinary negative records match their expected rejection exits and stages; all four typed-late records match their required rejection variants. They are controlled observations, not statistical evidence of soundness against arbitrary forgeries.

**The ordinary maximum is 2.2384327568579465 s**, from `arith-commitment-changed`. Its internal process time is 1891.980432 ms. Its bounded read/decode/shape phase is **965.892610 ms**, and its arithmetic STARK rejection phase is **2.606757 ms**. The complete phase list in final `MEASUREMENTS.json` matches the original record exactly.

The typed-late subset has these external observations:

| Typed control | Required rejection | External wall, s |
|---|---|---:|
| SHA last-fold query value | `FinalPolyMismatch` | 0.42877326905727386 |
| SHA last-fold authentication sibling | `CommitPhaseMmcsError(CapMismatch)` | 0.5982154139783233 |
| Arithmetic last-fold query value | `FinalPolyMismatch` | 0.9946349170058966 |
| Arithmetic last-fold authentication sibling | `CommitPhaseMmcsError(CapMismatch)` | 1.0436571650207043 |

The **1.0436571650207043 s** typed-late maximum does not replace the larger ordinary maximum. Neither does run01's smaller observation. A larger wall observation is not automatically a deeper algorithmic rejection path; the recorded phases show why those meanings must remain separate. No specific cause for scheduling/runtime variation is inferred here. Both maxima are retained, and neither is a global worst-case rejection or DoS bound.

## Prefix reconstruction evidence

`native-prefix-preparations.json` was extracted from the existing three raw native benchmark files without a new measurement. Its campaign SHA matches the locally available original `native-campaign.json`, and its three raw-file SHA values exactly match that campaign's pins.

| Native process | Retained prefix reconstruction |
|---|---:|
| 0 | 2,655,389 ns |
| 1 | 2,375,195 ns |
| 2 | 2,448,736 ns |
| Median | **2,448,736 ns** |

The frozen runner source matches the current baseline source pin. The timed operation is `parse(existing raw, independent expected)` plus `make_prefixes`: it regenerates noise/factors and every noisy prefix. It does not create the original candidate's C/header/trace/ticket, load that raw file from disk, or search for a winner. There is one retained-prefix preparation sample per fresh process.

The new raw benchmark files themselves were not retrieved into this local audit; their identity is checked through the extraction's hash agreement with the original campaign record. There is no need to run another benchmark merely to recover an already recorded preparation value.

## Cost conclusion

The final report uses the correct boundaries for an explicit path with N receivers:

```text
native   = G + N*Vn
research = G + P_prefix + W_statement + S_prove + N*Vs
```

The resulting difference is

`P_prefix + W_statement + S_prove + N*(Vs - Vn)`.

Under the measured per-receiver policy, `Vs > Vn`, while the added producer terms are nonnegative. Accordingly this implementation has no N ≥ 1 at which receiver replication recovers its proving overhead. This restricted conclusion does not need a value for the unmeasured common G. It does not exclude a different backend, statement representation, preprocessing-cache policy, or optimized producer.

The **22.169762369943783 s** figure starts with an existing raw candidate and complete prefix. The **22.172211105943784 s** extension adds the independently observed prefix median and starts with an existing raw candidate. Both are synthetic sums using one generation and verifier/preparation medians. Neither is a measured paired producer-plus-receiver median, a complete task-to-winner latency, or a cheapest legal production cost.

Truly identical common work can cancel in an additive difference; it does not disappear from a ratio denominator. A fused producer might retain already computed prefix data instead of rebuilding it. Thus full reconstruction must not be counted twice, nor can upstream prefix creation/retention/storage be assumed universally free. The final report states these limitations consistently.

## Selected-event scope and freeze

The selected directory's **36 manifest entries still match**, and its frozen identities remain:

- THEOREM: `8f6b90181200a30284f53f4e7d6575b5325712aa3a7e695b75e6403bb860d5b3`.
- PRICING: `24c3ebc61c4d1bf0f9b14768e12bcf7bf4402318515c7f381a00b2c94c111b46`.
- SHA256SUMS: `a5680efbea9604706feb354d2c3e65dd21565ee668e1fe7b6708971f161f05c7`.

The final root summary agrees with the previously audited formula/table scope: lifetime M/H/R/Q, the reverse-pointer hash terms, conditional classical full-message-ROM row bounds, J=32 for the displayed nonce cache table, retry-aware general counts, achieved rather than universal algorithm costs, and the 512-trial arithmetic-only equality. No frozen proof file was edited or test suite rerun for this audit.

The selected-event local lottery remains a different relation from the complete W1 STARK experiment. Its row-query tariff does not yield native seconds, physical SHA compression lower bounds, a universal cheapest legal strategy, or new useful economic demand. The reviewed numerical/cost claims do not establish concrete noninteractive security, QROM security, production-resource bounds, or Node qualification. Actual repository gate execution is a separate deliverable. **HOLD_NO_GO remains unchanged.**
