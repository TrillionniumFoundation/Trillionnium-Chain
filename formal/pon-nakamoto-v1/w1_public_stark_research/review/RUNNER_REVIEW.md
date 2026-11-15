# Independent review of the recovered full W1 runner

This is a new source review after scratch recovery. It covers the source snapshot recorded in `runner_review.json`; it is not a restored assertion about a previous binary. The initial pre-format review is preserved in `runner_review.preformat.json`. The current snapshot records the coordinated canonical-format source, while execution records identify the particular source used by each job. These identities are kept separate.

## Accepted design

The CLI has three separate operations: `prepare`, `prove` and `verify`. Preparation is explicitly labeled as witness construction without proof. Proving is explicitly labeled as generation pending independent verification. Verification calls both actual Plonky3 proof verifiers after rebuilding their preprocessing keys.

The verifier reads the public statement at exactly 377,290 bytes and reads independent expected header/artifact files of exactly 318/64 bytes. It derives both canonical plans from this same statement and `Expected`, constructs SHA preprocessing via `public_only`, and reconstructs both VKs in the verification process. No serialized prover key is trusted. The source does not provide an arbitrary-plan acceptance route.

The statement controls the SHA messages and arithmetic public rows, not the proof configuration. SHA and arithmetic configurations are fixed and separated by component identifiers. Trace degree bits are required to be 13 and 17 respectively. The verification call has no fallback to a native evaluator or a digest assertion.

## Wire input bounds

Every proof has an eight-byte component envelope: `W1P3SHA1` or `W1P3ARI1`. The complete envelope has a 64 MiB file cap. File metadata is checked before allocation, a bounded read has a one-byte overflow detector, and the final actual length is checked again.

Bincode 1.3.3 uses explicit fixed-width integer encoding, rejects trailing bytes and has a size limit of 64 MiB minus the envelope. Decode panics are contained, as are panics from each proof verifier. Fixed degree metadata is rejected before expensive preprocessing setup.

These are meaningful input restrictions, not a complete hard memory/time bound. The runner does not pre-validate every nested PCS vector length before deserialization or preprocessing; P3's verifier enforces the remaining shapes. Allocation failure/process termination is not equivalent to a caught Rust panic. A future untrusted service needs independently enforced process resource limits and a complete decoder/shape audit.

## Measured phases

Verifier setup time includes recomputing preprocessing and the VK. Prover metadata computation is separately timed. Each proof-verification phase is timed even if it returns a controlled error. Overall process wall time and external `/usr/bin/time -v` observations include work outside the named phases.

The campaign runs three fresh-process positive verifications. Its eleven negative controls span fixed-length framing, truncated/trailing proof bytes, both commitment digests, C, prefix, an AB intermediate, a noise-tail claim, independent expected artifacts and the independent expected header. Expected rejection prefixes prevent an I/O failure from masquerading as a proof-level rejection. Arithmetic negatives must record that they reached SHA verification and arithmetic setup/verification.

## Material measurement correction made during review

The first campaign draft flipped the first byte after the proof envelope and called it a commitment mutation. In the chosen Bincode layout that byte is the first MerkleCap vector's length. It would have been an early malformed-shape sample, not a changed digest.

The corrected campaign verifies that the cap length is one and changes the first digest's first u64 at offset 16 by a canonical increment modulo Goldilocks. It therefore preserves the intended cap shape. A mismatch of that expected serialization layout fails the campaign instead of silently mutating a different field. The smoke test independently changes a commitment through the typed Rust object.

The eleven cases are observed cost samples only. In particular, the largest observed rejection time is not a maximum over every malicious proof or candidate.

## Observed generic integration execution

The durable desktop job `1a1b8516541-12894-e47` completed successfully with Rust 1.95.0 and the pinned P3 0.8.0 crates. Its release check of all targets passed. The release library suite passed all 18 tests, and the three small real-proof integration tests passed in 0.72 seconds. The tests generate actual SHA and arithmetic PCS/FRI proofs, independently reconstruct verifier preprocessing, and check changed public statements, keys, proof fields, component domains and wire encodings. They are component tests, not complete W1 proof execution.

The initial `cargo fmt -- --check` returned exit 1 for style differences. The complete diff is retained in the first-attempt log. `cargo update --offline` added the already locked `p3-security` crate to the root package's direct dependency list; no package version changed. A later coordinated canonical formatting pass produced the current frozen Rust files. The first-attempt execution must not be attributed to those different source hashes without this distinction.

The reviewer independently read the structured job status, command start/end records, lock diff, test names/results and error stream. The full retained streams are `../round2_runtime/generic_first_attempt.stdout.log` and `generic_first_attempt.stderr.log`; the structured source and execution record is `generic_first_attempt.status.json`. Their SHA-256 values are recorded in `runner_review.json`.

## Observed first complete W1 run

The subsequent native gate, job `1a1b8567762-12894-e78`, also passed format checking, the release all-target check, the release build, and all 18 library plus three real-proof integration tests. It used `RUSTFLAGS=-C target-cpu=native`, eight Rayon threads and two Cargo build jobs. At that review, the reviewer read its command results and final binary record, and independently matched all eight canonical-format Rust hashes against the then-current local source. Its binary SHA-256 is `e438893d1620ebad45b8cfd2be0698fe1105c270b2c722263f27af9420adf3f3`. The full logs are retained separately as `native_final_validation.stdout.log` and `native_final_validation.stderr.log`.

The separate `retained-native-01` campaign generated both full proofs and passed three fresh full verifications. The reviewer independently read its provenance, prover report, all three acceptance records and all eleven negative-control records, and matched their source/binary and statement/proof identities. The SHA proof is 4,356,101 bytes, the arithmetic proof is 530,885 bytes, and the public statement is 377,290 bytes. All three verifier records report the same statement and proof hashes as the prover.

All eleven original negatives rejected at their expected parser or component stage. The seven component-level negatives changed the transcript and failed at an input multiproof `SiblingCountMismatch`. The three arithmetic cases reached SHA verification and arithmetic setup/verification, but this is still an early arithmetic proof failure. In the last-C sample, the arithmetic verifier phase took about 1.32 ms; its approximately 0.93-second total process time mostly reflects other phases, especially preprocessing. It is not a measurement of a last FRI query.

The three positive outer process times were approximately 1.042, 0.969 and 0.994 seconds, including independent preprocessing. The first campaign's largest observed negative outer time was approximately 0.947 seconds. These are retained samples on the recorded desktop, not global bounds. The full per-phase values, error strings and evidence hashes are retained in `runner_review.run01.json` and the current `runner_review.json`.

Local identifiers such as `round2_results/` and `round2_runtime/` name the records used during review; they are not required delivery paths. The final package manifest supplies their package locations. Upstream registry source locations are listed in `AUDIT_SOURCE_LOCATORS.json` using pinned official crate/version URLs and full hashes.

## Final-source rerun and additional controls

The strict lint gate requested an equivalent rewrite of one fixed 16-element SHA message-binding loop. The first run's entire pre-lint SHA source is preserved in `prelint_sha_air.rs.txt`, whose SHA-256 was independently matched to `ccf2f7b52b0ad2a8de95289a1c4f6c3d56b497cd1da9141eb121f0c6bea5a2a5`. Its execution identity is not rewritten as the later source.

The final-source gate and complete `retained-native-02` rerun completed successfully in durable job `1a1b875cbb9-12894-f8f`, with exit code 0, complete durable output, no timeout and no log truncation. The reviewer read the complete command/result records, error stream, authoritative status, seven raw result files and final source/binary manifest. All 13 files in that manifest match the local bytes and SHA-256 values. The final binary is `7700eff6ea4a3ff1f8f6551c323ac5b90b2bb5a96d1eaeca41e108bc54a7e3fc` and the final SHA-wrapper source is `a5e4d045eede07e01474225d5568326f2d6abdf0aae8246311bd9084a9b137fa`.

Locked/offline Cargo metadata, format checking, strict release Clippy with all targets/features and `-D warnings`, the all-target build and the test commands passed. There were 18 passing library tests and three passing real-proof smoke tests; their execution times were 0.01 and 0.66 seconds. The main, example and doc-test targets contained zero tests and are not additional test counts. The all-target test command's 78.61-second wall time includes compilation and must not be reported as the tests' execution time.

The final source generated both full-size proofs, passed all three fresh complete verifications, and rejected all eleven original plus four typed later-stage controls at the required stages. Its measured proof process outer wall time was **21.196110213 seconds**, including `/usr/bin/time` overhead; the binary's own process timer reported 21,180.277754 ms. The separate Python generation command, which also prepares the witness, took 21.320564266 seconds. `/usr/bin/time` reported a peak resident set of **2,381,440 KiB**, 154.28 user seconds, 3.61 system seconds and zero swaps. These are observed desktop samples with eight Rayon threads.

The three fresh verifier outer wall times were **0.949266404, 0.936410328 and 0.948203783 seconds**, including independent preprocessing. The actual run-02 statement and both proof hashes and sizes equal run-01's reported identities. This equality was checked after generation, rather than assumed from the equivalent lint change. All four mutant proof hashes and the security metadata also agree across the observed runs. Their execution timings and binary identities remain separate.

The largest of the eleven ordinary negative samples was `arith-commitment-changed`, at **2.238432757 seconds** outer wall. It still rejected at the early input multiproof `SiblingCountMismatch`: bounded read/decode/shape took 965.892610 ms, while arithmetic verification took only 2.606757 ms. The raw sample is retained. Neither those phase observations nor the gap between outer and process timers identifies a specific system cause, and the longer wall time does not indicate a deeper FRI check.

The four typed later-stage controls preserve challenges and proof shapes and target either the end of query 63's fold chain or a late shared commit-phase authentication check. All four matched the exact required `FinalPolyMismatch` or `CommitPhaseMmcsError(CapMismatch)` subtype. Their largest final-run outer wall was **1.043657165 seconds**. Their precise paths, timings and limitations are in `LATE_REJECTION_REVIEW.md`; they remain samples, not a universal latest-rejection bound.

`runner_review.run02.json` records this final source and execution independently. The pre-format record, run-01 record, run-01 late supplement, original SHA source and failed format/Clippy/harness attempts are preserved. All raw-result hashes are computed from the original bytes, including `prover_report.json` without a trailing newline.

The concrete noninteractive bound remains unresolved and qualification stays `HOLD_NO_GO`, regardless of those execution results.
