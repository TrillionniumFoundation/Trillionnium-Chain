# Canonical Submit decoding: predeclared component result

One planned invocation completed on frozen local candidate 205ae38ff01bbf968f3fc2ef0297bee986224684. All 768 trials and all 384 expected codec errors were retained. All twelve groups passed the fixed CPU criteria. This is the unoptimized same-binary body/Packet component experiment; it is not original-resource CI, whole-node throughput, or a four-second/History business acceptance.

The exact compact record is [BENCH_CORE.json](BENCH_CORE.json); complete statistics and every raw sample remain under [component-205ae38](component-205ae38/). The plan was declared at 2026-11-07 16:38:05 UTC with SHA256 82f087389dd27519cb4e1fe2568ba2e1988f200d187d7fd9e922a18d7e63e820. No threshold was changed and no additional measurement run was selected.

Each row has 32 samples per method in 16 sequential ABBA blocks. All values below are milliseconds; pairs are original owned path → candidate borrowed path. New means a new body allocation, not an operating-system cache flush. p95 uses nearest rank.

| Fixture | Allocation | CPU median ms | CPU p95 ms | Wall median ms | Wall p95 ms | CPU median ratio |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| native-empty | new | 1.042033 → 0.903635 | 1.131247 → 1.026263 | 1.043422 → 0.905010 | 1.132803 → 1.027714 | 0.867184 |
| native-empty | reused | 1.060794 → 0.921015 | 1.074934 → 0.931477 | 1.062170 → 0.922562 | 1.076553 → 0.932739 | 0.868232 |
| native-transfers-1 | new | 1.067891 → 0.926449 | 1.095187 → 0.935414 | 1.069458 → 0.928041 | 1.096964 → 0.937104 | 0.867550 |
| native-transfers-1 | reused | 1.044219 → 0.907428 | 1.068648 → 0.917704 | 1.045448 → 0.908703 | 1.070008 → 0.918898 | 0.869002 |
| native-transfers-64 | new | 1.318978 → 1.142128 | 1.353528 → 1.172355 | 1.320463 → 1.143543 | 1.355267 → 1.174089 | 0.865919 |
| native-transfers-64 | reused | 1.353587 → 1.172344 | 1.374937 → 1.198810 | 1.354998 → 1.173946 | 1.376312 → 1.200343 | 0.866102 |
| malformed-header | new | 0.943350 → 0.816187 | 0.972179 → 0.841279 | 0.944835 → 0.817634 | 0.973810 → 0.842788 | 0.865200 |
| malformed-header | reused | 0.921014 → 0.802635 | 0.945151 → 0.842592 | 0.922054 → 0.803721 | 0.946146 → 0.843678 | 0.871469 |
| malformed-count | new | 0.924841 → 0.803377 | 0.964288 → 0.827659 | 0.926199 → 0.805102 | 0.965596 → 0.829002 | 0.868664 |
| malformed-count | reused | 0.943476 → 0.819451 | 0.962846 → 0.841615 | 0.944577 → 0.820537 | 0.963987 → 0.842795 | 0.868545 |
| truncated-proof | new | 0.940704 → 0.818061 | 0.966173 → 0.840391 | 0.942793 → 0.819631 | 0.967922 → 0.841788 | 0.869627 |
| truncated-proof | reused | 0.933010 → 0.812835 | 0.952136 → 0.838389 | 0.934107 → 0.813829 | 0.953345 → 0.839500 | 0.871196 |

The component CPU medians decreased by 12.8531%–13.4800%. For the actual 64-transaction packet, the two decreases were 13.4081%, 13.3898%. Their candidate/original ratios were below the predeclared 0.90 threshold; all other groups were below the fixed 1.05 limit.

Actual binary packet sizes were 49,508 bytes (empty/invalid header/invalid count), 49,709 bytes (one signed transfer), 62,372 bytes (64 signed transfers), and 49,507 bytes (truncated proof). Accepted codec outputs each retained the complete 49188-byte proof. Malformed header/count/truncated-proof outcomes remained HEADER_CODEC, TRANSACTION_LIMIT and PACKET_LIMIT, respectively.

Cargo's actual Running unittests path matched the single planned binary. Its before/after SHA256 remained 60c0bef51679d2eddb570a7f3624c8b709cca540fa3b46f6382655d7807f8b7c. The complete source-before/source-after manifests retained the same 11,019 tracked files and SHA256 57b81d43099e9fc60e5d673599a55e7103cf9c897ca73b191070874eb186e16f. The authoritative process and original exact-test reader both exited zero.

The original 100.226 ms phase cost is not a removable-cost estimate and was not scaled into a promised saving. Full Work, current Node/State/Host checks, admission, persistence, queues and networking are outside this timing scope. Later combined source, the remote integration branch, and original business gates require their own actual validation.

See [NATIVE_VALIDATION.md](NATIVE_VALIDATION.md) for the separate 22-test/Clippy results and all retained failed attempts. The frozen artifact contains both native runner failures, all runner/driver versions, the predeclared plan, raw records, exact denominators and identities.
