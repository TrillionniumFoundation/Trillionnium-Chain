# Paged consumer reconstruction C1 evidence

Runtime source: `c8214f7e41f8c8f1d885bf990dba6b7ddf829ea2`, tree `4c09f0bfbd6933ce4d4f17194387141560038c00`.
Original base: `06233be630f8eff6cea59cd5111e5941135a4aa5` (#848).
[Original run](c1-full/observation.json) records exact clean source, all gate commands,
raw-log hashes and unchanged source manifests. The publication commit only adds
these observations and updates documentation; runtime source remains C1.

| Executed scope | Observed result |
| --- | --- |
| New selected-version restoration cases | 11 passed |
| Complete default-feature DA crate | 823 passed, zero failed or ignored |
| Native-PQ Node storage-service scope | 44 passed, zero failed or ignored |
| Locked offline Cargo graph | PASS |
| Strict Clippy, both crates/all targets | PASS |
| Formatting | PASS |
| Source-integrity negatives and repository/links | PASS |

The cross-page fixture is synthetic: 128 16 KiB model chunks plus a 20-byte
runtime chunk, 129 records in two committed pages. Publisher and delivery CAS
are removed, catalog payload is unavailable, and four actual local provider
targets reconstruct a fresh consumer. Another case uses parity slots 0,2,4,5.
Complete ordered TCV1 and independently pinned TCV2 readback is required.
Missing/corrupt pages, catalog drift, wrong content/original-operation pins,
late quorum failure, bounded retries and shared cumulative allowance are tested.

This observes selected-version consumer reconstruction only. It does not
replace native custody settlement, change original funding/operation/Unknown
responsibilities or grant execution rights. Local directories share an operator.
Actual-model native paged restoration, independent fault domains/WAN,
continuous paid retention, ordinary Hepta FinalUse and production remain HOLD.
The earlier real 280 MB #848 model observation used TCA3 complete-copy recovery;
it is not relabeled as this shard operation.

The initial patch and staged pre-resume state are preserved. No completed
validation attempt existed before the C1 commit; they are not recorded as
failed runtime tests. [Manifest](file-manifest.json) excludes itself and records
every other committed evidence file's exact size and SHA-256.

The first evidence publication commit omitted ignored raw .log files. The
tracked-artifact audit refused publication; [packaging observation](packaging-observation.json)
preserves that failure. The continuation explicitly retains every original log.
The [C2 documentation-source audit](c2-source/observation.json) also remains
attributed to its own exact source; runtime observations remain C1.
