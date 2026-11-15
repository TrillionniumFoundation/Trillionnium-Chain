# Recovered source gates and finite-model publication evidence

This directory retains a byte-for-byte copy of three completed evidence directories from HeptaRuntime host `desktop`, source root `/home/qian-qi/work/chain-pon-joint-state-risk-ledger-20261107`. The copied sources remain unchanged. The copy did not change the remote publish worktree, checkout, Git configuration, branches, or commits.

The transfer contains **208 original files, 27 directories, and 11,647,156 original bytes**. The inventory came from physical directory traversal, including empty files and ignored log files; Git and `rg` ignore rules did not select the file set. The complete original-file table below lists every source path, byte count, and SHA-256. `remote-copy-manifest.json` retains the machine-readable remote inventory.

## Contents and retained results

| Original directory | Files | Original bytes |
| --- | ---: | ---: |
| [recovered-exact-source-02](recovered-exact-source-02/checks.json) | 152 | 11,580,625 |
| [recovered-exact-source](recovered-exact-source/checks.json) | 3 | 655 |
| [model-publications](model-publications/checks.json) | 53 | 65,876 |

- `recovered-exact-source` preserves the first setup attempt: its one fetch command exited 128 because the requested bundle reference was absent. Its `checks.json`, stdout, and stderr remain intact.
- `recovered-exact-source-02` preserves all 24 successful command records for recovered source commit `1a426b6ed3a32745d996be328ec31929660fee5b`. These include locked/offline Cargo metadata, Rust formatting, strict owner Clippy, native owner tests (10 + 10 passed, one explicitly ignored crash-child entry), a newly generated native scenario, 21 independent-reader tests, 26 lifecycle-query tests, 16 composition tests, 105 CI source-contract tests, 77 CI execution-contract tests, and the source-inventory check. Push and GitHub remote-readback streams are included.
- `model-publications` preserves all 26 successful command records across three commits. Each commit has its own preflight, tests, push streams, and GitHub readback: `8527ec98698f706b471f9dd985a92c601e2f02ff`, `628ec7f367e64139eff84a23956e00f9e4e613ee`, and `6615ffa37a0d8f6451bf3e49c2500b4626ffae6c`. The final commit's retained tests report 34 FJS1, 21 EC1, and 105 CI-negative tests passed.

The fresh native scenario is retained in full, including raw framed journals, packet artifacts, checkpoints, run JSON, and SQLite databases. The associated original composition summary reports six raw journals, 425 checked journal records, 58 packet artifacts across journals, real ML-DSA-65 signature verification, and `status: PASS`. It also keeps `production_qualified: false`, `native_scenario_execution_independently_attested: false`, and `native_six_successor_failure_probability: null`. These are the original scoped claims; this copy does not strengthen them. The composition source-base field intentionally names the earlier base commit and explicitly says it does not authenticate new files.

`transport/checks-summary.json` is a local read-only aggregation of the retained command records. It verifies every corresponding stdout/stderr file is present and, wherever the original checks declare stream hashes, recomputes and matches those hashes. No test was rerun as part of copying these evidence directories.

## Transfer provenance and completeness

- Remote preflight job: `1a1b85b2727-12894-ea6`, exit 0; original preflight and physical inventory output are retained in `transport/preflight-and-inventory.log`.
- Remote archive job: `1a1b85c87bb-12894-eb1`, exit 0, durable output complete.
- Completed model-publications job: `1a1b8563bad-12894-e76`, exit 0, durable output complete.
- Remote archive: `/home/qian-qi/work/chain-pon-joint-state-risk-ledger-20261107/recovered-source-gates-20261107-transfer-v1.tar.gz`.
- Archive length: **854,280 bytes**.
- Archive SHA-256: `5fda3a5d87d3a8b5dbd41d40a9f2c613d7866c6af2e4b3bbc82c20d9c88c8829`.
- Embedded manifest SHA-256: `be3594c56ba817d94851585eeb22d8bef0d02db54dac10870c691d50344dd416`.
- HeptaRuntime archive version: `2050:52470213:854280:1794094447814495277:1794094447814495277`.

The remote archiver rejected symbolic links and special files, checked each regular file before and after reading, archived the same bytes it hashed, then rescanned and reread the complete selected source tree. Every source byte count and SHA matched after copying. Fourteen download chunks were read with the same pinned archive version, decoded, individually hashed, and assembled with exact contiguous offsets. The complete local archive hash and embedded manifest hash matched the remote receipt. Before extraction, all tar paths, types, duplicates, and the exact file/directory set were checked. New-only extraction preserved every original file byte. A physical traversal then verified the complete extracted tree against the remote manifest, including empty directories and empty files.

Archive directory/file modes were normalized; inode numbers, ownership, mtimes, and OS execution state are not preserved or authenticated. Endpoint file checks do not establish execution attestation, eliminate changes away and back between observations, authenticate physical clocks, close hidden-inventory coverage, or establish the actual-resource/oracle reduction. No actual work or native execution security qualification is promoted.

The transport files retain raw archive bytes, metadata, decoded-chunk hash receipts, and logs. Duplicate transport encodings (`data_base64` and durable-process `bytes_hex`) are deliberately not stored. The small failed local metadata-write attempt is retained separately; it occurred before any Python statements executed and did not change archive bytes.

## Recheck the retained copy

From this directory:

```sh
python3 transport/verify-transfer.py
```

The checker recomputes all 14 chunk hashes, the archive and manifest hashes, the exact tar inventory, every source-file hash, and the full physical extracted inventory. `transport/verification.json` records the completed successful recheck, and `transport/verification-command.json` retains its exit status. `--extract` is a new-only mode and refuses an already populated source tree.

The inventories below were generated from the physical files, without Git ignore filtering. They include every file present when this README was written; `README.md` itself is the one self-describing file and is not given a recursive content hash. Publication must include ignored logs and raw artifacts as well as Markdown/JSON files.

## Complete original-file inventory

| Relative path | Bytes | SHA-256 |
| --- | ---: | --- |
| [model-publications/1-8527ec98-ci-contract.stderr](model-publications/1-8527ec98-ci-contract.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/1-8527ec98-ci-contract.stdout](model-publications/1-8527ec98-ci-contract.stdout) | 180 | `1811739ab56176be2d74cfd1b12a86ba05919a96769d5479faca6db12f37dd54` |
| [model-publications/1-8527ec98-finite-state.stderr](model-publications/1-8527ec98-finite-state.stderr) | 5355 | `09e8b29b919ef7839bd6ad67bb2b029338d39f5c32a5302786ebc045fcd42f2c` |
| [model-publications/1-8527ec98-finite-state.stdout](model-publications/1-8527ec98-finite-state.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/1-8527ec98-merge.stderr](model-publications/1-8527ec98-merge.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/1-8527ec98-merge.stdout](model-publications/1-8527ec98-merge.stdout) | 4190 | `ea5c28f1ee701469208d3d1fef90182e450a7f23bc01dd3b7381fdf6543eb260` |
| [model-publications/1-8527ec98-preflight.stderr](model-publications/1-8527ec98-preflight.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/1-8527ec98-preflight.stdout](model-publications/1-8527ec98-preflight.stdout) | 177 | `390eaae41b4cea9817edf58dae3def992730ea1e0af10cf6403a7fd9e47bd304` |
| [model-publications/1-8527ec98-push.stderr](model-publications/1-8527ec98-push.stderr) | 427 | `093819335a5d005b4e16e1c7430eac61941b528f6e90e142fd58498f9da331e0` |
| [model-publications/1-8527ec98-push.stdout](model-publications/1-8527ec98-push.stdout) | 178 | `7c7f070dca3c60e7e7f3c6cd93fbcdbcea034f3ce0cff3fbb40dcc7e6b0e17a7` |
| [model-publications/1-8527ec98-remote-readback.stderr](model-publications/1-8527ec98-remote-readback.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/1-8527ec98-remote-readback.stdout](model-publications/1-8527ec98-remote-readback.stdout) | 41 | `04c7aeb509d1636817ed9f6088802c24b761936e5dedde3ca871aab02558708c` |
| [model-publications/1-8527ec98-source-clean.stderr](model-publications/1-8527ec98-source-clean.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/1-8527ec98-source-clean.stdout](model-publications/1-8527ec98-source-clean.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/2-628ec7f3-ci-contract.stderr](model-publications/2-628ec7f3-ci-contract.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/2-628ec7f3-ci-contract.stdout](model-publications/2-628ec7f3-ci-contract.stdout) | 180 | `1811739ab56176be2d74cfd1b12a86ba05919a96769d5479faca6db12f37dd54` |
| [model-publications/2-628ec7f3-event-coverage.stderr](model-publications/2-628ec7f3-event-coverage.stderr) | 3905 | `f4e87d6d08e339335a76b3cced0ce0df0a9362bd416e8e0c7e0523b0b95546cf` |
| [model-publications/2-628ec7f3-event-coverage.stdout](model-publications/2-628ec7f3-event-coverage.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/2-628ec7f3-finite-state.stderr](model-publications/2-628ec7f3-finite-state.stderr) | 5355 | `3ed147be8405c875ac42fc3b3382a8e4027a3393a1d930e9a3c9235d1e1a35d5` |
| [model-publications/2-628ec7f3-finite-state.stdout](model-publications/2-628ec7f3-finite-state.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/2-628ec7f3-merge.stderr](model-publications/2-628ec7f3-merge.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/2-628ec7f3-merge.stdout](model-publications/2-628ec7f3-merge.stdout) | 1190 | `b0d331a46854c037f89a31f7f57bd87ed9a3545a1f919be3f8c93f3082a66fa0` |
| [model-publications/2-628ec7f3-preflight.stderr](model-publications/2-628ec7f3-preflight.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/2-628ec7f3-preflight.stdout](model-publications/2-628ec7f3-preflight.stdout) | 177 | `390eaae41b4cea9817edf58dae3def992730ea1e0af10cf6403a7fd9e47bd304` |
| [model-publications/2-628ec7f3-push.stderr](model-publications/2-628ec7f3-push.stderr) | 427 | `a5cd47e304a6388100119d4c7fa172551d1138243a5fca5d2b1986b3afe1475a` |
| [model-publications/2-628ec7f3-push.stdout](model-publications/2-628ec7f3-push.stdout) | 178 | `7c7f070dca3c60e7e7f3c6cd93fbcdbcea034f3ce0cff3fbb40dcc7e6b0e17a7` |
| [model-publications/2-628ec7f3-remote-readback.stderr](model-publications/2-628ec7f3-remote-readback.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/2-628ec7f3-remote-readback.stdout](model-publications/2-628ec7f3-remote-readback.stdout) | 41 | `30b17b6b0d97eff137ec0ecbe156a73091adc37ace73b3fd05ee2d5f9e7c9443` |
| [model-publications/2-628ec7f3-source-clean.stderr](model-publications/2-628ec7f3-source-clean.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/2-628ec7f3-source-clean.stdout](model-publications/2-628ec7f3-source-clean.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/3-6615ffa3-ci-contract.stderr](model-publications/3-6615ffa3-ci-contract.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/3-6615ffa3-ci-contract.stdout](model-publications/3-6615ffa3-ci-contract.stdout) | 180 | `1811739ab56176be2d74cfd1b12a86ba05919a96769d5479faca6db12f37dd54` |
| [model-publications/3-6615ffa3-ci-negative-tests.stderr](model-publications/3-6615ffa3-ci-negative-tests.stderr) | 17535 | `ec911d384ac58e9b8bd4d78ff9536ac29f27edb87eb08c1ecde7dd6cdb8fa770` |
| [model-publications/3-6615ffa3-ci-negative-tests.stdout](model-publications/3-6615ffa3-ci-negative-tests.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/3-6615ffa3-event-coverage.stderr](model-publications/3-6615ffa3-event-coverage.stderr) | 3905 | `7cbaf06d13b687fc8ede4a8af8e5d514f7b5339f964f32ae07af50b134e00fa2` |
| [model-publications/3-6615ffa3-event-coverage.stdout](model-publications/3-6615ffa3-event-coverage.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/3-6615ffa3-finite-state.stderr](model-publications/3-6615ffa3-finite-state.stderr) | 5536 | `81c0881b8196c04707de20352cd9e3dea424387ee6d9d4b2bb547dd00e3688c7` |
| [model-publications/3-6615ffa3-finite-state.stdout](model-publications/3-6615ffa3-finite-state.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/3-6615ffa3-merge.stderr](model-publications/3-6615ffa3-merge.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/3-6615ffa3-merge.stdout](model-publications/3-6615ffa3-merge.stdout) | 4211 | `610be0a0573aab685c9d9140e083e72042ea69ccffcccd7c35f7b18fbeb2fe7e` |
| [model-publications/3-6615ffa3-preflight.stderr](model-publications/3-6615ffa3-preflight.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/3-6615ffa3-preflight.stdout](model-publications/3-6615ffa3-preflight.stdout) | 177 | `390eaae41b4cea9817edf58dae3def992730ea1e0af10cf6403a7fd9e47bd304` |
| [model-publications/3-6615ffa3-push.stderr](model-publications/3-6615ffa3-push.stderr) | 427 | `d3be342199c75878567f5ee7c7aeb319624a66a2dfe2d3a83145de99736373ff` |
| [model-publications/3-6615ffa3-push.stdout](model-publications/3-6615ffa3-push.stdout) | 178 | `7c7f070dca3c60e7e7f3c6cd93fbcdbcea034f3ce0cff3fbb40dcc7e6b0e17a7` |
| [model-publications/3-6615ffa3-remote-readback.stderr](model-publications/3-6615ffa3-remote-readback.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/3-6615ffa3-remote-readback.stdout](model-publications/3-6615ffa3-remote-readback.stdout) | 41 | `d756cc9a0677c7d7a198a0e67c588feb4eb3c28d11ba17a534b206ab4397f446` |
| [model-publications/3-6615ffa3-source-clean.stderr](model-publications/3-6615ffa3-source-clean.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/3-6615ffa3-source-clean.stdout](model-publications/3-6615ffa3-source-clean.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/checkout-evidence-path.stderr](model-publications/checkout-evidence-path.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/checkout-evidence-path.stdout](model-publications/checkout-evidence-path.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [model-publications/checks.json](model-publications/checks.json) | 11543 | `84c2f84e2e44665b95a87bd65af5d6f4caec7d175d441a969d638611826bf221` |
| [model-publications/fetch-model-bundle.stderr](model-publications/fetch-model-bundle.stderr) | 142 | `64a7c180dfd9dcb1bfb75de39ce1d6e0a79cc27524b5c56ee23d3334ad44ef30` |
| [model-publications/fetch-model-bundle.stdout](model-publications/fetch-model-bundle.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source/checks.json](recovered-exact-source/checks.json) | 576 | `12a110662535e5f46a091dd96f77b1f1b6ce86dda16138cb8fc846410bd42532` |
| [recovered-exact-source/fetch-bundle.stderr](recovered-exact-source/fetch-bundle.stderr) | 79 | `cb1905b8ee86e7e2ed7ad66cf34482738739a5c8a5779690bb73373f1d689330` |
| [recovered-exact-source/fetch-bundle.stdout](recovered-exact-source/fetch-bundle.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/cargo-graph.stderr](recovered-exact-source-02/cargo-graph.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/cargo-graph.stdout](recovered-exact-source-02/cargo-graph.stdout) | 869824 | `30b17c703b3eab629fb68acc5dacf721ec4cddebb0401d3d3ebcdd11fee768bf` |
| [recovered-exact-source-02/checkout-recovered.stderr](recovered-exact-source-02/checkout-recovered.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/checkout-recovered.stdout](recovered-exact-source-02/checkout-recovered.stdout) | 104 | `377d9222c3d4acdf45339f996ab72117f1fcf497359b376cf5f2420154f9b8e4` |
| [recovered-exact-source-02/checks.json](recovered-exact-source-02/checks.json) | 10911 | `2a99fb9c6e7278e67b887d4694b07a0d1d56975be1928e86e0243779c9b4f616` |
| [recovered-exact-source-02/ci-execution-contract.stderr](recovered-exact-source-02/ci-execution-contract.stderr) | 12414 | `c55ce9df420f601b05bb7f6346318174df2c2734da829be1f60bfad87c0767d0` |
| [recovered-exact-source-02/ci-execution-contract.stdout](recovered-exact-source-02/ci-execution-contract.stdout) | 484 | `d0796879fc0bffd85d497a972835eef38ebb61f7917c41e16162101f562b6470` |
| [recovered-exact-source-02/ci-source-contract.stderr](recovered-exact-source-02/ci-source-contract.stderr) | 17535 | `98da4e0f7833ba45d6caf814e0e7fbdc34cb015a8c4237f813d7ae0b6732b25e` |
| [recovered-exact-source-02/ci-source-contract.stdout](recovered-exact-source-02/ci-source-contract.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/composition/attempt.json](recovered-exact-source-02/composition/attempt.json) | 610 | `cfd4a1d8d2d30c5f5dd03970699d10c697d2b196e19533b53c0a73f28b6958f2` |
| [recovered-exact-source-02/composition/exact_model_counterexamples.json](recovered-exact-source-02/composition/exact_model_counterexamples.json) | 15418 | `5f7bfcfd976af03bf7fa176d08ec4e215673711dd875a0f82fdb643ca76ecb46` |
| [recovered-exact-source-02/composition/exact_packet_join.json](recovered-exact-source-02/composition/exact_packet_join.json) | 3926 | `99aa50d25a994fbbd2b28c9e384c8a60c9b0b28b36dd6e0292a633082d81ee47` |
| [recovered-exact-source-02/composition/native_composition_negative_controls.json](recovered-exact-source-02/composition/native_composition_negative_controls.json) | 6677 | `0aa7827dff9c8e35ca8bd91158d8dc2ee56d7675e0d9a2aef867307d875f6956` |
| [recovered-exact-source-02/composition/native_packet_publications/artifacts/776dc990e3543a9c4e9957c796a88b2c7901aa3d23816490efe19ce4b0c7b3c5.bin](recovered-exact-source-02/composition/native_packet_publications/artifacts/776dc990e3543a9c4e9957c796a88b2c7901aa3d23816490efe19ce4b0c7b3c5.bin) | 49508 | `776dc990e3543a9c4e9957c796a88b2c7901aa3d23816490efe19ce4b0c7b3c5` |
| [recovered-exact-source-02/composition/native_packet_publications/artifacts/d42cd500b7cf949fc2075ed868145f70c54fd0a11f5c3f1f2fc58af6f785260e.bin](recovered-exact-source-02/composition/native_packet_publications/artifacts/d42cd500b7cf949fc2075ed868145f70c54fd0a11f5c3f1f2fc58af6f785260e.bin) | 49508 | `d42cd500b7cf949fc2075ed868145f70c54fd0a11f5c3f1f2fc58af6f785260e` |
| [recovered-exact-source-02/composition/native_packet_publications/public_expected_pins.json](recovered-exact-source-02/composition/native_packet_publications/public_expected_pins.json) | 4334 | `d62fdce1a1683341a61204fae66c986227fc4965b3e451d227722e214e912d92` |
| [recovered-exact-source-02/composition/native_packet_publications/signed_observations.json](recovered-exact-source-02/composition/native_packet_publications/signed_observations.json) | 16258 | `bdba6892e7db9a22b02c6ad3f36162f4123a13594944994a0f48ce35bd3d786c` |
| [recovered-exact-source-02/composition/native_reader_results.json](recovered-exact-source-02/composition/native_reader_results.json) | 209377 | `37693ab847bbd3e80d9e633c7b3d7b05c0037e1495aa134aece4372419d5372e` |
| [recovered-exact-source-02/composition/producer_attribution_counterexample.json](recovered-exact-source-02/composition/producer_attribution_counterexample.json) | 3740 | `fcd864264d4a21b9d4934c4e558636058ac15640fab42bf7dfffe34bb986be28` |
| [recovered-exact-source-02/composition/signed_false_producer_statement/artifacts/d94942f385a1a9b037494b3c56c520dcd40147e2dbccb686e5f6569355821820.bin](recovered-exact-source-02/composition/signed_false_producer_statement/artifacts/d94942f385a1a9b037494b3c56c520dcd40147e2dbccb686e5f6569355821820.bin) | 49188 | `d94942f385a1a9b037494b3c56c520dcd40147e2dbccb686e5f6569355821820` |
| [recovered-exact-source-02/composition/signed_false_producer_statement/artifacts/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.bin](recovered-exact-source-02/composition/signed_false_producer_statement/artifacts/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.bin) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/composition/signed_false_producer_statement/artifacts/e7ada67c55f95759095b5853150866e0393ed57c8518cdc2a05fd30ddaa81e1b.bin](recovered-exact-source-02/composition/signed_false_producer_statement/artifacts/e7ada67c55f95759095b5853150866e0393ed57c8518cdc2a05fd30ddaa81e1b.bin) | 32800 | `e7ada67c55f95759095b5853150866e0393ed57c8518cdc2a05fd30ddaa81e1b` |
| [recovered-exact-source-02/composition/signed_false_producer_statement/public_expected_pins.json](recovered-exact-source-02/composition/signed_false_producer_statement/public_expected_pins.json) | 4335 | `2e34b42697da7934d5229126bb18f2be2fd90c857d9313111877d439e72c8c12` |
| [recovered-exact-source-02/composition/signed_false_producer_statement/signed_observations.json](recovered-exact-source-02/composition/signed_false_producer_statement/signed_observations.json) | 16419 | `b307075aea9817ac9c34dc1d6a37f98c0f7af9fa7a2c6e81af3f5d99c163809b` |
| [recovered-exact-source-02/composition/source_manifest_before.json](recovered-exact-source-02/composition/source_manifest_before.json) | 2291 | `7679c78d2062fad98ef1ce7b89c8aefeb55d7e5465cd4d0ce46c6e457d650d55` |
| [recovered-exact-source-02/composition/summary.json](recovered-exact-source-02/composition/summary.json) | 4147 | `47e4214aa909f55752bbfc0ddd870e23456466da6b0a4dd6fbb89a084648adb2` |
| [recovered-exact-source-02/composition-models.stderr](recovered-exact-source-02/composition-models.stderr) | 3477 | `e22e6c10b18c6ddcb64d0b1e15a931d490f27dc8c4ab32a6d5273812385f5a9d` |
| [recovered-exact-source-02/composition-models.stdout](recovered-exact-source-02/composition-models.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/exact-certificate-composition.stderr](recovered-exact-source-02/exact-certificate-composition.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/exact-certificate-composition.stdout](recovered-exact-source-02/exact-certificate-composition.stdout) | 235 | `b6e30e9f2e6076aad62fc4fa83a827c9e37ecf0199e3cd63999f23aaffb551dd` |
| [recovered-exact-source-02/fetch-bundle.stderr](recovered-exact-source-02/fetch-bundle.stderr) | 142 | `878d515c735a0d1f7f6975e92f8d342c68f80c60dc302a1915e8a7bc743fb4bb` |
| [recovered-exact-source-02/fetch-bundle.stdout](recovered-exact-source-02/fetch-bundle.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/fresh-native-scenario.stderr](recovered-exact-source-02/fresh-native-scenario.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/fresh-native-scenario.stdout](recovered-exact-source-02/fresh-native-scenario.stdout) | 240 | `e4fb10e90a0ca3084f31a5c016a282f130611b0f70cf5e2e79838bbf4c02a505` |
| [recovered-exact-source-02/hook-config.stderr](recovered-exact-source-02/hook-config.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/hook-config.stdout](recovered-exact-source-02/hook-config.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/independent-native-reader-tests.stderr](recovered-exact-source-02/independent-native-reader-tests.stderr) | 4238 | `965f289ad241956f157ba955783685494f90f96a79b30c52655f97e2fc6597bf` |
| [recovered-exact-source-02/independent-native-reader-tests.stdout](recovered-exact-source-02/independent-native-reader-tests.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/native-journal-build.stderr](recovered-exact-source-02/native-journal-build.stderr) | 314 | `2c793133f306a941f47b70c8ee586aebf3a71e75b1b20b2e73b4e07b2342beeb` |
| [recovered-exact-source-02/native-journal-build.stdout](recovered-exact-source-02/native-journal-build.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/native-owner-journal/alice-before-restart-checkpoint.json](recovered-exact-source-02/native-owner-journal/alice-before-restart-checkpoint.json) | 190 | `8b6947d32fcb3d0f5080722e337df504d913a9ac9fa5e3671bc2191dc91dc3df` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/journal.pnoj1](recovered-exact-source-02/native-owner-journal/alice-journal/journal.pnoj1) | 1565731 | `c3a572a2bf448fbf94696d05cd4bd4681ef3e379a626026c4bc6c2e0fe5ff1f7` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/owner.lock](recovered-exact-source-02/native-owner-journal/alice-journal/owner.lock) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/0911acca8ac8c87868b5f08de9d8183b85820f991d1e9395ece71e7776d083ab.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/0911acca8ac8c87868b5f08de9d8183b85820f991d1e9395ece71e7776d083ab.pnp1) | 49508 | `0911acca8ac8c87868b5f08de9d8183b85820f991d1e9395ece71e7776d083ab` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/16b76c3f1e567abed89066f07aabee48fbf8036d6a1437e95c4a691ee3dc8f09.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/16b76c3f1e567abed89066f07aabee48fbf8036d6a1437e95c4a691ee3dc8f09.pnp1) | 49508 | `16b76c3f1e567abed89066f07aabee48fbf8036d6a1437e95c4a691ee3dc8f09` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/23a22bc54331b6c4f6f291921478703b12adea793a7077f7ab280628e23ef29d.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/23a22bc54331b6c4f6f291921478703b12adea793a7077f7ab280628e23ef29d.pnp1) | 49508 | `23a22bc54331b6c4f6f291921478703b12adea793a7077f7ab280628e23ef29d` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/2d4868329e2a4ef4a76bfd86d00ed43a9db0ac4772957af24390b0277f0178de.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/2d4868329e2a4ef4a76bfd86d00ed43a9db0ac4772957af24390b0277f0178de.pnp1) | 49709 | `2d4868329e2a4ef4a76bfd86d00ed43a9db0ac4772957af24390b0277f0178de` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/2fb14f1b46b51aa45fe54f2824738d2b2becf69384dc046e14dbc29fe7ea8f6e.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/2fb14f1b46b51aa45fe54f2824738d2b2becf69384dc046e14dbc29fe7ea8f6e.pnp1) | 49508 | `2fb14f1b46b51aa45fe54f2824738d2b2becf69384dc046e14dbc29fe7ea8f6e` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/412c750326721e6ec5d9e5952038dc045e8603683aed6ecd1859e1f067633e54.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/412c750326721e6ec5d9e5952038dc045e8603683aed6ecd1859e1f067633e54.pnp1) | 49508 | `412c750326721e6ec5d9e5952038dc045e8603683aed6ecd1859e1f067633e54` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/4376d1102a405753673dbcd2b59523e23d50493779b7cf2d00b725c85fb185bd.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/4376d1102a405753673dbcd2b59523e23d50493779b7cf2d00b725c85fb185bd.pnp1) | 49508 | `4376d1102a405753673dbcd2b59523e23d50493779b7cf2d00b725c85fb185bd` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/4a978ab260bf253182e098f050b6d62a91257dc3777f36be0fe62d6dd3b907b7.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/4a978ab260bf253182e098f050b6d62a91257dc3777f36be0fe62d6dd3b907b7.pnp1) | 49508 | `4a978ab260bf253182e098f050b6d62a91257dc3777f36be0fe62d6dd3b907b7` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/4b2a10c6cb264552378c8fec99f40d200816fc558ca2c05ae423268d1a1f4e78.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/4b2a10c6cb264552378c8fec99f40d200816fc558ca2c05ae423268d1a1f4e78.pnp1) | 49508 | `4b2a10c6cb264552378c8fec99f40d200816fc558ca2c05ae423268d1a1f4e78` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/776dc990e3543a9c4e9957c796a88b2c7901aa3d23816490efe19ce4b0c7b3c5.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/776dc990e3543a9c4e9957c796a88b2c7901aa3d23816490efe19ce4b0c7b3c5.pnp1) | 49508 | `776dc990e3543a9c4e9957c796a88b2c7901aa3d23816490efe19ce4b0c7b3c5` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/83e5904ac17b2c3f58cd8243de4220d2b5fe324e8a640cca48dbb7f04bde3e14.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/83e5904ac17b2c3f58cd8243de4220d2b5fe324e8a640cca48dbb7f04bde3e14.pnp1) | 49508 | `83e5904ac17b2c3f58cd8243de4220d2b5fe324e8a640cca48dbb7f04bde3e14` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/89ec206947d46e4280541b8eafc72250763b315cdde2457398f6b796c6656cb7.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/89ec206947d46e4280541b8eafc72250763b315cdde2457398f6b796c6656cb7.pnp1) | 49508 | `89ec206947d46e4280541b8eafc72250763b315cdde2457398f6b796c6656cb7` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/8c54fa5ba8958229d49a6c5750f75ae846b3bc15c61dd882b446df5aa3e2c691.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/8c54fa5ba8958229d49a6c5750f75ae846b3bc15c61dd882b446df5aa3e2c691.pnp1) | 49508 | `8c54fa5ba8958229d49a6c5750f75ae846b3bc15c61dd882b446df5aa3e2c691` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/a2e0494fa79cc78255f5dbe4dcf5ed8ae7d6be53806a2da193efe3c09747104f.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/a2e0494fa79cc78255f5dbe4dcf5ed8ae7d6be53806a2da193efe3c09747104f.pnp1) | 49508 | `a2e0494fa79cc78255f5dbe4dcf5ed8ae7d6be53806a2da193efe3c09747104f` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/a5cb39f8bfb11d03d960c7414a7ca9a635f94e144d8c97b97407406b81fe53e0.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/a5cb39f8bfb11d03d960c7414a7ca9a635f94e144d8c97b97407406b81fe53e0.pnp1) | 49508 | `a5cb39f8bfb11d03d960c7414a7ca9a635f94e144d8c97b97407406b81fe53e0` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/a87e881dea297719ff996dc533465e75809eb151a61ba5297d378614e8277e63.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/a87e881dea297719ff996dc533465e75809eb151a61ba5297d378614e8277e63.pnp1) | 49508 | `a87e881dea297719ff996dc533465e75809eb151a61ba5297d378614e8277e63` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/ae71245e9159ae093183ff7011370d167ecdfbdb32041ec9a19ca6fafe33cd06.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/ae71245e9159ae093183ff7011370d167ecdfbdb32041ec9a19ca6fafe33cd06.pnp1) | 49508 | `ae71245e9159ae093183ff7011370d167ecdfbdb32041ec9a19ca6fafe33cd06` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/bf2ec604f1eb1d6b326074f5184a657730e7b1c846f99dcccdd4ac0063f0f9ee.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/bf2ec604f1eb1d6b326074f5184a657730e7b1c846f99dcccdd4ac0063f0f9ee.pnp1) | 49508 | `bf2ec604f1eb1d6b326074f5184a657730e7b1c846f99dcccdd4ac0063f0f9ee` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/c66a1aed9fe347af0b812c54b08906caac84f33f53e04c40231eddcfbcf4a389.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/c66a1aed9fe347af0b812c54b08906caac84f33f53e04c40231eddcfbcf4a389.pnp1) | 49508 | `c66a1aed9fe347af0b812c54b08906caac84f33f53e04c40231eddcfbcf4a389` |
| [recovered-exact-source-02/native-owner-journal/alice-journal/packets/d42cd500b7cf949fc2075ed868145f70c54fd0a11f5c3f1f2fc58af6f785260e.pnp1](recovered-exact-source-02/native-owner-journal/alice-journal/packets/d42cd500b7cf949fc2075ed868145f70c54fd0a11f5c3f1f2fc58af6f785260e.pnp1) | 49508 | `d42cd500b7cf949fc2075ed868145f70c54fd0a11f5c3f1f2fc58af6f785260e` |
| [recovered-exact-source-02/native-owner-journal/alice-store/native.sqlite](recovered-exact-source-02/native-owner-journal/alice-store/native.sqlite) | 1118208 | `ef6b93d16fe6f9b9be7bfa922e481f92fbf82f87c09958e272dac5a59aa3ab0c` |
| [recovered-exact-source-02/native-owner-journal/alice-store/owner.lock](recovered-exact-source-02/native-owner-journal/alice-store/owner.lock) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/native-owner-journal/bob-journal/journal.pnoj1](recovered-exact-source-02/native-owner-journal/bob-journal/journal.pnoj1) | 440626 | `e31fb99898f051cf70d56de3156edd5d661e19b7ab32e8345d7e269fd7ac855b` |
| [recovered-exact-source-02/native-owner-journal/bob-journal/owner.lock](recovered-exact-source-02/native-owner-journal/bob-journal/owner.lock) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/native-owner-journal/bob-journal/packets/2fb14f1b46b51aa45fe54f2824738d2b2becf69384dc046e14dbc29fe7ea8f6e.pnp1](recovered-exact-source-02/native-owner-journal/bob-journal/packets/2fb14f1b46b51aa45fe54f2824738d2b2becf69384dc046e14dbc29fe7ea8f6e.pnp1) | 49508 | `2fb14f1b46b51aa45fe54f2824738d2b2becf69384dc046e14dbc29fe7ea8f6e` |
| [recovered-exact-source-02/native-owner-journal/bob-journal/packets/4376d1102a405753673dbcd2b59523e23d50493779b7cf2d00b725c85fb185bd.pnp1](recovered-exact-source-02/native-owner-journal/bob-journal/packets/4376d1102a405753673dbcd2b59523e23d50493779b7cf2d00b725c85fb185bd.pnp1) | 49508 | `4376d1102a405753673dbcd2b59523e23d50493779b7cf2d00b725c85fb185bd` |
| [recovered-exact-source-02/native-owner-journal/bob-journal/packets/4b2a10c6cb264552378c8fec99f40d200816fc558ca2c05ae423268d1a1f4e78.pnp1](recovered-exact-source-02/native-owner-journal/bob-journal/packets/4b2a10c6cb264552378c8fec99f40d200816fc558ca2c05ae423268d1a1f4e78.pnp1) | 49508 | `4b2a10c6cb264552378c8fec99f40d200816fc558ca2c05ae423268d1a1f4e78` |
| [recovered-exact-source-02/native-owner-journal/bob-journal/packets/776dc990e3543a9c4e9957c796a88b2c7901aa3d23816490efe19ce4b0c7b3c5.pnp1](recovered-exact-source-02/native-owner-journal/bob-journal/packets/776dc990e3543a9c4e9957c796a88b2c7901aa3d23816490efe19ce4b0c7b3c5.pnp1) | 49508 | `776dc990e3543a9c4e9957c796a88b2c7901aa3d23816490efe19ce4b0c7b3c5` |
| [recovered-exact-source-02/native-owner-journal/bob-journal/packets/83e5904ac17b2c3f58cd8243de4220d2b5fe324e8a640cca48dbb7f04bde3e14.pnp1](recovered-exact-source-02/native-owner-journal/bob-journal/packets/83e5904ac17b2c3f58cd8243de4220d2b5fe324e8a640cca48dbb7f04bde3e14.pnp1) | 49508 | `83e5904ac17b2c3f58cd8243de4220d2b5fe324e8a640cca48dbb7f04bde3e14` |
| [recovered-exact-source-02/native-owner-journal/bob-journal/packets/89ec206947d46e4280541b8eafc72250763b315cdde2457398f6b796c6656cb7.pnp1](recovered-exact-source-02/native-owner-journal/bob-journal/packets/89ec206947d46e4280541b8eafc72250763b315cdde2457398f6b796c6656cb7.pnp1) | 49508 | `89ec206947d46e4280541b8eafc72250763b315cdde2457398f6b796c6656cb7` |
| [recovered-exact-source-02/native-owner-journal/bob-journal/packets/ae71245e9159ae093183ff7011370d167ecdfbdb32041ec9a19ca6fafe33cd06.pnp1](recovered-exact-source-02/native-owner-journal/bob-journal/packets/ae71245e9159ae093183ff7011370d167ecdfbdb32041ec9a19ca6fafe33cd06.pnp1) | 49508 | `ae71245e9159ae093183ff7011370d167ecdfbdb32041ec9a19ca6fafe33cd06` |
| [recovered-exact-source-02/native-owner-journal/bob-journal/packets/bf2ec604f1eb1d6b326074f5184a657730e7b1c846f99dcccdd4ac0063f0f9ee.pnp1](recovered-exact-source-02/native-owner-journal/bob-journal/packets/bf2ec604f1eb1d6b326074f5184a657730e7b1c846f99dcccdd4ac0063f0f9ee.pnp1) | 49508 | `bf2ec604f1eb1d6b326074f5184a657730e7b1c846f99dcccdd4ac0063f0f9ee` |
| [recovered-exact-source-02/native-owner-journal/bob-store/native.sqlite](recovered-exact-source-02/native-owner-journal/bob-store/native.sqlite) | 548864 | `e03cc87f1b7ca639782d1180e70269793aa9a3936c6228f5de77dcf446e95d5d` |
| [recovered-exact-source-02/native-owner-journal/bob-store/owner.lock](recovered-exact-source-02/native-owner-journal/bob-store/owner.lock) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/native-owner-journal/crash-journal/journal.pnoj1](recovered-exact-source-02/native-owner-journal/crash-journal/journal.pnoj1) | 301066 | `6dfe7acbc624497d07010edaf49d58bf833a28dc8e313549c76413e1828cc802` |
| [recovered-exact-source-02/native-owner-journal/crash-journal/owner.lock](recovered-exact-source-02/native-owner-journal/crash-journal/owner.lock) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/native-owner-journal/crash-journal/packets/0911acca8ac8c87868b5f08de9d8183b85820f991d1e9395ece71e7776d083ab.pnp1](recovered-exact-source-02/native-owner-journal/crash-journal/packets/0911acca8ac8c87868b5f08de9d8183b85820f991d1e9395ece71e7776d083ab.pnp1) | 49508 | `0911acca8ac8c87868b5f08de9d8183b85820f991d1e9395ece71e7776d083ab` |
| [recovered-exact-source-02/native-owner-journal/crash-journal/packets/23a22bc54331b6c4f6f291921478703b12adea793a7077f7ab280628e23ef29d.pnp1](recovered-exact-source-02/native-owner-journal/crash-journal/packets/23a22bc54331b6c4f6f291921478703b12adea793a7077f7ab280628e23ef29d.pnp1) | 49508 | `23a22bc54331b6c4f6f291921478703b12adea793a7077f7ab280628e23ef29d` |
| [recovered-exact-source-02/native-owner-journal/crash-journal/packets/2d4868329e2a4ef4a76bfd86d00ed43a9db0ac4772957af24390b0277f0178de.pnp1](recovered-exact-source-02/native-owner-journal/crash-journal/packets/2d4868329e2a4ef4a76bfd86d00ed43a9db0ac4772957af24390b0277f0178de.pnp1) | 49709 | `2d4868329e2a4ef4a76bfd86d00ed43a9db0ac4772957af24390b0277f0178de` |
| [recovered-exact-source-02/native-owner-journal/crash-journal/packets/412c750326721e6ec5d9e5952038dc045e8603683aed6ecd1859e1f067633e54.pnp1](recovered-exact-source-02/native-owner-journal/crash-journal/packets/412c750326721e6ec5d9e5952038dc045e8603683aed6ecd1859e1f067633e54.pnp1) | 49508 | `412c750326721e6ec5d9e5952038dc045e8603683aed6ecd1859e1f067633e54` |
| [recovered-exact-source-02/native-owner-journal/crash-journal/packets/a2e0494fa79cc78255f5dbe4dcf5ed8ae7d6be53806a2da193efe3c09747104f.pnp1](recovered-exact-source-02/native-owner-journal/crash-journal/packets/a2e0494fa79cc78255f5dbe4dcf5ed8ae7d6be53806a2da193efe3c09747104f.pnp1) | 49508 | `a2e0494fa79cc78255f5dbe4dcf5ed8ae7d6be53806a2da193efe3c09747104f` |
| [recovered-exact-source-02/native-owner-journal/crash-journal/packets/a87e881dea297719ff996dc533465e75809eb151a61ba5297d378614e8277e63.pnp1](recovered-exact-source-02/native-owner-journal/crash-journal/packets/a87e881dea297719ff996dc533465e75809eb151a61ba5297d378614e8277e63.pnp1) | 49508 | `a87e881dea297719ff996dc533465e75809eb151a61ba5297d378614e8277e63` |
| [recovered-exact-source-02/native-owner-journal/crash-journal/packets/c66a1aed9fe347af0b812c54b08906caac84f33f53e04c40231eddcfbcf4a389.pnp1](recovered-exact-source-02/native-owner-journal/crash-journal/packets/c66a1aed9fe347af0b812c54b08906caac84f33f53e04c40231eddcfbcf4a389.pnp1) | 49508 | `c66a1aed9fe347af0b812c54b08906caac84f33f53e04c40231eddcfbcf4a389` |
| [recovered-exact-source-02/native-owner-journal/crash-plan.json](recovered-exact-source-02/native-owner-journal/crash-plan.json) | 2452 | `527f78f76c9d45cc8dfb55f11c855f4950e2a871116b2942004e7016bcf054b3` |
| [recovered-exact-source-02/native-owner-journal/crash-recovered-checkpoint.json](recovered-exact-source-02/native-owner-journal/crash-recovered-checkpoint.json) | 190 | `af4a61b6574dd2068b1e3d86f1a7cae4305e6c67f79a545d2db7578b6752cc82` |
| [recovered-exact-source-02/native-owner-journal/crash-store/native.sqlite](recovered-exact-source-02/native-owner-journal/crash-store/native.sqlite) | 499712 | `f1ca824c59fb562f7649053719423d4fc983c54e3a357eb28998a3ed6787e013` |
| [recovered-exact-source-02/native-owner-journal/crash-store/owner.lock](recovered-exact-source-02/native-owner-journal/crash-store/owner.lock) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/native-owner-journal/old-crash-journal/journal.pnoj1](recovered-exact-source-02/native-owner-journal/old-crash-journal/journal.pnoj1) | 276715 | `dbbcb1736608b6ff8f6a12cb2a6bb5d05ea8023ce4aa3d9e12c963f2feb645d1` |
| [recovered-exact-source-02/native-owner-journal/old-crash-journal/owner.lock](recovered-exact-source-02/native-owner-journal/old-crash-journal/owner.lock) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/native-owner-journal/old-crash-journal/packets/0911acca8ac8c87868b5f08de9d8183b85820f991d1e9395ece71e7776d083ab.pnp1](recovered-exact-source-02/native-owner-journal/old-crash-journal/packets/0911acca8ac8c87868b5f08de9d8183b85820f991d1e9395ece71e7776d083ab.pnp1) | 49508 | `0911acca8ac8c87868b5f08de9d8183b85820f991d1e9395ece71e7776d083ab` |
| [recovered-exact-source-02/native-owner-journal/old-crash-journal/packets/23a22bc54331b6c4f6f291921478703b12adea793a7077f7ab280628e23ef29d.pnp1](recovered-exact-source-02/native-owner-journal/old-crash-journal/packets/23a22bc54331b6c4f6f291921478703b12adea793a7077f7ab280628e23ef29d.pnp1) | 49508 | `23a22bc54331b6c4f6f291921478703b12adea793a7077f7ab280628e23ef29d` |
| [recovered-exact-source-02/native-owner-journal/old-crash-journal/packets/2d4868329e2a4ef4a76bfd86d00ed43a9db0ac4772957af24390b0277f0178de.pnp1](recovered-exact-source-02/native-owner-journal/old-crash-journal/packets/2d4868329e2a4ef4a76bfd86d00ed43a9db0ac4772957af24390b0277f0178de.pnp1) | 49709 | `2d4868329e2a4ef4a76bfd86d00ed43a9db0ac4772957af24390b0277f0178de` |
| [recovered-exact-source-02/native-owner-journal/old-crash-journal/packets/412c750326721e6ec5d9e5952038dc045e8603683aed6ecd1859e1f067633e54.pnp1](recovered-exact-source-02/native-owner-journal/old-crash-journal/packets/412c750326721e6ec5d9e5952038dc045e8603683aed6ecd1859e1f067633e54.pnp1) | 49508 | `412c750326721e6ec5d9e5952038dc045e8603683aed6ecd1859e1f067633e54` |
| [recovered-exact-source-02/native-owner-journal/old-crash-journal/packets/a2e0494fa79cc78255f5dbe4dcf5ed8ae7d6be53806a2da193efe3c09747104f.pnp1](recovered-exact-source-02/native-owner-journal/old-crash-journal/packets/a2e0494fa79cc78255f5dbe4dcf5ed8ae7d6be53806a2da193efe3c09747104f.pnp1) | 49508 | `a2e0494fa79cc78255f5dbe4dcf5ed8ae7d6be53806a2da193efe3c09747104f` |
| [recovered-exact-source-02/native-owner-journal/old-crash-journal/packets/a87e881dea297719ff996dc533465e75809eb151a61ba5297d378614e8277e63.pnp1](recovered-exact-source-02/native-owner-journal/old-crash-journal/packets/a87e881dea297719ff996dc533465e75809eb151a61ba5297d378614e8277e63.pnp1) | 49508 | `a87e881dea297719ff996dc533465e75809eb151a61ba5297d378614e8277e63` |
| [recovered-exact-source-02/native-owner-journal/old-crash-journal/packets/c66a1aed9fe347af0b812c54b08906caac84f33f53e04c40231eddcfbcf4a389.pnp1](recovered-exact-source-02/native-owner-journal/old-crash-journal/packets/c66a1aed9fe347af0b812c54b08906caac84f33f53e04c40231eddcfbcf4a389.pnp1) | 49508 | `c66a1aed9fe347af0b812c54b08906caac84f33f53e04c40231eddcfbcf4a389` |
| [recovered-exact-source-02/native-owner-journal/old-crash-store/native.sqlite](recovered-exact-source-02/native-owner-journal/old-crash-store/native.sqlite) | 499712 | `f1ca824c59fb562f7649053719423d4fc983c54e3a357eb28998a3ed6787e013` |
| [recovered-exact-source-02/native-owner-journal/old-crash-store/owner.lock](recovered-exact-source-02/native-owner-journal/old-crash-store/owner.lock) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/native-owner-journal/orphan-journal/journal.pnoj1](recovered-exact-source-02/native-owner-journal/orphan-journal/journal.pnoj1) | 27413 | `a32c311f6d457d414c474a745e66ab7906b0a1527abde5bb6a33a0e8911bd786` |
| [recovered-exact-source-02/native-owner-journal/orphan-journal/owner.lock](recovered-exact-source-02/native-owner-journal/orphan-journal/owner.lock) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/native-owner-journal/orphan-journal/packets/ad267759cf349338a0f9f238c5ab39d63ce271fc46085cd935f4d41292b81a46.pnp1](recovered-exact-source-02/native-owner-journal/orphan-journal/packets/ad267759cf349338a0f9f238c5ab39d63ce271fc46085cd935f4d41292b81a46.pnp1) | 49508 | `ad267759cf349338a0f9f238c5ab39d63ce271fc46085cd935f4d41292b81a46` |
| [recovered-exact-source-02/native-owner-journal/orphan-store/native.sqlite](recovered-exact-source-02/native-owner-journal/orphan-store/native.sqlite) | 196608 | `6edce7f3a89ebbbad7f673fa122113f166a4c522f10f8f060e5c4030b59ae47e` |
| [recovered-exact-source-02/native-owner-journal/orphan-store/owner.lock](recovered-exact-source-02/native-owner-journal/orphan-store/owner.lock) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/journal.pnoj1](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/journal.pnoj1) | 672634 | `18b2c538934fbbbc9807a0c03027dc253b2dd326527f270037b5495d85924c33` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/owner.lock](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/owner.lock) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/0911acca8ac8c87868b5f08de9d8183b85820f991d1e9395ece71e7776d083ab.pnp1](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/0911acca8ac8c87868b5f08de9d8183b85820f991d1e9395ece71e7776d083ab.pnp1) | 49508 | `0911acca8ac8c87868b5f08de9d8183b85820f991d1e9395ece71e7776d083ab` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/23a22bc54331b6c4f6f291921478703b12adea793a7077f7ab280628e23ef29d.pnp1](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/23a22bc54331b6c4f6f291921478703b12adea793a7077f7ab280628e23ef29d.pnp1) | 49508 | `23a22bc54331b6c4f6f291921478703b12adea793a7077f7ab280628e23ef29d` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/2d4868329e2a4ef4a76bfd86d00ed43a9db0ac4772957af24390b0277f0178de.pnp1](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/2d4868329e2a4ef4a76bfd86d00ed43a9db0ac4772957af24390b0277f0178de.pnp1) | 49709 | `2d4868329e2a4ef4a76bfd86d00ed43a9db0ac4772957af24390b0277f0178de` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/2fb14f1b46b51aa45fe54f2824738d2b2becf69384dc046e14dbc29fe7ea8f6e.pnp1](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/2fb14f1b46b51aa45fe54f2824738d2b2becf69384dc046e14dbc29fe7ea8f6e.pnp1) | 49508 | `2fb14f1b46b51aa45fe54f2824738d2b2becf69384dc046e14dbc29fe7ea8f6e` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/412c750326721e6ec5d9e5952038dc045e8603683aed6ecd1859e1f067633e54.pnp1](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/412c750326721e6ec5d9e5952038dc045e8603683aed6ecd1859e1f067633e54.pnp1) | 49508 | `412c750326721e6ec5d9e5952038dc045e8603683aed6ecd1859e1f067633e54` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/4376d1102a405753673dbcd2b59523e23d50493779b7cf2d00b725c85fb185bd.pnp1](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/4376d1102a405753673dbcd2b59523e23d50493779b7cf2d00b725c85fb185bd.pnp1) | 49508 | `4376d1102a405753673dbcd2b59523e23d50493779b7cf2d00b725c85fb185bd` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/4b2a10c6cb264552378c8fec99f40d200816fc558ca2c05ae423268d1a1f4e78.pnp1](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/4b2a10c6cb264552378c8fec99f40d200816fc558ca2c05ae423268d1a1f4e78.pnp1) | 49508 | `4b2a10c6cb264552378c8fec99f40d200816fc558ca2c05ae423268d1a1f4e78` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/776dc990e3543a9c4e9957c796a88b2c7901aa3d23816490efe19ce4b0c7b3c5.pnp1](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/776dc990e3543a9c4e9957c796a88b2c7901aa3d23816490efe19ce4b0c7b3c5.pnp1) | 49508 | `776dc990e3543a9c4e9957c796a88b2c7901aa3d23816490efe19ce4b0c7b3c5` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/83e5904ac17b2c3f58cd8243de4220d2b5fe324e8a640cca48dbb7f04bde3e14.pnp1](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/83e5904ac17b2c3f58cd8243de4220d2b5fe324e8a640cca48dbb7f04bde3e14.pnp1) | 49508 | `83e5904ac17b2c3f58cd8243de4220d2b5fe324e8a640cca48dbb7f04bde3e14` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/89ec206947d46e4280541b8eafc72250763b315cdde2457398f6b796c6656cb7.pnp1](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/89ec206947d46e4280541b8eafc72250763b315cdde2457398f6b796c6656cb7.pnp1) | 49508 | `89ec206947d46e4280541b8eafc72250763b315cdde2457398f6b796c6656cb7` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/a2e0494fa79cc78255f5dbe4dcf5ed8ae7d6be53806a2da193efe3c09747104f.pnp1](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/a2e0494fa79cc78255f5dbe4dcf5ed8ae7d6be53806a2da193efe3c09747104f.pnp1) | 49508 | `a2e0494fa79cc78255f5dbe4dcf5ed8ae7d6be53806a2da193efe3c09747104f` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/a87e881dea297719ff996dc533465e75809eb151a61ba5297d378614e8277e63.pnp1](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/a87e881dea297719ff996dc533465e75809eb151a61ba5297d378614e8277e63.pnp1) | 49508 | `a87e881dea297719ff996dc533465e75809eb151a61ba5297d378614e8277e63` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/ae71245e9159ae093183ff7011370d167ecdfbdb32041ec9a19ca6fafe33cd06.pnp1](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/ae71245e9159ae093183ff7011370d167ecdfbdb32041ec9a19ca6fafe33cd06.pnp1) | 49508 | `ae71245e9159ae093183ff7011370d167ecdfbdb32041ec9a19ca6fafe33cd06` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/bf2ec604f1eb1d6b326074f5184a657730e7b1c846f99dcccdd4ac0063f0f9ee.pnp1](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/bf2ec604f1eb1d6b326074f5184a657730e7b1c846f99dcccdd4ac0063f0f9ee.pnp1) | 49508 | `bf2ec604f1eb1d6b326074f5184a657730e7b1c846f99dcccdd4ac0063f0f9ee` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/c66a1aed9fe347af0b812c54b08906caac84f33f53e04c40231eddcfbcf4a389.pnp1](recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets/c66a1aed9fe347af0b812c54b08906caac84f33f53e04c40231eddcfbcf4a389.pnp1) | 49508 | `c66a1aed9fe347af0b812c54b08906caac84f33f53e04c40231eddcfbcf4a389` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-store/native.sqlite](recovered-exact-source-02/native-owner-journal/recovered-crash-store/native.sqlite) | 913408 | `a7250772209276c3c1397e2007b9d4fb854de9aa153b78fa4a6e28bfa38c4ed1` |
| [recovered-exact-source-02/native-owner-journal/recovered-crash-store/owner.lock](recovered-exact-source-02/native-owner-journal/recovered-crash-store/owner.lock) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/native-owner-journal/run.json](recovered-exact-source-02/native-owner-journal/run.json) | 241032 | `209514f433658d4227b393dcbfbcb2fbbf63a19d9d7d1db8920c023d868032d2` |
| [recovered-exact-source-02/native-owner-tests.stderr](recovered-exact-source-02/native-owner-tests.stderr) | 3782 | `70748ba24d79ad74c1bb39b110d9953e41428abc331ace5bbf138572b8783193` |
| [recovered-exact-source-02/native-owner-tests.stdout](recovered-exact-source-02/native-owner-tests.stdout) | 2061 | `d4888d8eb763cac7f263bbd8d0e47d7b8f781508fb82efa79416306028475ef5` |
| [recovered-exact-source-02/new-publish-worktree.stderr](recovered-exact-source-02/new-publish-worktree.stderr) | 80 | `a7ea9b9ab282d727697fb3340f0db9d0c477cf699e0d393bdba0f16649f517a2` |
| [recovered-exact-source-02/new-publish-worktree.stdout](recovered-exact-source-02/new-publish-worktree.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/pre-push-preflight.stderr](recovered-exact-source-02/pre-push-preflight.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/pre-push-preflight.stdout](recovered-exact-source-02/pre-push-preflight.stdout) | 177 | `390eaae41b4cea9817edf58dae3def992730ea1e0af10cf6403a7fd9e47bd304` |
| [recovered-exact-source-02/preflight.stderr](recovered-exact-source-02/preflight.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/preflight.stdout](recovered-exact-source-02/preflight.stdout) | 177 | `390eaae41b4cea9817edf58dae3def992730ea1e0af10cf6403a7fd9e47bd304` |
| [recovered-exact-source-02/preserve-mirror-branch.stderr](recovered-exact-source-02/preserve-mirror-branch.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/preserve-mirror-branch.stdout](recovered-exact-source-02/preserve-mirror-branch.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/publish-recovered.stderr](recovered-exact-source-02/publish-recovered.stderr) | 688 | `5d9113a1611b6cbd83ad9649bf079f7683dde1d38d6fda83af06e96c762ddb8b` |
| [recovered-exact-source-02/publish-recovered.stdout](recovered-exact-source-02/publish-recovered.stdout) | 309 | `5e6294756fdd55400dbd0ed1feb5dc122381286a7eb80a06667e1446141573ba` |
| [recovered-exact-source-02/query-models.stderr](recovered-exact-source-02/query-models.stderr) | 3705 | `5c462af496808c9940f8ca0f7717fe351e4ba5e31e67f0ebf11ac56ddfd0ab78` |
| [recovered-exact-source-02/query-models.stdout](recovered-exact-source-02/query-models.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/remote-readback.stderr](recovered-exact-source-02/remote-readback.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/remote-readback.stdout](recovered-exact-source-02/remote-readback.stdout) | 41 | `9e399935db055b079ce36be4a7eddecce414369cf8b0c21869042f64c9bd2f14` |
| [recovered-exact-source-02/rust-format.stderr](recovered-exact-source-02/rust-format.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/rust-format.stdout](recovered-exact-source-02/rust-format.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/source-inventory.stderr](recovered-exact-source-02/source-inventory.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/source-inventory.stdout](recovered-exact-source-02/source-inventory.stdout) | 35 | `8bd8670851048e151182dd0f0bc26834d54e151f39ca53f06c98e06c4479c51a` |
| [recovered-exact-source-02/sparse-init.stderr](recovered-exact-source-02/sparse-init.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/sparse-init.stdout](recovered-exact-source-02/sparse-init.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/sparse-select.stderr](recovered-exact-source-02/sparse-select.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/sparse-select.stdout](recovered-exact-source-02/sparse-select.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [recovered-exact-source-02/strict-owner-clippy.stderr](recovered-exact-source-02/strict-owner-clippy.stderr) | 4287 | `b5430f9e47554444fce486b3df87fd1fe485b025cc857b204c7b1021a71a8f3b` |
| [recovered-exact-source-02/strict-owner-clippy.stdout](recovered-exact-source-02/strict-owner-clippy.stdout) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

## Retained transfer and local verification files

| Relative path | Bytes | SHA-256 |
| --- | ---: | --- |
| [remote-copy-manifest.json](remote-copy-manifest.json) | 47103 | `be3594c56ba817d94851585eeb22d8bef0d02db54dac10870c691d50344dd416` |
| [transport/checks-summary.json](transport/checks-summary.json) | 24504 | `42d500afd3b4ebd209656b1bbbf2ad1c5505c5d829a0ef15b2d21b67590b183d` |
| [transport/chunks.jsonl](transport/chunks.jsonl) | 4838 | `6ebea3642f0a2d60a65dbe8e323644823e9a43153b20bcf8f4e0a7f05863bacb` |
| [transport/download-receipt.json](transport/download-receipt.json) | 2716 | `993c86d1589f1c6f07af26f24f102e2e58800f499ed2ede8febdf817739e9c9e` |
| [transport/metadata-write-attempt-01.stderr](transport/metadata-write-attempt-01.stderr) | 383 | `815b5a9436a5d8f2eb70966b621204f7e113b6b5ca47fe371ca973695a3837e9` |
| [transport/preflight-and-inventory.log](transport/preflight-and-inventory.log) | 2251 | `d7d9b16b02ead12b3a23c3edcf90a02e077864a46cc7af52ffdedba65e120f28` |
| [transport/recovered-source-gates-20261107-transfer-v1.tar.gz](transport/recovered-source-gates-20261107-transfer-v1.tar.gz) | 854280 | `5fda3a5d87d3a8b5dbd41d40a9f2c613d7866c6af2e4b3bbc82c20d9c88c8829` |
| [transport/verification-command.json](transport/verification-command.json) | 220 | `da3080f3f96a1a59faa7b4c6d402fea548e78655ffba3549e2689a3aa6adb12c` |
| [transport/verification.json](transport/verification.json) | 789 | `cb4ed221b6459ab0489de068f33fbe8c231ccda637ec55dd5afd8813ba3563a5` |
| [transport/verification.stderr](transport/verification.stderr) | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| [transport/verify-transfer.py](transport/verify-transfer.py) | 6890 | `e236eb8963903e0ab022f8c0a5640f812dbd2d0a27af8129f7e0293aa5460d11` |
| [README.md](README.md) | This document | Self-describing inventory |

## Complete original-directory inventory

- `model-publications`
- `recovered-exact-source`
- `recovered-exact-source-02`
- `recovered-exact-source-02/composition`
- `recovered-exact-source-02/composition/native_packet_publications`
- `recovered-exact-source-02/composition/native_packet_publications/artifacts`
- `recovered-exact-source-02/composition/signed_false_producer_statement`
- `recovered-exact-source-02/composition/signed_false_producer_statement/artifacts`
- `recovered-exact-source-02/native-owner-journal`
- `recovered-exact-source-02/native-owner-journal/alice-journal`
- `recovered-exact-source-02/native-owner-journal/alice-journal/packets`
- `recovered-exact-source-02/native-owner-journal/alice-store`
- `recovered-exact-source-02/native-owner-journal/bob-journal`
- `recovered-exact-source-02/native-owner-journal/bob-journal/packets`
- `recovered-exact-source-02/native-owner-journal/bob-store`
- `recovered-exact-source-02/native-owner-journal/crash-journal`
- `recovered-exact-source-02/native-owner-journal/crash-journal/packets`
- `recovered-exact-source-02/native-owner-journal/crash-store`
- `recovered-exact-source-02/native-owner-journal/old-crash-journal`
- `recovered-exact-source-02/native-owner-journal/old-crash-journal/packets`
- `recovered-exact-source-02/native-owner-journal/old-crash-store`
- `recovered-exact-source-02/native-owner-journal/orphan-journal`
- `recovered-exact-source-02/native-owner-journal/orphan-journal/packets`
- `recovered-exact-source-02/native-owner-journal/orphan-store`
- `recovered-exact-source-02/native-owner-journal/recovered-crash-journal`
- `recovered-exact-source-02/native-owner-journal/recovered-crash-journal/packets`
- `recovered-exact-source-02/native-owner-journal/recovered-crash-store`
