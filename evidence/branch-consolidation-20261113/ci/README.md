# CI and PQ branch consolidation review

Status: **HOLD for final composed-source qualification**. This records 103 assigned tips,
including 39 detailed legacy-workflow reviews and 64 additional source-family reviews.
The exact input worklists, original heads, merge bases, core paths and decisions are in
[ledger.json](ledger.json). Source declaration matches are supporting inventory only;
they are not used as a substitute for semantic decisions.

## Compatible integration

The selected ports retain full-name CI assertions, read-only CodeQL permissions,
declared-control/local-material/WAN readers, an always-HOLD P0–P6 reader, the declared
admission-cost model, explicit V5 exit-mm observations, complete legal reference-search
journals, read-only anchored trial reconciliation, explicit V4 recovery handoff, and
the create-only durable PQ outbound journal with sealed reply authority. Existing
consensus, cancellation, release, public-submit recovery and current signed domains
remain owned by their selected implementations. Cross-owned TLS and History ports
are identified by their actual integration commits in the ledger.

## Historical alternatives

Old source publishers, blob stagers, toolchain exporters, destructive maintenance,
self-hosted relay recovery and frozen campaign readbacks remain historical. No such
workflow was dispatched or reactivated. Alternate initial-root optimizations, Rust1.99
qualification, frozen W1 continuation/succinct profiles, old Node PQ codecs and old
global reservation accounting are explicit alternatives, not falsely claimed as
implemented equivalents. The root integrator verifies their original Git ancestry.

## Validation limits that remain visible

- Original CI drift, native compile failures, sparse-material failures and local host
  ownership refusals are retained with their exact log bytes.
- Native outbound9/9 passed on unchanged source bytes using local OpenSSL3.5.7.
  Hosted pinned3.5.9 and the final composed-source gate remain independently required.
- The preliminary outbound doctest was not observed complete and is not counted PASS.
- After host recovery, 16 scoped CI contract tests and three outbound roster tests
  passed; Rust1.95 formatting and diff checks also passed. No new native build was run.
- The interrupted source writer and two readers returned exit130. Their original
  stale zero-byte index lock was retained before the reviewed source commit resumed.
- Two actual nonroot installed-ELF handoff controls fail because this container lacks
  root-owned /usr ancestors. Neither the ownership rule nor required controls changed.
- Original30s source replay could time out under the shared-host load. No deadline
  was extended to turn a resource-limited run into qualification.
- Current source registers and corpus pins must be rebound only after composition;
  original frozen artifact, source, run and failure identities must remain immutable.

## Per-tip disposition

| Original head | Branch | Decision |
| --- | --- | --- |
| [55033605dc](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/55033605dc738908304ae7ac7a6493452c37c4b5) | `archive/chain-pon-v2-summarizer-20261105-gpt6` | COMPATIBLE_SOURCE_PORTED_AND_HISTORICAL_CAMPAIGN_RETAINED |
| [c592cccdfb](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/c592cccdfb5c0c4004fcae25aadeaab1b11d4b1c) | `archive/library-chain-pql3-pcs1-source-20261104` | EXACT_INERT_ARCHIVE_ALREADY_RETAINED |
| [2c5349cb78](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/2c5349cb785d83e007b06c7af4ab1262277ad870) | `diagnostic/chain-fuzz-asm-lock-20261104-gpt6` | HISTORICAL_WORKFLOW_ONLY |
| [1ac0628e1b](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/1ac0628e1bed5ecf097498d3e9c21cc8eb436b9f) | `archive/host-source-custody-20261103-desktop-v2` | EXACT_INERT_ARCHIVE_ALREADY_RETAINED |
| [3f0f21db85](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/3f0f21db859df0ead267ed52b1a4f9611e4773fc) | `archive/chain-initial-root-cloud-evidence-20261104` | ALTERNATIVE_INITIAL_ROOT_OPTIMIZATION_ARCHIVED |
| [38fda50fa3](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/38fda50fa39f338fdbf30afc4ed2f003e41cd183) | `archive/chain-initial-root-borrow-ecb54-20261103` | ALTERNATIVE_INITIAL_ROOT_OPTIMIZATION_ARCHIVED |
| [28fb63124e](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/28fb63124e535227563da9f23873b4cc56783c11) | `archive/chain-state-json-failed-d55daefd-20261103` | ALTERNATIVE_INITIAL_ROOT_OPTIMIZATION_ARCHIVED |
| [98447abce3](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/98447abce355a50810bd3b658ce53c659ceb3411) | `chore/chain-library-small-source-20261103-gpt6` | EXACT_INERT_ARCHIVE_ALREADY_RETAINED |
| [d48c8070f1](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/d48c8070f1dfe406a7405fd875909b68db0e6b9a) | `archive/library-bundle-source-20261103-gpt6` | EXACT_INERT_ARCHIVE_ALREADY_RETAINED |
| [d3b9abedeb](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/d3b9abedeb05909173305bf773714ca380950600) | `evidence/chain-completed-w1-and-ticket-costs-20261028` | FROZEN_ALTERNATIVE_PROOF_PROFILE_ARCHIVED |
| [c61e2112de](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/c61e2112de67f9295258246b42d3c3ebf652d445) | `evidence/pon-root-supplement-c61e211-20261022` | COVERED_BY_SELECTED_SOURCE |
| [17ff05b5a2](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/17ff05b5a2dc93c901dcd76906e9831341d02781) | `maintenance/actions-storage-reclaim-20261022` | HISTORICAL_WORKFLOW_ONLY |
| [64771d99de](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/64771d99de08d917631a8c3e1bc8c8a62e4db9da) | `ops/github-storage-audit-20261022` | HISTORICAL_WORKFLOW_ONLY |
| [086a5b67d0](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/086a5b67d07278c95972ce9b4587d3eab6125a52) | `ci/pon-chain316-main-target-merge-20261015` | COVERED_BY_SELECTED_SOURCE |
| [32f8355f90](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/32f8355f904a5e70ababaf74e70386a6d9f033ac) | `ci/pon-source-bundle-20261011` | HISTORICAL_WORKFLOW_ONLY |
| [b9b981ffc3](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/b9b981ffc3aafb210f43395a9fe576f1fb691693) | `ci/pon-five-track-source-repair-20261012-r2` | HISTORICAL_WORKFLOW_ONLY |
| [f4a60bb6bc](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/f4a60bb6bc0cb8eff1de14a0f3fe49a742120b87) | `ci/pon-native-workbench-20261012-r1` | HISTORICAL_WORKFLOW_ONLY |
| [6a09d7ac50](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/6a09d7ac50f317f5ade592fbc57a5a7c03396ebd) | `ci/pon-baseline-source-repair-20261012` | HISTORICAL_WORKFLOW_ONLY |
| [89d38b5937](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/89d38b5937b3c9822a2cc7037042294f39a76df7) | `tools/pon-exact-bundles-20261011` | HISTORICAL_WORKFLOW_ONLY |
| [8ed17cf06b](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/8ed17cf06bec65a098b1f5d6befd82e79cc38929) | `chore/chain-work-collector-stage-20261011` | HISTORICAL_WORKFLOW_ONLY |
| [60a0cb3826](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/60a0cb3826d5622bebb26d98f83a4904484bc82a) | `tooling/pon-fixed-native-source-stage-20261011` | HISTORICAL_WORKFLOW_ONLY |
| [bccf7063f3](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/bccf7063f33d35d5be48640f68f6bbbf3a22c243) | `ci/pon-five-track-native-export-20261011` | HISTORICAL_WORKFLOW_ONLY |
| [753f683db8](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/753f683db8e1f5f0a11926f5c7f9459e99589156) | `tooling/pon-canonical-kernel-stage-20261011` | HISTORICAL_WORKFLOW_ONLY |
| [9e471e2369](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/9e471e2369d99623e0320412a237454ed90ecd1b) | `tooling/pon-cpu-conservation-publication-20261011` | HISTORICAL_WORKFLOW_ONLY |
| [5600b8ddd7](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/5600b8ddd70a5d1394b9a024d26f5cd1a43f5748) | `tooling/pon-offline-native-kit-20261011` | HISTORICAL_WORKFLOW_ONLY |
| [291be2c8fe](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/291be2c8fef2ffacd5cd3550f9381d0332250775) | `dev/pon-five-axis-source-export-20261011` | HISTORICAL_WORKFLOW_ONLY |
| [887a6f7e1a](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/887a6f7e1ad66dafba67aec4f7a478b12fc00849) | `tools/pon-audit-source-transport-20261011` | HISTORICAL_WORKFLOW_ONLY |
| [67c057b48e](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/67c057b48e1ef72bf2b42b6189c1f86b26fa6843) | `tools/pon-source-export-20261011` | HISTORICAL_WORKFLOW_ONLY |
| [f2b98437f9](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/f2b98437f9a3f37d587a2708bf1908a332faaf14) | `work/pon-batched-confirmation-source-20261011` | HISTORICAL_WORKFLOW_ONLY |
| [634fd8efb8](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/634fd8efb8ecc39a386383baef882d6c48d08d80) | `work/pon-cpu-conservation-runtime-20261011` | ALTERNATIVE_RESERVATION_POLICY_ARCHIVED |
| [9cd31d3a08](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/9cd31d3a088bb73d5ebbe6737a440d2e64bff5b9) | `ci/pon-local-toolchain-export-20261011` | HISTORICAL_WORKFLOW_ONLY |
| [e4fbaee63d](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/e4fbaee63d0d01edf8c7aefedff45083f1ee473f) | `ci/pon-pressure-window-source-20261010` | HISTORICAL_WORKFLOW_ONLY |
| [06aa0bef38](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/06aa0bef38c73491cc6726a326ea6f157acc6cfe) | `dev/pon-snapshot-verified-delivery-20261010` | HISTORICAL_WORKFLOW_ONLY |
| [1311db987f](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/1311db987f4d22eefc696587126ba30f151eed20) | `dev/pon-five-axis-offline-export-20261010` | HISTORICAL_WORKFLOW_ONLY |
| [e594e4c20e](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/e594e4c20e8dab293f6e3a5a980e294a9ae0f719) | `work/pon-nullable-blob-staging-20261010` | HISTORICAL_WORKFLOW_ONLY |
| [1938bbc570](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/1938bbc5706ebdd880302ca99dd2875ebc7b483f) | `ci/pon-fixed-blob-inventory-stage-20261010` | HISTORICAL_WORKFLOW_ONLY |
| [1c27fda200](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/1c27fda2001a242a7285f305bd13760971e47519) | `ci/pon-fixed-blob-bounds-stage-20261010` | HISTORICAL_WORKFLOW_ONLY |
| [4e2b0f7c2b](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/4e2b0f7c2b074731dd94237b4610476a34bc39d9) | `staging/pon-sql-reuse-20261009` | HISTORICAL_WORKFLOW_ONLY |
| [128d9d6ddf](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/128d9d6ddf92841618328b1399e52565bfc01395) | `ci/pon-native-snapshot-qualification-20261009` | HISTORICAL_WORKFLOW_ONLY |
| [8805ce62ff](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/8805ce62ff28e76ca4636a0ca1e4465b61fe7911) | `ci/pon-packed-branch-qualification-20261009` | HISTORICAL_WORKFLOW_ONLY |
| [b74508f1db](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/b74508f1db7e804436605a428773da41815f7c54) | `diagnostic/pon-five-native-lab-20261009` | HISTORICAL_WORKFLOW_ONLY |
| [ffbdf1b1b0](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/ffbdf1b1b0626af25c64095a889118ff7c5305f5) | `repair/pon-history-cost-20261009` | HISTORICAL_WORKFLOW_ONLY |
| [a77d94db15](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/a77d94db1525f5cfeec0433b27d9c0ceadde1e1d) | `ci/pon-architecture-source-check-20261008` | HISTORICAL_WORKFLOW_ONLY |
| [cecee753c7](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/cecee753c785b1a1ceb511c75ba85b1996b8bd13) | `dev/chain-observation-delivery-20261007` | HISTORICAL_WORKFLOW_ONLY |
| [78d0237083](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/78d0237083ea753ce714a3184d2a8b49a0934a90) | `evidence/chain-sixline-native-20261007` | HISTORICAL_WORKFLOW_ONLY |
| [7be021f745](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/7be021f745fa7b3cd9c9f5063304026f3b1a52f2) | `dev/chain-directed-delivery-20261006` | HISTORICAL_WORKFLOW_ONLY |
| [ce86ecd201](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/ce86ecd2019fc2344482db7e75a11f23b44e9a09) | `work/chain-offline-build-transfer-20261006` | HISTORICAL_WORKFLOW_ONLY |
| [6363c83995](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/6363c8399589b84c6837cd14610bc67c11a82aaf) | `dev/chain-native-delivery-20261005` | HISTORICAL_WORKFLOW_ONLY |
| [4eca52d447](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/4eca52d447624c54156357ba54baa2cec7601a7b) | `dev/chain-exact-source-20261005` | HISTORICAL_WORKFLOW_ONLY |
| [2d20365dd5](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/2d20365dd5bfa6df086786fbfdd4854450ee4b5f) | `chore/chain-rust-199-20261004` | ALTERNATIVE_COMPILER_QUALIFICATION_ARCHIVED |
| [a6e78fd090](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/a6e78fd090e018e0c07f825ee6751d877259d9e0) | `chore/chain-development-overhead-20261002` | COMPATIBLE_CALLER_CONTROL_PORTED_ALTERNATE_CLEANUP_ARCHIVED |
| [2c3e885e03](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/2c3e885e033cbe8a5d9d34ef161c7a5c4ed3aad0) | `chore/chain-clear-readme-20260929` | OBSOLETE_DOCUMENT_DELETION_ARCHIVED |
| [b1a787f084](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/b1a787f0848c464a99b1f9854b6c133f933c5c47) | `ops/recover-qian-qi-20260925` | HISTORICAL_OPERATIONAL_WORKFLOW_ONLY |
| [24648a6fdc](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/24648a6fdcac29c31c4676a4ef341ceb755ba9e1) | `fix/pq-source-pin-sqlite-loader-20261107` | COVERED_BY_SELECTED_SOURCE |
| [982131d30c](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/982131d30c33cc474c60027702470c02698461b8) | `fix/chain-pq-format-copy-relative-module-20261107` | COVERED_BY_SELECTED_SOURCE |
| [e42f85ed5b](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/e42f85ed5b1d0b4c9ebcfd8d5bd3247becb74959) | `fix/chain-pq-transport-custody-gates-20261106-a864cf` | COMPATIBLE_SOURCE_PORTED_ALTERNATE_ENDPOINT_ARCHIVED |
| [bbdb1af203](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/bbdb1af203674fec3923c522a49b3dcc6bbca6bc) | `fix/chain-pq-roster-harness-20261107-6f8b` | COMPATIBLE_SOURCE_PORTED |
| [5c148d4cd2](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/5c148d4cd2bfd493164f614f4029fe67337aff29) | `fix/chain-pq-roster-52-current-head-20261106-gpt6` | COVERED_BY_SELECTED_SOURCE |
| [cab60041fe](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/cab60041feb52ee58fe79a4a4b51f710e651a08e) | `fix/pq-required-controls-52-20261106-gpt6` | HISTORICAL_PIN_WITH_CURRENT_SUCCESSOR |
| [83735d9600](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/83735d9600a93c6fafe16442df72421a8239ec4e) | `fix/chain-pq-system-roster-52-20261106-gpt6` | HISTORICAL_PIN_WITH_CURRENT_SUCCESSOR |
| [685e734590](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/685e734590cf9fa2effa0ee12e851120e8737a9e) | `dot/pq-fix-branch-native-count-20261105` | COVERED_BY_SELECTED_SOURCE |
| [318a499759](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/318a49975900ae9cd375f76857a5631f783e2f07) | `dot/pq-fix-exact-inventory-link-20261105` | COVERED_BY_SELECTED_SOURCE_WITH_FINAL_REBIND |
| [96d6977ee3](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/96d6977ee3ffd9aedcc897cc6d6211334df5e107) | `fix/pq-system-ci-job-source-pin-20261104` | HISTORICAL_PIN_WITH_CURRENT_SUCCESSOR |
| [013bd4bab7](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/013bd4bab7a336b12e64ec90909f317f6f223e27) | `test/chain-pq-normal-source-merge-20261103` | ALTERNATIVE_INITIAL_ROOT_OPTIMIZATION_ARCHIVED |
| [fe9cd0ba3c](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/fe9cd0ba3ca85901adfa8e444465eb6d486e5f5c) | `test/chain-pq-normal-source-20261103` | ALTERNATIVE_INITIAL_ROOT_OPTIMIZATION_ARCHIVED |
| [440a510ac5](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/440a510ac5ea23662ac7dcbaff2eafd04f60b2fd) | `fix/chain-pq-observation-fnonce-followup-20261104-gpt6` | COVERED_BY_SELECTED_SOURCE |
| [fb57ce7dcf](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/fb57ce7dcfa9b5e6740e9e387f4e8200f1120587) | `recovery/library-pqn4-w1-native-20261103-gpt6` | EXACT_INERT_ARCHIVE_ALREADY_RETAINED |
| [0865f74dee](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/0865f74deee7194aa52820a8dd8077c986b1843a) | `recovery/library-offline-pq-20261103` | HISTORICAL_EVIDENCE_ONLY |
| [b0b99d7bb7](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/b0b99d7bb7827b6cb97b49c1cabfb2d4e4ef7fec) | `docs/chain-pq-acceptance-recovery-20261101` | HISTORICAL_FAILURE_EVIDENCE_ONLY |
| [201e8f5e3b](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/201e8f5e3b105ce81112a876224fadd5e08eebe7) | `fix/chain-pq-active-tip-test-query-20261031` | COVERED_BY_SELECTED_SOURCE |
| [b46d17be9b](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/b46d17be9b7aaa837b791812720ea3fe5b8d4184) | `fix/chain-pq-shared-npq5-test-fixture-clippy-20261031` | COVERED_BY_SELECTED_SOURCE |
| [79d2e8dc3d](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/79d2e8dc3dc26770249af1c2961632b2134cce93) | `fix/chain-pq-native-ci-regressions-20261031` | COVERED_BY_SELECTED_SOURCE |
| [3dfdb1e08f](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/3dfdb1e08f3cb64471c5b7e0748ac337e2a02010) | `fix/chain-pq-hepta-handoff-v2-20261031` | COVERED_BY_SELECTED_SOURCE |
| [87056297a3](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/87056297a3d23b833015bf13ee2bf7f57d809e80) | `audit/chain-pq-authority-surfaces-20261031` | COVERED_BY_SELECTED_SOURCE |
| [35cca89eb1](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/35cca89eb13c6246a7e8893070b880bfd977adce) | `audit/pq-policy-json-finite-float-20261030` | COVERED_BY_SELECTED_SOURCE |
| [9a96067817](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/9a96067817d20b69d19e4e222bc207242a9c89d4) | `test/chain-native-pq-quota-v3-ci-20261028` | SELECTED_M06_SUCCESSOR_RETAINED_ALTERNATE_NODE_PROFILE_ARCHIVED |
| [f7b044f654](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/f7b044f654b8865b41433dedeb2788f771aea572) | `research/pq-pql5-temp-schema-ack-fence-20261027` | COVERED_BY_SELECTED_SOURCE |
| [e5e92ff2b0](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/e5e92ff2b055b198c087631eb48b4b9ad28e0ad0) | `research/pq-preserved-liability-native-import-20261026` | EXACT_COMPATIBLE_SOURCE_ALREADY_RETAINED |
| [35b4e13594](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/35b4e135949fb069d6d0082a5a7b8c2ce4e38376) | `fix/chain-security-ci-source-lock-20261110` | COVERED_BY_SELECTED_SOURCE_WITH_FINAL_REBIND |
| [b8672afb70](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/b8672afb702e4b0bfff8e2bef2b6144d355442dd) | `fix/chain-system-security-ab60-20261109` | COVERED_BY_SELECTED_SOURCE |
| [4906dbad8e](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/4906dbad8e97c2a252a395b7b581ebbe21a59204) | `fix/chain-codeql-local-sarif-no-upload-20261107` | COMPATIBLE_PERMISSION_NARROWING_PORTED |
| [f006f0d971](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/f006f0d971b25802dda4b6d12ce0f770b1fb993f) | `fix/w1-staged-observer-budget-test-20261107` | CURRENT_STRONGER_BUDGET_CONTROL_RETAINED |
| [919e738373](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/919e7383739b2577836c25c5d39c3bfc1698e46c) | `fix/chain-native-codeql-source-scan-20261106-gpt6` | SAFER_SELECTED_CODEQL_OWNER_RETAINED |
| [728297c907](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/728297c907821a92724e189430d1a0ba5c0e61c9) | `fix/chain-durable-schema-parser-mode-20261107` | COVERED_BY_SELECTED_SOURCE |
| [058a729a27](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/058a729a274b431ed1617efee2725cad8471d966) | `fix/chain-control-domain-evidence-20261106` | COMPATIBLE_SOURCE_PORTED |
| [b6c5ca4651](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/b6c5ca46517710d703e0e059bc3c681c73c22901) | `fix/chain-runtime-marker-metadata-compat-20261106` | COVERED_BY_SELECTED_SOURCE |
| [53f65ff33e](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/53f65ff33eb8b47646b8a95cc5a7923dd50acd20) | `fix/chain-retained-failure-readback-20261104` | HISTORICAL_READBACK_WORKFLOWS_ONLY |
| [3a862b0d4b](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/3a862b0d4b6423885e48e839ad8208b037771239) | `research/chain-original-cpu-readback-20261103-gpt6` | HISTORICAL_READBACK_WORKFLOW_ONLY |
| [2c7c262724](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/2c7c262724158833d7d00a7782f6318dad7e3e3f) | `research/chain-da-sequence-readback-20261104-gpt6` | HISTORICAL_READBACK_WORKFLOW_ONLY |
| [1bb63dabe6](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/1bb63dabe64029cb51c1e064bcd7489981d2d25c) | `fix/ci-owner-cleared-readme-origin-20261103-gpt6` | COVERED_BY_SELECTED_SOURCE |
| [ad490ed4b1](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/ad490ed4b1132a333159fd76702809fd248a4462) | `fix/chain-exit-worker-count-boundary-20261029` | COVERED_BY_SELECTED_SOURCE_AND_HISTORICAL_EXPORTERS |
| [07f22452e4](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/07f22452e4bab3f42c38ff522fab55c07ab0c5a2) | `fix/chain-hepta-task-bound-objective-20261027` | SELECTED_V4_OWNER_RETAINED_HISTORICAL_CAMPAIGN_DRIVER_ARCHIVED |
| [e34a60bf63](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/e34a60bf63236b10f104873ac9ee3190c38f7ec3) | `fix/chain-rss-mm-detached-v5-20261027` | COMPATIBLE_VERSIONED_SOURCE_PORTED |
| [5328d75283](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/5328d7528350df4c910ae25e60f9e97b988ee054) | `automation/chain506-five-native-tests-20261027-1117` | COMPATIBLE_FULL_NAME_ASSERTIONS_PORTED |
| [c2e0e70fed](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/c2e0e70fed5ac1f7b49dad41dd82d4ca43fe7436) | `audit/chain-506-from-zero-five-tests-20261027` | COVERED_BY_SELECTED_SOURCE |
| [428d084bce](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/428d084bceee9699504cfef19617a62fed1c2af8) | `dot/pon-p0-p6-evidence-failclosed-20261026` | COMPATIBLE_SOURCE_PORTED |
| [83ecbbd361](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/83ecbbd361c15fb11df26d2abbc544bbf530bef7) | `dot/p2-v3-economic-feasibility-20261026` | COMPATIBLE_SOURCE_PORTED |
| [34a0f50914](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/34a0f509145607746a1e6b156709bd5680213227) | `dot/p2-false-work-cost-envelope-20261026` | EXACT_COMPATIBLE_SOURCE_ALREADY_RETAINED |
| [a598d58623](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/a598d586239b9c019d4a1cd4df01d70c1d39f387) | `fix/chain-finality-profile-20261014` | SELECTED_DENY_BY_DEFAULT_OWNER_RETAINED |
| [eb94f835ad](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/eb94f835ade72eaa7b0eaf82d6989b783186a913) | `codex/freeze-pon-experimental-20261014` | COVERED_BY_SELECTED_DENY_BY_DEFAULT_OWNER |
| [0774bb04ca](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/0774bb04ca90333737898c79bb7ee9c70feabfc4) | `test/chain-cached-owner-stage-20261009` | HISTORICAL_WORKFLOW_ONLY |
| [b879ab7f4b](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/b879ab7f4bd1500c2f49e1580a1aa560524b880e) | `perf/pon-branch-encoding-stage-20261009` | HISTORICAL_WORKFLOW_ONLY |
| [f0c69ed85d](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/f0c69ed85d1b044d8b38112ed1ff10a5beed592c) | `fix/chain-owner-hotpath-delivery-20261006` | HISTORICAL_WORKFLOW_ONLY |
