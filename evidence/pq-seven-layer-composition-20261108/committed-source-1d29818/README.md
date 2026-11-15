# Committed-source validation

Tested source: `1d29818ad927f549f43d74a06f51e91771feac70`. Aggregate command result: **PASS**
(29 / 29 commands completed).
Runtime job: `1a1baff7670-12894-1ef7`. This is an operator-host scoped validation, not
independent system acceptance.

The [original summary](summary.json), [exact command vectors](commands.json),
[source before](source-before.json), and [source after](source-after.json) retain
their original bytes. [Capture encoding](capture-encoding.json) maps every
original stdout/stderr stream to its lossless gzip file and records both hashes.
The original command outcomes are unchanged. A later source has a separate run.

| Command | Exit | Gate | Observed suite result |
| --- | --- | --- | --- |
| preflight | 0 | PASS | command gate |
| source-before | 0 | PASS | command gate |
| lifetime-tests | 0 | PASS | 58 tests: OK |
| claim-tests | 0 | PASS | 49 tests: OK |
| effect-register-tests | 0 | PASS | 18 tests: OK |
| root-policy-tests | 0 | PASS | 26 tests: OK |
| lifetime-report | 0 | PASS | command gate |
| claim-report | 0 | PASS | command gate |
| effect-register-report | 0 | PASS | command gate |
| root-policy-example | 0 | PASS | command gate |
| pq-source-integration | 0 | PASS | command gate |
| pq-source-negatives | 0 | PASS | 55 tests: OK |
| authority-scanner-negatives | 0 | PASS | 15 tests: OK |
| ci-contract | 0 | PASS | command gate |
| ci-contract-negatives | 0 | PASS | 105 tests: OK |
| source-integrity-negatives | 0 | PASS | 43 tests: OK |
| repository | 0 | PASS | command gate |
| repository-negatives | 0 | PASS | 50 tests: OK |
| distributed-inventory | 0 | PASS | command gate |
| diff-check | 0 | PASS | command gate |
| cargo-version | 0 | PASS | command gate |
| metadata-default | 0 | PASS | command gate |
| metadata-all-features | 0 | PASS | command gate |
| metadata-fuzz | 0 | PASS | command gate |
| formatting | 0 | PASS | command gate |
| strict-workspace-clippy | 0 | PASS | command gate |
| native-crypto-default | 0 | PASS | 165 passed / 0 failed / 0 ignored / 0 filtered |
| native-hepta-pq-comparator | 0 | PASS | 6 passed / 0 failed / 0 ignored / 0 filtered |
| source-after | 0 | PASS | command gate |

Counts belong to their named commands; they are not a deduplicated total across
all suites. Corpus pins are not tests. The native tests cover the default crypto
library and the Hepta PQ comparator only. The complete Node suite and the two
failed #796 release-owner tests were not run by this campaign. The earlier #796
aggregate FAIL remains separately preserved in the parent packet.

The whole-chain qualification, production activation, complete Node campaign,
and hosted-CI acceptance fields in the original summary remain false.

This source includes the canonical inventory repair. The delivery commit adds
only files beneath `evidence/pq-seven-layer-composition-20261108/`; code, Cargo
graphs, lockfiles, CI definitions, configuration, generated source inventory,
and formal policy files remain identical to this tested source. The delivery
head receives a separate raw-source and repository-integrity check; that is not
a second native campaign.
