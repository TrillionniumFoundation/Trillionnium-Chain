## Problem

The retained copied-lease socket regression exposed an ordering conflict: a second owner’s connect-only liveness probe correctly refused takeover but woke the incumbent’s accept-time pathname check. The incumbent exited before the fixture restored its original lease pathname.

## Changes

Remove only the redundant accept-time socket-owner check. The existing bounded complete-frame path still checks the same lease pathname identity before checkpoint export, lookup, compare-and-advance or a protocol response. Preserve all three original socket regressions and add a complete-request negative control requiring the precise pathname fence, nonzero daemon exit, and unchanged socket identity and journal bytes.

## Native validation — Draft HOLD

- Tested source: 7d4303f1a9ba3c259b92e58b85126eef3c5378a1.
- Source tree: 2a580a0444f56c0e70e0d73a7fad1120367d1e9e.
- Fixed parent evidence: 09e4801308366fac01e55bcbdcf8bdfd4e6d2810, stacked on #945.
- Evidence-only sole child: b62cb86d22405dd9e5b441970639b6e5dd44a8b8.
- Scoped native result: FAIL / incomplete.
- Raw originals and ordered part manifest: evidence/checkpoint-socket-probe-20261112-df05/PUBLICATION_PACKAGE.json.

| Original command | Exit | Timed out | Outer limit (s) | Elapsed (s) |
| --- | ---: | :---: | ---: | ---: |
| preflight | 0 | false | 120 | 12.982 |
| rustc-version | 0 | false | 120 | 12.692 |
| cargo-version | 0 | false | 120 | 12.598 |
| openssl-version | 0 | false | 120 | 12.443 |
| metadata-default | 0 | false | 300 | 13.008 |
| metadata-all-features | 0 | false | 300 | 12.664 |
| metadata-fuzz | 0 | false | 300 | 12.743 |
| format | 1 | false | 300 | 38.793 |
| source-integrity-controls | 0 | false | 600 | 27.501 |
| repository-links | 0 | false | 600 | 57.545 |
| research-corpus | 0 | false | 600 | 22.382 |
| source-inventory | 0 | false | 300 | 17.762 |
| checkpoint-package | 0 | false | 1200 | 24.014 |
| strict-workspace-clippy | 0 | false | 3600 | 190.611 |

The complete checkpoint package retained the original 1200-second outer limit, compile profile, two build jobs, test-thread setting, and internal transport bounds. Its observed libtest blocks are:

| Block | Passed | Failed | Ignored | Measured | Filtered | Consistent |
| ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| 1 | 18 | 0 | 0 | 0 | 0 | True |
| 2 | 15 | 0 | 0 | 0 | 0 | True |
| 3 | 15 | 0 | 0 | 0 | 0 | True |
| 4 | 6 | 0 | 0 | 0 | 0 | True |
| 5 | 4 | 0 | 0 | 0 | 0 | True |
| 6 | 0 | 0 | 0 | 0 | 0 | True |

Observed required socket results:

- `rejected_nonprivate_socket_parent_does_not_unlink_existing_listener`: ok.
- `different_admitted_journal_cannot_replace_a_live_checkpoint_endpoint`: ok.
- `copied_lease_record_cannot_replace_a_live_checkpoint_endpoint`: ok.
- `complete_checkpoint_request_rejects_a_copied_lease_replacement`: ok.

Package parse observations: `[]`.
The source-integrity controls require exactly 43 successful original cases; observed verdict: `true`.

## Preserved prior evidence

The earlier Root source 87943f6229d8785c3f431ede5eadba62b634ab8c and evidence 09e4801308366fac01e55bcbdcf8bdfd4e6d2810 retain their original suite timeouts and socket exit 101. This follow-up did not rerun the Root V3/V4/V5/V6 suites, and none of those results was relabelled to the new source or evidence child. The prior ignored-log staging refusal and exact staging-only recovery receipt are retained separately; no old receipt was repaired or hidden.

The first socket validation attempt stopped at target admission because its recorded prior build directory was absent, with zero command records. Its original FAILED.json and traceback remain under prior-validation-v1. This attempt instead uses a newly created empty private target with identity checked before and after every command. It does not reconstruct or claim reuse of the missing target; original command arguments, profile, resources and time limits remain unchanged.

## Scope

The source delta is limited to two Rust paths, a prepend to the sole development plan, and the three corresponding existing corpus pins. The archival child adds only manifest-bound evidence and new corpus pins/required paths. All existing non-corpus source modes and blobs remain equal to the tested source.

This remains Draft HOLD. No production merge, deployment or activation is authorized. ARM, an unbuilt GitHub prospective merge, the original three 30-second campaigns, whole-chain post-quantum qualification, independent witness custody and actual external provider effects remain outside this scoped result.

Exact original command arguments:

- `bash scripts/project-preflight.sh`.
- `/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustc -Vv`.
- `/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/cargo -V`.
- `/home/qian-qi/credit-envelope-f7e62-provider2/runner/trnm-pq-provider-3.5.9.5yXdk2mN/install/bin/openssl version -a`.
- `/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/cargo metadata --locked --offline --format-version 1 --manifest-path trillionnium/Cargo.toml`.
- `/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/cargo metadata --locked --offline --format-version 1 --all-features --manifest-path trillionnium/Cargo.toml`.
- `/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/cargo metadata --locked --offline --format-version 1 --manifest-path tests/fuzz/Cargo.toml`.
- `/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check`.
- `/usr/bin/python3 -B -m unittest discover -s scripts/ci -p test_ci_source_integrity.py -v`.
- `/usr/bin/python3 -B scripts/ci/check_repository.py`.
- `/usr/bin/python3 -B scripts/ci/check_pq_research_integration.py`.
- `/usr/bin/python3 -B scripts/refresh_distributed_source_inventory.py --check`.
- `/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-checkpoint-store -- --show-output --test-threads=1`.
- `/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/cargo clippy --locked --offline --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings`.
