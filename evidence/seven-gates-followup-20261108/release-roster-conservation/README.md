# Release roster conservation at bb026697

This evidence reconciles the retained native stdout with the exact release-crate source and the immutable original 52-test manifest. It does **not** change the original collector or turn the original 32-command campaign into a pass. The original collector rejection must remain in the campaign record.

## Result

On the observed Unix target, the exact set equality is:

**55 native passed names = original 37 + initial-root-material 6 + quorum-preflight 9 + pre-existing content tests 3.**

The retained stdout contains one libtest summary: **55 passed, 0 failed, 0 ignored, 0 measured, 0 filtered out**. Its 55 result rows have 55 distinct names. Every original manifest name occurs exactly once with outcome `ok`; there are no missing original names, duplicate names, or unexplained extras. The independently enumerated direct source test definitions and reviewed module registrations produce the same 55 names. The parser matches only `test <name> ... <outcome>` rows, so the repeated names in the later `successes:` section are not counted twice.

The parent task reports process exit code 0. The retained stdout itself does not independently prove process exit status, build/source identity, or provider identity; those remain the responsibility of the original campaign's command and source receipts. This reconciliation makes no substitute claim for them.

## Fixed sources and history

| Item | Exact identity |
| --- | --- |
| Final Chain source | `bb026697a972521009bc133ae6ed2b653e18e931` |
| Final source tree | `18175756871bf341586fc37be1b17a00ef1dd099` |
| Earlier #812 source | `7e044b65454f4c9ea505591727332acffb33e7e5` |
| Release-crate tree at both sources | `326e561cfdf894b64c8115b538c78809278a80a6` |
| Three-test introduction commit | `155c8e3a8c188ba113accb4079e9ad344d5c63a1` |
| Introduction parent | `12e510b211110d93d9ead07e02c07a1eecc28ae9` |
| Retained native stdout SHA-256 | `ae0c50c82ed0682bb5ed1fc81620283d68954839f95be03d15a5b52302aabb2a` |

The introduction commit is titled `feat(security): bind CPQ1 authorization to complete content`. Its content-test file is absent from its parent. The introduction commit is an ancestor of `7e044b6`, which is an ancestor of `bb026697`. The content-test file has had no subsequent path-history changes and retains Git blob `0e850dd1e82a8b0ec56d62eab554dd01cf9cfe77` from introduction through both fixed sources. The entire release crate is unchanged between the two fixed sources. Thus these are additional names relative to the old 52-name manifest, **not tests introduced by this follow-up integration**.

The three additional names, all under `content_v1::tests::`, are:

| Test | Definition | Scope |
| --- | --- | --- |
| `complete_artifact_and_all_metadata_enter_the_strong_commitment` | `src/content_v1/tests.rs:35` | All targets compiling this module |
| `retained_file_reads_exact_bytes_and_refuses_partial_offset` | `src/content_v1/tests.rs:96` | `#[cfg(unix)]` |
| `short_long_wrong_locator_and_old_digest_wrapper_are_refused` | `src/content_v1/tests.rs:70` | All targets compiling this module |

The 55-name statement is scoped to this Unix execution; it is not a platform-independent test-count contract.

## Complete source roster accounting

The complete per-name source map, definition lines, attributes, original partitions, and native result names are retained in `roster-conservation.json`.

| Registered module | Direct test definitions |
| --- | ---: |
| `tests` | 2 |
| `pq_release::tests` | 16 |
| `pq_release::tests::current_tests` | 5 |
| `pq_release::tests::validated_root_tests` | 4 |
| `pq_release::tests::bundle_quorum_tests` | 6 |
| `pq_release::tests::retained_verifier_tests` | 4 |
| `pq_release::tests::initial_root_material_tests` | 6 |
| `pq_release::tests::quorum_preflight_tests` | 9 |
| `content_v1::tests` | 3 |
| **Total** | **55** |

All direct `#[test]` attributes in the tracked crate Rust files are accounted for. There are no tracked additional test/example/bench/bin source directories in this crate. No `#[ignore]` annotation was found in the tracked Rust sources. This is a finite, reviewed module enumeration, not a general Rust macro or configuration evaluator; the native stdout supplies the actual executed roster.

## Original rejection is preserved

The unchanged runner `evidence/pq-authority-preflight-20261108-9d315/authority-final-validation-runner.py` requires the exact disjoint `37 + 6 + 9 = 52` inventory from `config/pon/pq-initial-root-material-required-tests-v1.json`. It rejects a 55-name execution even when all 52 original names and three separately understood names pass. The expected preserved error is:

`raw release libtest execution differs from exact 52 passed, zero ignored`

| Immutable input | SHA-256 | Git blob at both fixed sources |
| --- | --- | --- |
| Original runner | `d81437a1cef461666b9103cc3f9e8f8ab0c67a90903b5802f582d2c52cd82710` | `1e1955540157c0b5378d3ab708199fa81678933e` |
| Original 52-name manifest | `a359086820e876a3806acdd1225689ff072ebfe10d455ac3a96d8d7060680693` | `0c14ebf5c70fb0f7ee823d324897e12fb41820c8` |
| Three-test source | `8661b99da563148371ef16f470ab6f112390755ebcf0fc09372e517fb3f100f1` | `0e850dd1e82a8b0ec56d62eab554dd01cf9cfe77` |

The source checkout was clean before and after reconciliation. No Cargo command was executed, no test was rerun, and neither the source, immutable runner, nor original manifest was edited. Overall qualification remains **HOLD**. This artifact grants no whole-chain PQ, payment, WAN, or original-campaign qualification.

## Retained material and reproduction

- `roster-conservation.json`: complete 55-name reconciliation, original 52-name partitions, per-name source mapping, identities, and explicit non-qualification fields.
- `git-history-readback.json`: exact read-only Git commands, exit codes, and returned history/source identities.
- `release-bb026697.stdout.log`: byte-identical retained native stdout.
- `source/`: exact copies of the tracked release crate, immutable original runner, and original manifest.
- `reconcile_release_roster.py`: evidence-only reader; it never invokes Cargo or writes inside the source repository.
- `SHA256SUMS`: digest inventory for this evidence directory, excluding the inventory itself.

To reproduce only this read-only reconciliation against an existing clean final-source checkout, use an output directory outside that checkout:

```sh
python3 -B reconcile_release_roster.py \
  --repo /path/to/clean/bb026697-checkout \
  --log /path/to/release-bb026697.stdout.log \
  --out /path/to/new-evidence-directory
```

This reproduction is a source/log readback, not the original native campaign.
