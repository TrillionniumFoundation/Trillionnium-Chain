# Reviewed recent-batch source guard rebind — 2026-10-27

## Scope and source identity

This correction changes exactly two literal Git blob IDs in
`.github/workflows/pon-recent-batch-acceptance.yml`. It retains all 16 source
guards and every other workflow byte: runners, source lanes, compiler, selectors,
expected test counts, deadlines, budgets, required checks and failure handling.
No Rust source, model source, native test, production primitive or development
plan is changed. A source guard passing is not native acceptance.

The direct parent is published candidate
`0c804e9f5bcf6e972bbb4524c744d4b3c8801c34`, tree
`ebd3545aac5815260ec1f94a2b9a2f383e8dd051`. Its base is
`57c1ed545d067937cbd7aaa7570d5f22123265e6`; the actual PR #506 merge tested
by the original run is `e22045b22fcda846d826243210c998a97d4559a3`, with
ordered parents `[base, candidate]` and the same tree. The local predecessor
`c4a2bc4e45a7317df5bff831f9615761605d8e09` also has that tree but is not this
repair's parent. Original local and published commit identities are not conflated.

## Original failure remains a failure

[Run 40490734388](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40490734388)
failed in all four lanes. Each job's initial `verify_ci_source.py` completed
successfully and reported `tracked_worktree_verified: true`, 5,477 tracked
entries and 706,019,303 tracked bytes. The immediately following first literal
comparison, for `store.rs`, then exited 1. This attribution follows the ordered
`set -euo pipefail` script and the independently verified blob mismatch; the
shell did not emit a separate diagnostic naming the failed `test` expression.
The later `public_v3_multiprocess.rs` mismatch was found by auditing all guards;
that comparison was not reached in these runs.

| Job | Runner / source | Result |
| --- | --- | --- |
| [122143726626](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40490734388/job/122143726626) | ubuntu-24.04 / prospective-merge | Step 3 failed; steps 4–23 skipped |
| [122143726957](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40490734388/job/122143726957) | ubuntu-24.04-arm / head | Step 3 failed; steps 4–23 skipped |
| [122143726992](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40490734388/job/122143726992) | ubuntu-24.04-arm / prospective-merge | Step 3 failed; steps 4–23 skipped |
| [122143727081](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40490734388/job/122143727081) | ubuntu-24.04 / head | Step 3 failed; steps 4–23 skipped |

The always-run source recheck also succeeded in each lane. That step subsequently
failed at `sha256sum "$OUT"/*.log` because no native/test log had been produced.
That secondary missing-log failure is not a source-integrity failure and is
not changed by this patch. Artifact upload succeeded in all four jobs.
No original failed run is reclassified, retried in this evidence, or used as
a native pass. The successor and its actual prospective merge still need CI.

SHA-256 of each complete UTF-8 log string returned by the GitHub job-log
connector, independently retained during review (not hashes of ZIP wrappers):

| Job | Decoded log SHA-256 |
| --- | --- |
| 122143726626 | `2a8f6477f78ca53c410b70df60701e518fb5ba6e9533890446011cdf66383261` |
| 122143726957 | `22e7cd93aec9ab4db1dc5dce44e926711d49d92480e75b75584297b47bc51b5c` |
| 122143726992 | `8898fca37888afbe0513b24011c03a14a86297aba79939dc08b21b26f2ac7881` |
| 122143727081 | `ae115e1c01690eef29de7d04c4168f58584f566d627d92c7313662431cde265c` |

## All 16 guards audited

All original expected IDs equal their files at base `57c1ed545`. Fourteen files
also remain byte-identical at published `0c804e9f`. Only the following two have
reviewed source changes. The replacement values are fixed literal IDs; they
are not computed from HEAD at execution time.

| File | Original/base blob | Reviewed published blob |
| --- | --- | --- |
| `trillionnium/crates/trnm-pon-node/src/store.rs` | `a255e10464938ecc189bf100462c9e8e204b0247` | `97cb5b57e5dd4ad6572f9a619c4df125e7d8d024` |
| `trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs` | `634ff4edb04694bb3de3807c1a859b2ed358a4ed` | `d6bd11f737fa00d1dfffc5447beb7e36bbf02732` |

The following 14 literal values remain unchanged. Node paths are relative to
`trillionnium/crates/trnm-pon-node/`; the two `formal/` paths are repository-root
relative.

| File | Unchanged blob |
| --- | --- |
| `src/store/history_page.rs` | `c8569bd62a9c374b03a8ffc0ad02c64b0365eee4` |
| `src/native_authenticated_tests.rs` | `fa9b0036b9f7092831ac6d73fc50fd8fe728865e` |
| `src/store/native_authenticated.rs` | `d015587f5a52726fc6322efab4385d40b6e61a05` |
| `src/store/native_fixed_blob_tests.rs` | `cecb8a984c02ffca7590e69c4392223ea748b40f` |
| `tests/authenticated_storage_cli.rs` | `7301aeb3033913f080b23767bfca52a2bf76d45b` |
| `formal/pon-nakamoto-v1/work_query_bound.py` | `2d568879899da290c7bec8add6eb2746554897d6` |
| `formal/pon-nakamoto-v1/test_work_query_bound.py` | `2161dd7d25b605b9e67f05bee5aa20038cf4469d` |
| `src/native_account_query_tests.rs` | `c8567475a36cf449d9fd2b33363a545fbd4704ab` |
| `src/store/native_authenticated/arithmetic_cache.rs` | `252f2c96cf162f84636a4404b702a67caa4a44fe` |
| `src/store/native_authenticated/arithmetic_cache/root_arithmetic.rs` | `0ee21dfd707456783d10876adf791bbf48ccd7ed` |
| `src/store/native_authenticated/arithmetic_cache/root_arithmetic/tests.rs` | `04e70ffd8f227b622d1e1f13ce7398f8d4146b01` |
| `src/account_archive_execution/state_witness.rs` | `0b27b9fce9d77fed63f351c8a8e33b02a856ace1` |
| `src/store/native_authenticated/history_arithmetic.rs` | `4ab2d3dcc08314da77066ca1941faedd15f938c9` |
| `src/store/native_authenticated/history_arithmetic/tests.rs` | `13ecdb3e45ef78e5abcc34f4bf30af0312dd2f11` |

## Why a reviewed rebind is appropriate

The workflow checks out the current event head or its actual prospective merge,
checks all tracked source bytes, then tests that checkout. It does not check out
a historical frozen fixture. The sole development plan already records prior
reviewed rebindings of these same guards: the 2026-10-21 native cloud follow-up,
the public-V3 measurement-integrity correction, and the authenticated-frame test
helper rename. Those entries also preserve prior failures and all original gates.
This repair follows that explicit current-source review boundary.

The complete base-to-published delta of both files was read. The base blobs were
retrieved through GitHub because the local partial clone lacked them, then
verified using Git's `blob <length>\0<bytes>` object hash before comparison.

`store.rs` has two additive regions. The private
`WorkCheckedPacket::verify_with_rejection_cache` passes the original challenge,
task, target and complete proof to the existing exact negative cache. That cache
retains only fully verified Transcript/Product failures, binds the full statement,
and still propagates local cancellation; it does not cache acceptance or create
owner authority. The helper initially has no owner permit. The existing ingress
context/owner checks and complete verified-work attachment remain in force.
The other addition is a `#[cfg(test)]` helper that retains original Node
context/owner checks and carries the caller's same execution-progress callback
through M06 and SQL. No existing persistence body or assertion was removed.

The `public_v3_multiprocess.rs` change captures one import deadline before the
existing 30-second measurement epoch and calls
`receive_public_page_from_before` with the original source address and deadline.
The helper requires the fixed administrator-owned Host parent even on loopback
and passes the same deadline into original History admission. The change does
not grant a fresh 30 seconds to each page. Original workload, measurement end,
budgets and result assertions are unchanged. This review does not assert that
the still-unexecuted CI campaign will meet its liveness or throughput predicates.

The `store.rs` path history after base, in chronological order, is:

| Published commit | Source change / original local identity when different |
| --- | --- |
| `4845e48272561e146ea1d41771c935fd2214f5e8` | Private checked-packet exact invalid-W1-cache adapter |
| `fbcea75f443f826c0590108b56b9bb4355e13ab1` | Original Host-owned W1 History progress helper |
| `9bf25e01515d8535ff2f6a80bd65809c1914a83f` | Same Host ownership through History M06 execution |
| `dc8d2370799d28f7e46a245b79eb8eb47f0db879` | Shared History/deadline correction; original local `83e90cb2b4b2c3ac17b000280b976ddbe607ebb1` |
| `0e750055855869bafc74115ce53786b42aafcf3b` | Formatting; original local `3ec9aecb0aeae2bcd8dac36e5621dafbfc88ebcd` |

Only `dc8d2370799d28f7e46a245b79eb8eb47f0db879` changes the multiprocess
test after base. Both mapped published commits preserve their original trees.
These identities describe provenance; they do not rewrite previous observations.

For independent byte checking, SHA-256 of base/current `store.rs` is
`debb13662b9d80c10380de4fc29684c4899c738515ae3c079b867032a40dc87c` /
`66eb698d5ccccea67efe6b4a39e2e840f378a2700aca75aa48c183429dff1aa0`;
base/current `public_v3_multiprocess.rs` is
`d210d08a86476faf196dc23dbcb75a1cb850b8af7bed7d403816ec4de4ae8d90` /
`246ac35e0d31f5ed79a09a00823fbc052641a95b1a470f4a8df730698e2320cd`.

## Local validation and remaining gate

Before editing, the mandatory `bash scripts/project-preflight.sh` passed on
the new branch rooted at published `0c804e9f`. Local checks on this repair:

| Command or check | Actual result |
| --- | --- |
| `python3 -B scripts/ci/check_ci_contract.py` | PASS; five head jobs, five merge lanes, two native cost architectures |
| `python3 -B scripts/ci/test_ci_contract.py` | 91 tests, PASS (5.695 seconds reported by unittest) |
| `python3 -B scripts/ci/test_ci_source_integrity.py` | 34 tests, PASS (2.638 seconds reported by unittest) |
| Byte comparison to the published workflow after substituting only the two reviewed IDs | PASS; every other byte identical |
| All literal guards against published source and working file bytes | 16/16 match |
| Append-one-byte source hash negative controls, without editing source files | All 16 mutations differ from their fixed expected IDs |
| YAML parsing | PASS |

The source-integrity negative suite intentionally emits rejected-fixture `FAIL`
receipts; its unittest result is 34 passed. The CI contract suite contains
explicit synthetic shell plumbing controls, not executed native test results.
No Rust build, Rust test, performance run, Hepta native execution or new hosted
CI execution is claimed here. Workflow SHA-256 after the two replacements is
`e5f4f5839a7b4d34f605b3f7c4164ca0d20eb8f6130aa1c7d85bc54b46370634`.

The original validation output was retained during review. SHA-256 of the
complete CI contract stderr is
`3ae51828eb97b81648da16a3415cb416fce657d49f027757bb4aa39c0346ea2a`;
source-integrity stderr is
`4b06937596b50e63a976367b2ee7d98cd39e164c7f7e3b2a7a52a06de36f19be`.
An unrelated pre-existing 12,582,912-byte untracked temporary summary in the
isolated repair worktree was preserved outside the checkout before final source
verification, SHA-256
`0cc2140d6cae04e777db8b8ab52447da3f4759944f5f6095172ca0ab378ef206`.
No original evidence or concurrent root worktree file was overwritten.

The required next observation is the unchanged four-lane recent-batch workflow
on the successor's exact published head and actual prospective merge. A later
native failure remains a failure requiring its own diagnosis. This guard repair
alone closes neither native acceptance nor public readiness.
