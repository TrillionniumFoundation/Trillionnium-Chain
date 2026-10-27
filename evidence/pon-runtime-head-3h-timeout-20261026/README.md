# Original head-runtime 3-hour qualification timeout — retained failure

This package preserves one actual hosted failure observation on Chain source
`53fb654b532ed8e737e0dea635a31dce3b73b3cc` / tree
`d82ba0c7bbaea04200f11d38f6e9c4dccac81f78`: run `40310512277`,
attempt `1`, job `121574328675` (`rust-baseline shard (runtime)`).
The official conclusion is `cancelled`; its annotation explicitly states
“The job has exceeded the maximum execution time of 3h0m0s”.
Job timestamps are 2026-10-26 15:21:00–18:22:25 UTC. The retained Rust step
was cancelled at 18:22:15 UTC. This is a failed qualification, not a pass.

The original release test
`store::growth_reference::tests::native_growth_reference_65537_signed_accounts_and_cold_reopen`
started at 17:10:41.2175097 UTC. Cancellation followed 4,293.980079 seconds
later. Its final observed progress was 61,444 active accounts at height 240,
18:14:55.4499201 UTC. Completion at 65,537 accounts and the required cold reopen
are not proven. Subsequent growth-v2 and account-verification-cost executions
are not proven. The retained `rust-shard.json` remains `status=running`,
`exit_code=null`; source verification after cancellation confirms the same
source/tree and `tracked_worktree_verified=true`.

`original-22-files.tar.gz` is an ordinary compressed evidence archive. It is
not a prepared experiment input, execution result, product release or new
budget. Its 22 members are pinned in `original-22-files.manifest.sha256` and
have been read back from the archive byte-for-byte. They preserve the complete
781,638-byte original job log, official annotation, job metadata, source receipt,
both complete official artifact ZIPs, selected original members, and the failed
bounded transport plus exact HTTP206 tail-recovery history. The partial download
was retained; both completed ZIPs match their official digests. Additional
read-only artifact-transfer processes are not part of the original CI runtime.

Official immutable artifacts:

| Artifact ID | Bytes | SHA-256 |
| --- | ---: | --- |
| 12674439882 | 2,164 | `4040af620e7bd5da3ed823bbed730ddcaa19ffa96c17db8e3424da7e29313734` |
| 12674439876 | 4,465,869 | `bb5a008825b056cc67caa484fef8f4bb4d5f431b5f558c182aef305ab9cd4643` |

The raw full log SHA-256 is
`f3e3ee7c62acf848d2bc6b5bf5fdd82b65f65c018bf27825a83c181ce9bc9129`.
The separately copied `independent-cancellation-receipt.json` remains byte-exact
to the original read-only receipt, SHA-256
`e059d88998e0ac9dafc312768ced29e8bc129a45dfeefb514140986b789a66e1`.

This timeout is not evidence that the earlier 0.5-second marker issue or procfs
ESRCH caused it. It establishes no performance causality, minimum work cost,
hardware fairness or qualification for the later R4/R5/R6 source. The original
3-hour maximum, tests, assertions and resource limits remain unchanged. No
rerun, increased limit, source execution or workflow change was performed for
this packaging. All historical failures remain retained; **NO_GO**.

Original run/job:
<https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40310512277/job/121574328675>
