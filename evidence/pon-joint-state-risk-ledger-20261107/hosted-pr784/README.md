# PR #784 hosted gates and native refusal observations

This archive is assembled for candidate **b5c655ebe9611b3d62cf739e61e6867decc053e3**, tree **51ae39a63851cdbfbe5ad4ebc1fb039a9b95abff**. It preserves actual hosted results, failed observations, and publication/readback receipts. The independent archive branch is `chore/chain-pon-pr784-hosted-observations-20261108`; PR #784 keeps its original tested head.

## Completed repository-truth gates and overall snapshot

The later complete hosted readback establishes that both required-baseline repository-truth jobs passed: head job `128580281254` and prospective-merge job `128580281590`, in run `42431209912`. Full original logs are retained in [readback-05](reviews/final-pr-readback-05/).

The canonical `check_repository.py` directly reported PASS for the candidate at 00:48:37.347Z and prospective merge `b5adba8cfe5307675aac8482aa569312354bb3e4` at 00:48:41.709Z. Both reports bind tree `51ae39a63851cdbfbe5ad4ebc1fb039a9b95abff` and count 26 workspace packages, 1,198 Rust files, 4,232 local links and 25 normal dependency edges, with committed-clean source.

The hosted source guards passed before and after each lane, verifying 16,739 tracked entries and 1,733,895,581 bytes. Earlier [repository-truth observations](reviews/repository-truth/) stopped while the job was running and retain the original unavailable-log responses. Those historical records remain unchanged. The sparse local checkout had not run the full lane; the subsequent hosted success is a separate actual execution.

The retained **01:11:43Z** readback snapshot is still mixed: **104 head checks = 71 success, 12 failure, 18 running, 3 skipped**. This archive does not claim that all CI passed or that the later state of running jobs was observed.

## Retained failure groups

| Evidence group | What the original observation establishes |
| --- | --- |
| [Cross-architecture ARM](reviews/cross-arch-arm/) | Five native invocations returned successfully, but original business acceptance rejected `CONFIRMATION_TARGET`; the retained same-packet four-second comparison has baseline confirmation and no pressure confirmation. |
| [Protocol contract](reviews/protocol-contract/) | The verified prospective-merge artifact has five successful native invocations and passed service/sustained acceptance, followed by `confirmation_report` refusal with sole failure `CONFIRMATION_TARGET`. The head job's inner cause remains unknown. |
| [W1 fresh service](reviews/w1-fresh-service/) | Both lanes really executed their fresh named test. Each failed the original four-second/six-depth business target, panicked at `fresh_challenge.rs:244`, and exited 101 with `executed=true`, `timed_out=false`, and `finite_target_met=false`. `FRESH_NATIVE_PROCESS_REQUIRED` is the upper-level refusal of the unsuccessful execution; it does not mean no test ran. The original named test exited 0 but its business report also failed `CONFIRMATION_TARGET`. |
| [Retained historical artifact](reviews/retained-historical/) | The pinned old artifact could not be retrieved. The historical run remains readable, its current artifact list is empty, and its artifact metadata endpoint returns 404. This does not determine the retention mechanism and is not a current pressure-test execution. |
| [Other failed jobs](reviews/other-failures/) | Each job keeps its own first failed step and original logs. CodeQL export reached its deadline waiting for stable exact-source analyses/checks; it did not establish a retrieved security finding. The native-priorities and native-campaign failures are not assigned another job's unobserved internal cause. |

The protocol head ZIP fragment is explicitly **partial and unverified**: 2,177,980 bytes, SHA256 `4e428d751d7d58c4f0d35cea775012c259b43a749363a0f645dcb23a48a86a4d`. It remains a failed transport observation, with no internal head manifest. Merge or ARM evidence does not supply the head job's missing inner cause.

Relevant unchanged entry/test bytes and the base plan's already open confirmation gate are retained. They do not establish identical underlying causes, rule out every regression, or turn failed business acceptance into success. No acceptance threshold or production/security qualification was changed.

## Copy integrity and lossless ZIP deduplication

Frozen source directories were inventoried before and after copying. **Selected copied payload files** match the destination in path, byte count and SHA256. This is copy integrity, not execution attestation.

Complete, digest-verified ZIPs remain unchanged. Redundant expanded binaries, databases and large reports may be absent as separate physical copies. Each omission has an explicit original-path/size/SHA256-to-ZIP-member mapping; the member was fully streamed with CRC checking and matched to the original physical file. Small manifests, process records and logs remain directly readable, as do the protocol README's linked raw confirmation report and other linked targets.

The unmodified `physical-files`, `SHA256SUMS`, and artifact inventories inside the reviews describe their original source directories. They are provenance records, not claims that every expanded source file exists in this reduced archive. The outer [physical inventory](physical-sha256.json) describes files actually present here. Selection and reconstruction mappings are in the [W1 copy receipt](preparation/w1-fresh-service-copy-receipt.json) and [protocol copy receipt](preparation/protocol-contract-copy-receipt.json). The ARM archive keeps its original full ZIP without duplicating its separate extraction tree.

## Publication, preparation and source preservation

[Publication and earlier readback receipts](publication/) preserve the successful normal push and Draft PR creation, plus the old CLI's unsupported `baseRefOid`, terminal-newline comparison and pagination-refusal observations. Those readback harness failures are distinct from candidate test failures.

[Preparation records](preparation/workspace-preparation.json) preserve the initial `archive/` branch guard refusal and successful permitted `chore/` preflight, along with the unsuccessful local-clone setup and wrapper-quoting attempts. Those setup observations did not execute candidate tests. The archive checkout has independent Git configuration and shares cached objects. Canonical HEAD, tree, index, config and sparse settings remain unchanged.

The [workflow audit](preparation/workflow-push-audit.json) reads all 20 workflows from the fixed candidate, including retained exact source bytes. Six define push events; none matches this exact archive branch. No workflow, source guard, GitHub review policy, candidate PR head, or native/model test is changed by assembling this archive.

[The manifest](manifest.json) records every selected component and the fixed observation cutoff. Actual-work and actual-native-execution completeness remain false; the end-to-end failure probability remains unspecified and production activation remains false.
