# SP27-02 independent CI provenance audit

## Observed result

The original CI artifact supports **one fixed-order pair**, baseline 1/1 independent business confirmation and 16-worker pressure 0/1, in the same original four-second window and bounded Host parent. **Mechanism status: UNKNOWN.** This is an additional identified batch. The original failure is preserved, and no native experiment was rerun by this audit.

Primary sources: [run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43052900246), [job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43052900246/job/130634539770), [artifact](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43052900246/artifacts/13871459353).

## Archive and identity

Downloaded ZIP: `/workspace/scratch/e8159a5f91bf/provenance/ci-43052900246-13871459353.zip`.

- Bytes: 8,297,569.
- SHA-256: `8b21d753e0ac85ffdca7bc3e0a5f953d4dfffb24c7a10cc9ae394dcfe6590307`; exactly matches GitHub artifact metadata.
- ZIP CRC checked across all 282 entries. Each extracted file has a full byte SHA-256 in `CI_RAW_SHA256.json`.
- Existing `/workspace/scratch/400409ea9fda/audit_02_06/chain-pr913-service-model.zip` is byte-identical to this independent download.
- Tested commit: `8ebcdb01016946a131f9067ebe1ace39b9c4f260`.
- Tested tree: `1b887f5fe57c6c3875ad28b8cc26bd83a8f77b83`.
- Source-before and source-after identities match. Raw records report tracked worktree verification.
- Native binary is present, 11,849,144 bytes; SHA-256 `03d0dada775a2531876ce796192b59d27d78f86848e053de554ee70e281eb387`, matching build preparation.
- Raw named Rust tests all passed, while the original execution manifest has `passed=false`, `execution_finished=false`, `failures=["CONFIRMATION_TARGET"]`. Job conclusion remains failure.

Decoded job log is retained as `/workspace/scratch/e8159a5f91bf/provenance/job-130634539770.log`; the byte-verified artifact is the primary raw-record source. Log records runner version 2.338.2, ubuntu-24.04 image version 20261101.360.1.

## Host and resources

Before and after snapshots bind boot ID `e4467231-e96e-4736-9409-b547a3dc1666`, service `trnm-from-zero-43052900246-1-native-priorities-2395.service`, cgroup parent `/sys/fs/cgroup/trnmponpublic.slice`, device 31, inode 7066, root owner/group, mode 0755, no symlink. The installed unit SHA-256 is `74eb36a63559bf8603c15ddd3753a1db143684a2cefd84cce5aff10a76bbd622`.

| Field | Before and after |
| --- | --- |
| cpu.max | `25000 100000` (0.25 CPU) |
| cpu.max.burst | `0` |
| memory.max | `2147483648` (2 GiB) |
| memory.swap.max | `0` |
| pids.max | `256` |
| NoNewPrivs | `1` |
| CapBnd | `0000000000000000` |
| user/group | `1001/1001` |
| read_errors / child host_errors / final_host_errors | empty |

The complete before/after samples are in `CI_AUDIT.json`. These are Host eligibility readbacks, not consensus or model authorization.

### Scope of exclusivity

The exact executed source contains actual serialization: `run_from_zero_host.py` holds `public_fixture_host_lease.parent_lock()` across `outer_owned`; the lock is a root-owned immutable-name file using `LOCK_EX|LOCK_NB`, rejecting a concurrent cooperating owner. The artifact records a fresh parent (`parent_reused=false`) and pids.current=1 before and after the child experiment. The source files were fetched at the tested commit and independently checked against their Git blob identities.

This supports **cooperative fixture ownership**, with a fixed bounded parent. It does not prove a dedicated physical CPU, exclusive cpuset, continuous absence of noncooperating processes, or absence of unrelated host scheduling effects. The native receiver, pressure clients, reader and separate verifying client share the same experiment process/parent. A logical independent verifier is not a physically isolated CPU domain. No randomized pair order or replicated healthy control is present in this artifact. These limitations remain part of causal interpretation.

Sources: [Host runner](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/scripts/ci/run_from_zero_host.py), [parent lease](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/scripts/ci/public_fixture_host_lease.py).

## Pair observations and first divergence

| Observation | Baseline | Pressure |
| --- | ---: | ---: |
| Original window ns | 4,000,000,000 | 4,000,000,000 |
| Workers | 0 | 16 |
| Business start ns | 118,889 | 78,123,550 |
| Last of 7 honest submit ACKs ns | 201,950,838 | 1,270,197,394 |
| Independent History replays | 7 accepted | 3 accepted, then deadline refusal |
| Independent confirmation end ns | 2,704,367,684 | null |
| Original final gate | true | false |
| Independently confirmed businesses | 1/1 | 0/1 |
| Accepted attack proof | 0 | 0 |
| Invariant target | true | true |
| Mutation CPU refusals | 0 | 0 |
| Retained observer measurement failures | 0 | 0 |
| Observer records dropped | 0 | 0 |

The pressure run delivered all seven honest submit ACKs before T. The fourth History response returned at 3,877,883,009 ns; its independent replay began at 3,877,903,180 ns and returned `PUBLIC_REQUEST_DEADLINE` at 4,066,591,277 ns. All replay Host error-code lists are empty. No final independent confirmation object was returned. This localizes the observed terminal failure to incomplete independent replay by the unchanged deadline. It does not establish the causal source of delay.

Pressure recorded 386 attack calls: 370 returned `WORK:Transcript` and 16 had other terminal outcomes. It recorded 425 accepted connections, 569 queue backpressure events, and 4,592,317,421 aggregate queue-wait ns. Aggregate waits across concurrent requests are not a wall-clock critical path. Mutation CPU debit was 272,141,665 ns; the original meter records zero mutation CPU refusals and nonzero final stored credit. Thus this pair does not support a claim that the mutation stored-CPU meter was exhausted.

Both arms use the same reported packet sequence and initial state. Their execution order is baseline then pressure. One pair supplies no randomization-based causal estimate, confidence interval, stable baseline qualification, or service-capacity estimate. No latency percentiles should be inferred from one confirmed business.

Original qualification flags remain `strongest_honest_producer_used=false`, `work_profile_qualified=false`, `public_network_ready=false`, and `production_activation=false`. The reported success scope is finite invariant checks only. These flags are not upgraded by this audit.

## Previous SP27-02 local Host failure

**NOT_VERIFIED.** Exact Library title queries for `SP27_02`, `SP27-02`, `PUBLIC_HOST_KERNEL_PARENT` and a SP27 title inventory found no corresponding diagnostic/patch package. A content search produced unrelated fuzzy candidates, which were not treated as originals. In `/workspace/scratch/400409ea9fda/audit_02_06`, the error code occurs in the audit commentary but no corresponding raw failure log was found. These are bounded search results, not proof of global absence.

The exact [host_kernel_parent.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/8ebcdb01016946a131f9067ebe1ace39b9c4f260/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs) maps multiple failures to `PUBLIC_HOST_KERNEL_PARENT`: nonabsolute path; canonicalization failure; unapproved or noncanonical exact path; and directory/ownership/writability mismatch. The bare error string cannot identify which occurred. Missing local originals must not be reconstructed from chat descriptions.

## Raw file digests

The extracted root is `/workspace/scratch/e8159a5f91bf/provenance/ci-43052900246-13871459353/`. All 282 members appear in `CI_RAW_SHA256.json`; the primary record set is below.

| Relative path | Bytes | SHA-256 |
| --- | ---: | --- |
| `source.json` | 423 | `2ac891d7fcb941261b7414b3e3d67aebf5e8f7f3fbeb0fb599ec1a2bd2ec5452` |
| `from-zero-native/manifest.json` | 72941 | `82e6566b63abb6f4ed23f4cb2693798825baabab899c209478d09a0fc66f5ecd` |
| `from-zero-native/confirmation/report.json` | 11152091 | `4a4ec5d92810f51df792a2f1f08e4af4c9cb47c107c5ed3e3a8e2ef71dae9a1d` |
| `from-zero-native/public_v3_from_zero` | 11849144 | `03d0dada775a2531876ce796192b59d27d78f86848e053de554ee70e281eb387` |
| `from-zero-native-host/inside-before.json` | 1688 | `d159643991fb6a39e78a429a627aee1fcf2bdf033c53a4f94c58a1c6ba542d36` |
| `from-zero-native-host/inside-after.json` | 1700 | `cde41157499d69618b5042b86b51f2c208ff27af2c151467676b57a6e86f312d` |
| `from-zero-native-host/controller-result.json` | 7645 | `3dc5e8c36731efead98f19221213ba75189f12fa69ae804b0464b697c3a53dca` |
| `from-zero-native-host/child-result.json` | 339 | `65506802659d241946c0d8e17f0926e5cc25715a2f4a73c695fe84db934b6d03` |
| `from-zero-native-host/prepare-build.json` | 3406 | `f4f8b0deb7907fb8ac1e2f029c243bdeb7f28506cee9b54342233aa47540bb1a` |
| `public-fixture-parent.json` | 3233 | `d5edafd376699bc5072aeb266df15921557235cd7111fb11b6b6e4a81c4cfb68` |
| `from-zero-native-host/actual-systemd-parent.log` | 200 | `251aa282c289d7a152c48ec876369121b1ff818157cbbb4c1426dc89342501d3` |
| `from-zero-native-host/actual-systemd-parent-after.log` | 200 | `251aa282c289d7a152c48ec876369121b1ff818157cbbb4c1426dc89342501d3` |
| `from-zero-native-host/parent-properties.log` | 146 | `313ae0beb72fab5cfa2506271e7b1bab522a702995c7be248e46b91311afe343` |
