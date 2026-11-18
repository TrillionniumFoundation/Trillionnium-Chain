# Reuse actual native execution deltas for authenticated persistence

## Problem and bounded change

The original F0 at source `7e3e454f9b18d5d135e72cc5ea373e04fc5a2ef8`, run [44315121617](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44315121617), failed with 1/6 confirmations inside the original thirty-second phases and 0/6 against the scheduled four-second target. Full original bytes and independent readback remain in Draft #958 and the adjacent `chain-fixed-root-f0-20261118-2e9b` evidence.

The baseline client's 12 History imports made 121,963 Host checkpoints. The exclusive commit attribution was 62,107 calls / 2,636,001,313 ns of nested Host CPU. Actual stored full snapshots for heights 5–15 contain 11,473 union-key visits but only 26 canonical delta rows. `original-profile.json` independently recomputes those counts from the retained original SQLite snapshots and records the wider stage costs without adding nested intervals.

This candidate uses the complete canonical changes already produced by the original owner's real M06 execution to write authenticated-v1 deltas. Both held-owner and opaque detached-owner execution construct this optional write material internally. Each actual delta write retains its Host/CPU/cancellation checkpoint. The candidate does not accept public StagedOutput or caller-supplied changed-key lists.

Only authenticated-v1 with no task manifest uses this path; Legacy, PQ, Growth and all task-output re-derivation paths retain the existing full union. Public PreparedCommitment is not authority. The existing authenticated publish independently re-reads the actual SQL deltas and completely canonicalizes both actual States through matches_difference. Missing, extra or incorrect material therefore fails before commit. Original snapshot, packet, complete State, ancestry, active-tip, schema, transaction-owner and final callback fences remain in place. No original validator or guard assertion changed.

This removes one repeated full-State delta-candidate enumeration. The original account-graph traversals remain: baseline client account_graph was 84 calls / 4,365,213,739 ns of nested CPU, with 117 verify_state calls. Neither the eliminated-key count nor the native controls establish the business deadline. All costs remain charged by the original accounting.

## Native validation and retained failure

Rust 1.95.0 release jobs on ai395:

| Selector | Actual result |
| --- | --- |
| New executed-delta negative/parity/rollback controls | 3 passed |
| Original detached admission selector, including those 3 controls | 23 passed, 1 explicitly ignored |
| Original authenticated selector | 123 passed, 1 explicitly ignored |
| Original legacy admission selector | 8 passed |
| Original task_output_root_parity integration test | 2 passed |
| Original pon_commitment selector | 15 passed, 2 explicitly ignored |
| Strict trnm-pon-node library Clippy | passed, -D warnings |

The new controls compare all actual SQL tables and cold reopen between the native-delta path, literal full-union fallback and held owner; inject missing, extra, wrong-before, wrong-after, reversed and non-UTF8 material; and cancel at every actual delta row and the final commit boundary. They establish refusal/rollback and state parity, not service throughput.

First job `1a1ef2f794c-ffbe-425` passed the node and task-output controls, then the original commitment crate's test compilation failed because the sparse checkout omitted `tests/vectors/pon/native-growth-reference-v2.json`. The original failure is retained. Retry `1a1ef350e7f-ffbe-434` materialized that exact HEAD Git blob, verified all previously hashed files unchanged, and passed the remaining original commitment controls and Clippy. No assertion was weakened or test result replaced.

`native-originals.tar.xz`: 162,556 bytes, SHA256 `5e4f4f284b21d44522f824965959473f9f78dc1de068e3b41098f65e0c4e269c`. It retains both attempts, complete stdout/stderr/exit files, the actual formatted patch, source files, 1,705 source/vector hashes before/after and actual native test ELF identities. Full test ELF bytes are explicitly not in this archive. Local independent readback verified the archive hash, every before/after hash and the three tested source bytes against the published candidate inputs.

Project preflight, all 2,617 current source blob correspondences and the original native ownership omission/mutation negative control passed. Only the three new current source blob pins are refreshed relative to #959; historical evidence and qualification assertions remain frozen.

## Business and cost status

This is a separately frozen candidate stacked on #959. The original F0 workflow is to run on its exact published source, with all six scheduled confirmation targets, 42 exposures, 24 ROOT attackers, scalar CPU and memory bounds, original readers and failed/unobserved denominators unchanged. The #959 run 44328450170 is preserved independently; its result must not be transferred to this source.

Complete physical cost remains UNKNOWN: these archives do not measure system-wide energy, provider charges, all concurrent physical memory, physical network traffic or storage byte-seconds. Native/accounting/OS counters retain their original scopes and failures; nested CPU is not added. No independent-operator, WAN, production activation, consensus-hardness, FinalUse or reward-settlement qualification is claimed.

Prior #959 F0 has now completed with 0/6 original-window and 0/6 four-second confirmations. Its full provider ZIP and source-pinned independent failure readback are retained in the adjacent Host evidence, with the exact prior source attribution. This negative does not qualify this new candidate.
