# F0 independent History: Host-parent boundary audit

This is a read-only audit of the original F0 confirmation run on Chain `657bf2a462ff13a6101ebcb4fbe0fb91c515c972`, tree `7ce7ac50f788dd421e7cc0c9ddb957ade3e8df73`. It identifies an unclosed Host prerequisite at the independent public History entry. It does not identify an algorithm-throughput failure or authorize bypassing the Host guard. No source, configuration, profile, budget, deadline or original record was changed; no native binary or Cargo command was run. The tracked source was clean before and after this audit. Observation interval: `2026-11-05T10:30:28.530010+00:00` to `2026-11-05T10:31:23.785985+00:00`.

## Original outcomes and exact stopping point

The original local native command began at `2026-11-05T09:54:28.202508+00:00`. Its confirmation test process returned exit 0, while the separate confirmation validator rejected `CONFIRMATION_TARGET` and the outer command returned 1. Harness completion is retained separately from business completion. The raw confirmation report is present: SHA256 `3e7ca3825361fe9df23d3827c92af5f6411316c2e42f1a4085fcc05a2aef024d`.

| Scenario | Submit ACKs in window | History replies in window | Independent replay attempts | Accepted replays | Independently confirmed business transactions |
|---|---:|---:|---:|---:|---:|
| Attack-free baseline | 7/7 | 16/16 | 16 | 0 | 0/1 |
| From-zero pressure, 16 workers | 7/7 | 16/16 | 16 | 0 | 0/1 |

All **32** replay errors are `PUBLIC_HOST_KERNEL_PARENT`. Every native observer records one started, completed and rejected **Host resolve** call. Initial, checkpoint and final Host checks never start. All 19 native importer phases remain unentered, packet observations are empty, and importer `tip`, `after` and `supplied_packets` remain null. Measurement failures are zero. Each replay starts from the genesis cursor and returns no next cursor. Final independent confirmation is absent. Separate execution/inclusion counters, successful confirmation latency and qualified confirmation TPS remain unknown; database observations below do not replace those counters.

## Receiver loopback and public History have different prerequisites

The [fixture opens separate receiver and independent-client databases, then binds the receiver to loopback](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/657bf2a462ff13a6101ebcb4fbe0fb91c515c972/trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs#L1277-L1334). The [receiver library calls `require_for_listener`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/657bf2a462ff13a6101ebcb4fbe0fb91c515c972/trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs#L2097-L2114), whose [loopback branch supplies no explicit parent](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/657bf2a462ff13a6101ebcb4fbe0fb91c515c972/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs#L1239-L1251). Consequently that receiver can start without administrator provisioning.

The [independent fixture call](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/657bf2a462ff13a6101ebcb4fbe0fb91c515c972/trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs#L1424-L1482) uses the public observed History API. That API [always supplies `/sys/fs/cgroup/trnmponpublic.slice`, including for a loopback source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/657bf2a462ff13a6101ebcb4fbe0fb91c515c972/trillionnium/crates/trnm-pon-node/src/ingress.rs#L2553-L2598). An [explicit parent is opened regardless of source address](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/657bf2a462ff13a6101ebcb4fbe0fb91c515c972/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs#L445-L451). Host resolve precedes native History replay. A separate SQLite database does not provide cgroup authority or make this a separate operator. The receiver's ability to serve packets therefore cannot establish the independent importer's Host readiness.

## What the shared error identifies—and what it does not

The [frozen parent-open implementation](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/657bf2a462ff13a6101ebcb4fbe0fb91c515c972/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs#L363-L381) collapses four branches into the same public error:

| Source line | Rejection | Historical conclusion |
|---|---|---|
| 366 | Supplied path is not absolute | Excluded here: the call uses the fixed absolute literal. |
| 369 | Canonicalization returns an I/O error | Possible; the original record retains no errno. |
| 373 | Canonical path is outside the fixed identity or differs from the supplied spelling | Possible; historical canonical path is absent. |
| 380 | Metadata is not a directory, not owned by uid 0, or is writable by group/others | Possible; historical metadata is absent. |

The per-call Host diagnostic's `last_error_code` is null in all 32 cases. The retained report cannot choose among lines 369, 373 and 380. At the **later** audit observation `2026-11-05T10:30:28.702211+00:00`, Python strict resolution and `lstat` of the fixed path both return errno 2 (`FileNotFoundError`); the cgroup-v2 controllers file is present and this audit process reports membership `0::/`. This supports a current missing-path observation only. It does not retroactively assign ENOENT to the original run or prove its exact root cause. The native Host function was not rerun.

## Earlier Host readiness refusal remains a separate result

At `2026-11-05T09:53:32.757368+00:00`, the original Host wrapper returned exit 1 with `HOSTED_CI_ONLY_NO_LOCAL_PROVISION`, `passed=false`, and `host_readiness_only=true`. Its [outer guard](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/657bf2a462ff13a6101ebcb4fbe0fb91c515c972/scripts/ci/run_from_zero_host.py#L282-L289) refuses before acquiring the parent lease, provisioning the parent, or starting the native child. The original refusal log SHA256 is `f83ae7239b5ca746748c411437088139d89927cbf52986af6ee5e4fb436707ab`. The later local native invocation was a separate command and does not turn that refusal into readiness success.

The existing [reviewed parent unit](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/657bf2a462ff13a6101ebcb4fbe0fb91c515c972/config/systemd/trnmponpublic.slice) defines the shared physical parent. A valid public import requires the actual eligible parent and process membership, not a database field or a chosen directory name. This audit neither provisions that parent nor changes CI identity, limits or guard behavior.

## Retained SQLite observations

All five databases were queried using SQLite URI `mode=ro&immutable=1` and `PRAGMA query_only=ON`. Every retained WAL was empty. Main database, WAL and SHM hashes were identical before and after each read. The JSON companion records the exact queries, metadata, counts, fingerprints and observation timestamps.

| Retained database | Blocks | Height range | Active generation | Active tip |
|---|---:|---:|---:|---|
| producer | 8 | 0–7 | 7 | `3c02ec6cd94c4ae907693493e202aadb802b67ca8ce606abece2b70453a60c14` |
| baseline/receiver | 8 | 0–7 | 7 | `3c02ec6cd94c4ae907693493e202aadb802b67ca8ce606abece2b70453a60c14` |
| pressure/receiver | 8 | 0–7 | 7 | `3c02ec6cd94c4ae907693493e202aadb802b67ca8ce606abece2b70453a60c14` |
| baseline/independent-client | 1 | 0–0 | 0 | `f9c79ade09c69ab83c02c49e21cae0855b73998cd5bb781acda5ee5b55ed5516` |
| pressure/independent-client | 1 | 0–0 | 0 | `f9c79ade09c69ab83c02c49e21cae0855b73998cd5bb781acda5ee5b55ed5516` |

Producer and both receivers also have 7 events, 16 deltas and 14 key/value rows; each independent client has 0 events, 0 deltas and 7 key/value rows. Genesis and parameter metadata match the raw report. Producer/receiver block fingerprints are equal, and their seven stored packet hashes match the report's signed packet sequence. Both independent databases have the same genesis-only fingerprint. These are retained row observations, not a fresh native verification, a missing-block-parent diagnosis, or throughput measurements.

| Retained database | Database SHA256 | Canonical block-row SHA256 |
|---|---|---|
| producer | `0d5e8e88b221b194617e773a59987dbca33fde482bfe5b8edd23a976a6c2b770` | `2f0b29236b2d11a901f8c841ed57ced50de3a0dfd9f72e193a3d94a79107abcb` |
| baseline/receiver | `bc314e01dd564e9484dabad41ba06c3bf2cd6a7893bcbbd2e5f8f3bddbb2cc14` | `2f0b29236b2d11a901f8c841ed57ced50de3a0dfd9f72e193a3d94a79107abcb` |
| pressure/receiver | `bc314e01dd564e9484dabad41ba06c3bf2cd6a7893bcbbd2e5f8f3bddbb2cc14` | `2f0b29236b2d11a901f8c841ed57ced50de3a0dfd9f72e193a3d94a79107abcb` |
| baseline/independent-client | `ff19287bdbd7620b2dc9b974b64af2c376f187ecbdc9728f4af501200d86b274` | `a04aa68d31ac73a8872b4cd6c3e78ad3619ee533a67f17eb8031fe71ede37f59` |
| pressure/independent-client | `ff19287bdbd7620b2dc9b974b64af2c376f187ecbdc9728f4af501200d86b274` | `a04aa68d31ac73a8872b4cd6c3e78ad3619ee533a67f17eb8031fe71ede37f59` |

## Narrow next slice and limits

The smallest diagnostic change is to retain a bounded trusted-local rejection stage from the **same** `KernelBudget::open` attempt: canonicalization I/O kind/raw errno, canonical identity, or metadata eligibility. Preserve `PUBLIC_HOST_KERNEL_PARENT` externally and all existing checks. Do not substitute a second filesystem read for the failed operation. This diagnostic would make the next genuine failure distinguishable without granting admission.

Actual integration still requires readiness evidence from the existing authorized hosted wrapper and its exact fixed parent before interpreting independent confirmation. Retain hosted-only refusal, unsuccessful requests and the original acceptance denominator. Substituting the private development importer, admitting another cgroup, relaxing eligibility or widening limits would not close this interface correctly. No such change is proposed or performed here.

During the final local-object check, concurrent commit `cbead1508ce8b6d9deb2a86b4bc3181da09694e7` became available in four of 26 searched local Chain repositories. Its tree is `624c8aad419ee05dc71a4aac507abea429018289`. All seven reviewed files—Host-parent implementation, History ingress, public receiver, F0 fixture, Host runner, native runner and reviewed parent unit—have **identical Git blobs** at frozen 657 and cbead. Thus these call-path files contain no repair of this boundary in cbead. The JSON records each compared blob and immutable URL, including the [concurrent Host implementation](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cbead1508ce8b6d9deb2a86b4bc3181da09694e7/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs). No network query, cbead execution or broader whole-commit validation was performed.

The companion JSON binds these findings to immutable source URLs and input hashes. Existing original run records and the earlier F0 audit remain unchanged.
