# Read-only review of the inherited W1 QROM fixed-source mismatch

**Status: HOLD.** This review records source identity, bounded code differences,
and the scope of an observed CI refusal. It does not establish a QROM proof,
a complete oracle cost, a consensus security theorem, an exploitable attack, or
production qualification. No contract, reader, input limit, receipt, or old
execution record is changed by this document.

## 1. Sources and exact boundary

The frozen mapping was introduced by
[commit 7150d96a2112875b4afcf3023361a5cef4a0e4b1](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/7150d96a2112875b4afcf3023361a5cef4a0e4b1), whose parent is the
[declared source anchor cb114b13bf848a77634e40a08b31b30c7c758e7b](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/cb114b13bf848a77634e40a08b31b30c7c758e7b).
The contract and reader were read back at their introducing commit, the inherited
base, and the reviewed candidate. Their complete bytes are identical.

| Item | Git blob | SHA-256 |
| --- | --- | --- |
| [Fixed contract](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/7150d96a2112875b4afcf3023361a5cef4a0e4b1/config/pon/w1-qrom-implementation-v1.json) | `b8fe1e3f00d171400f57426dc3aa04d7b6faa0ca` | `7761787fca9ea92c7b678186ccb302900bfabc974460b7f6793c7a0aabb6cf22` |
| [Fixed reader](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/7150d96a2112875b4afcf3023361a5cef4a0e4b1/scripts/w1_qrom_implementation_audit.py) | `d345b2f2a397a254b44ab0a38c33083f507e206d` | `c6fc6c36e4c2ce198c1dad465a7d36495253f844438f46df652715ea6dc8b354` |

All sixteen entries in the contract's `project_files` list were retrieved and
checked for both exact UTF-8 byte length and SHA-256 at each of these sources:

| Source | Matches the frozen sixteen-file manifest |
| --- | --- |
| [Frozen `cb114b13bf848a77634e40a08b31b30c7c758e7b`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/cb114b13bf848a77634e40a08b31b30c7c758e7b) | 16 / 16 |
| [Inherited base `e4abb172147e941b62483652b0ceabaae4317624`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/e4abb172147e941b62483652b0ceabaae4317624) | 14 / 16 |
| [Reviewed candidate `2582a6d15a14d3929d3238d844e710f5a291b422`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/2582a6d15a14d3929d3238d844e710f5a291b422) | 14 / 16 |

Every one of the sixteen files is byte-identical between the inherited base and
the reviewed candidate. These two mismatches therefore predate the current
quantum-tip/native-current-clock change.

The contract explicitly limits its scope to selected entry, relation, framing,
native-work, and dependency-lock files. It does not claim all transitive source,
compiled features, public ingress, or runtime closure. The sixteen-path comparison
does not silently expand that scope.

| Selected path at the reviewed candidate | Comparison with the frozen source |
| --- | --- |
| [formal/pon-nakamoto-v1/w1_hardened_verifier/src/profile.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/formal/pon-nakamoto-v1/w1_hardened_verifier/src/profile.rs) | Exact frozen bytes |
| [formal/pon-nakamoto-v1/w1_hardened_verifier/src/wire.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/formal/pon-nakamoto-v1/w1_hardened_verifier/src/wire.rs) | Exact frozen bytes |
| [formal/pon-nakamoto-v1/w1_hardened_verifier/Cargo.toml](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/formal/pon-nakamoto-v1/w1_hardened_verifier/Cargo.toml) | Exact frozen bytes |
| [formal/pon-nakamoto-v1/w1_hardened_verifier/Cargo.lock](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/formal/pon-nakamoto-v1/w1_hardened_verifier/Cargo.lock) | Exact frozen bytes |
| [formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs) | Reviewed production source drift |
| [formal/pon-nakamoto-v1/w1_v2_verifier/src/image.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/formal/pon-nakamoto-v1/w1_v2_verifier/src/image.rs) | Exact frozen bytes |
| [formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.toml](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.toml) | Exact frozen bytes |
| [formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.lock](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.lock) | Exact frozen bytes |
| [formal/pon-nakamoto-v1/w1_zkvm/methods/guest-v2/src/main.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/formal/pon-nakamoto-v1/w1_zkvm/methods/guest-v2/src/main.rs) | Exact frozen bytes |
| [formal/pon-nakamoto-v1/w1_zkvm/methods/guest-v2/Cargo.toml](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/formal/pon-nakamoto-v1/w1_zkvm/methods/guest-v2/Cargo.toml) | Exact frozen bytes |
| [formal/pon-nakamoto-v1/w1_zkvm/methods/guest-v2/Cargo.lock](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/formal/pon-nakamoto-v1/w1_zkvm/methods/guest-v2/Cargo.lock) | Exact frozen bytes |
| [formal/pon-nakamoto-v1/w1_zkvm/relation/src/lib.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/formal/pon-nakamoto-v1/w1_zkvm/relation/src/lib.rs) | Exact frozen bytes |
| [formal/pon-nakamoto-v1/w1_zkvm/relation/src/v2.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/formal/pon-nakamoto-v1/w1_zkvm/relation/src/v2.rs) | Exact frozen bytes |
| [trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs) | Exact frozen bytes |
| [trillionnium/crates/trnm-crypto-primitives/src/pon_work/artifacts.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/trillionnium/crates/trnm-crypto-primitives/src/pon_work/artifacts.rs) | Exact frozen bytes |
| [trillionnium/crates/trnm-protocol/src/pon_wire.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/trillionnium/crates/trnm-protocol/src/pon_wire.rs) | Reviewed production source drift |

## 2. Verifier entry: a new production CLI mode

| Version of [`w1_v2_verifier/src/main.rs`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs) | Bytes | Git blob | SHA-256 |
| --- | ---: | --- | --- |
| [Frozen source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cb114b13bf848a77634e40a08b31b30c7c758e7b/formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs) | 9,233 | `3975ac2105e8fc0f349eb1769f58de574590a8da` | `07415e8e3bb53f3e81dd489e4ebda63368170efbe4a217ae6b0dd6cc0af14128` |
| [Inherited/current source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e4abb172147e941b62483652b0ceabaae4317624/formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs) | 11,172 | `1b2999ec2efb51b1291e4fac19f55ee0afeb5d75` | `5e102fcbe4881e3d163c7a8b65364304b14d080ae64f23b0d5032daa84208aa7` |

The complete 1,939-byte addition consists of `native_once` and its
`--native-once` dispatch. Removing exactly those two added regions from the
current source reproduces the complete frozen file byte for byte. In particular,
the old receipt-verification path, the old `--native` path, and the entire test
module are unchanged. This is production CLI code; it is not a test-only edit.

The command is:

```text
--native-once INPUT HEADER EXPECTED_ARTIFACTS
```

It requires exactly three arguments, a complete 49,506-byte native input, an
independently supplied 318-byte header, and 64 bytes of expected artifact
commitments. It rejects a mismatch between the supplied header and the input's
header, calls the existing `v2::check_complete_relation` once, and applies the
existing public-journal/artifact binding. Its output schema is
`TRNM-W1-V2-NATIVE-ONCE1`, with `iterations = 1`,
`full_replay_calls = 1`, `parent_eligibility_checked = false`, and
`admission_authorized = false`.

The previous `--native` command retains its initial replay and 1,000 additional
replays: 1,001 complete calls in total. The new mode does not substitute a native
replay for receipt verification on the original receipt path. Nor does it turn
the native command into parent eligibility or consensus admission.

The added mode first appears in
[d3037ca5dfb6f301757c159b7888dca9b0317be0](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/d3037ca5dfb6f301757c159b7888dca9b0317be0).
The subsequent merge
[af2b8661d049549f9d67e33c5aa69c5220dea0b5](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/af2b8661d049549f9d67e33c5aa69c5220dea0b5)
already contains the exact current 11,172-byte blob.

### Cost consequence

The new sample timer starts after input/header/artifact file reads, length
checks, independent-header comparison, and artifact decoding. It stops after
one complete relation replay and public binding. Output hashes, JSON
serialization, process startup, and destruction are outside that interval.
A complete receiver observation must account for those costs separately.

Consequently, the one-call sample and the previous 1,001-call benchmark are
different observations. Neither old benchmark timings nor an old receipt's
execution record can be relabelled as an execution of the new command. No new
complete-cost or physical quantum-oracle calibration was performed in this
read-only review.

## 3. Protocol framing: two additional exact payload formats

| Version of [`pon_wire.rs`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/trillionnium/crates/trnm-protocol/src/pon_wire.rs) | Bytes | Git blob | SHA-256 |
| --- | ---: | --- | --- |
| [Frozen source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cb114b13bf848a77634e40a08b31b30c7c758e7b/trillionnium/crates/trnm-protocol/src/pon_wire.rs) | 32,354 | `9333ce92c6ba130dd182538bfd8f69ec289acc83` | `be816ee5b209098fa790d6e190d1d9c659634ac22d58b95c83dc8b49899c70cd` |
| [Inherited/current source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e4abb172147e941b62483652b0ceabaae4317624/trillionnium/crates/trnm-protocol/src/pon_wire.rs) | 32,654 | `a92d02b7e1edd316aba52cb1b2ff8b546e65c03d` | `ee443e739da946fc023f119e7f3b882f373b3787820295b29b182ef0ee3ef83b` |

The complete 300-byte difference changes only the tag 2 and tag 5 branches in
`payload_len`. Reverting those two branches reproduces the complete frozen
file byte for byte.

| Tag | Frozen accepted payload length | Additional current format |
| --- | ---: | --- |
| 2 | 80 bytes | Exactly 380 bytes, `TSC1`, decoded as `FundedServiceReservationV1` |
| 5 | 64 bytes | Exactly 133 bytes, `TSD1`, decoded as `FundedServiceDecisionV1` |

The old lengths remain accepted. The new forms are bounded, exact formats;
this is not an unbounded payload allowance. `MAX_TX_BYTES = 2048` and the
318-byte header size remain unchanged.

This is an actual production input-grammar change. PNX1 `Envelope::unsigned`
calls `payload_len`; encoding, signing digests, identifiers, and decoding
reach that check. The added forms perform field and semantic checks, including
their fixed magic, nonzero commitments, permitted verdict, and relevant
deadline/identity constraints. Their decoding work therefore belongs in any
cost claim that covers these paths.

The new dependency
[`funded_service_task_v1.rs`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/trillionnium/crates/trnm-protocol/src/funded_service_task_v1.rs)
has Git blob `fcb274af627df537f7debe5cf922e6fed766bd7c` and SHA-256
`c7c501901dd9fe38b447db61069a6d605379c5a02555acc874ffebfb2c948cb1`.
It is publicly declared in the protocol crate, and it is **not** one of the
sixteen files in the frozen contract.

The independent native PQ profile grammar remains narrower:
[`pq_native_accounts_v2.rs`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/trillionnium/crates/trnm-protocol/src/pq_native_accounts_v2.rs) explicitly accepts
tag 2 only at 80 bytes and tag 5 only at 64 bytes for AccountsV2, QuotaV3,
TasksV4, TasksV5, and ApplicationV6. The funded-service source also retains
tests that expect the new 380/133-byte forms to be rejected by those profiles.
This review inspected that source; it does not claim a fresh execution of
those tests or that all PQ profiles gained the new formats.

The wire change was introduced by
[690f710c1b6808787996e86aa4c36bd53e1f3939](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/690f710c1b6808787996e86aa4c36bd53e1f3939).
The file at its parent
[ce9b9f734b99c0c7d0c0264e2819020e0bb9a5db](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ce9b9f734b99c0c7d0c0264e2819020e0bb9a5db/trillionnium/crates/trnm-protocol/src/pon_wire.rs)
is the exact frozen blob; the file at that introducing commit is the exact
current blob.

## 4. Actual CI refusal and why it must remain meaningful

The inherited mismatch was observed in
[Actions run 42935065392](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42935065392),
specifically the
[head/x64 job 130242977468](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42935065392/job/130242977468)
on source `2582a6d15a14d3929d3238d844e710f5a291b422`.

The [complete original job log](actions-2582a6d15a14/qrom-implementation.log)
is retained with its original mutant failures and rejected-input output. The
retrieved log has SHA-256
`7d7368fa962e4f6cb6d1c9715d9bb6376dd8b0fff23500fc84e2cb281d8b9a9f`.
The `test_w1_qrom_implementation_audit` suite ran 19 tests with two failures
and two errors. The workflow-gate class then reported a setup error. The
standalone reproduction step exited 2 with:

```text
input exceeds bound: formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs
```

The failures that expected a later `pinned input drift` diagnostic encountered
this earlier fixed-size refusal. These observations are original failure
evidence; they are not successful validation of a newly maintained mapping.

The [reader](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/2582a6d15a14d3929d3238d844e710f5a291b422/scripts/w1_qrom_implementation_audit.py) deliberately uses each manifest record's
exact `bytes` as the bounded read limit, then checks both exact length and
SHA-256. Its general two-MiB protection is a separate limit. Current `main.rs`
exceeds the frozen 9,233-byte record before the later `pon_wire.rs` record
is reached. Raising a generic cap would not restore source identity. Changing
only the main record would expose the second mismatch, and changing the
contract also requires confronting its fixed `CONTRACT_SHA256`.

The reader is correctly refusing to call different source bytes the frozen
mapping. Its failure does not itself establish a verifier exploit, quantum
attack, or invalid historical receipt.

## 5. Follow-up boundary

The source comparisons give no evidence that the fixed core v2 relation,
guest, image identifier, receipt profile, or the selected locked dependency
bytes changed. The `native_once` addition can be reviewed as an explicit new
CLI observation boundary without inventing a different Grover theorem or
claiming a new QROM result.

A mapping that describes the **current** executable and accepted input paths
nevertheless needs a clearly versioned current-source record. It must retain
the old contract, source anchor, historical receipts, and execution provenance;
acknowledge both production changes; identify the funded decoder and applicable
entry/profile scope; and independently validate any new complete-cost claim.
A claim spanning the newly accepted funded-task forms must state the associated
input-domain and eligibility assumptions. A selected-file digest refresh alone
is not complete runtime closure.

All project lifetime query inputs, concrete reduction errors, adaptive
composition bounds, quantum security bits, and proof/consensus/production
qualification remain unknown or false exactly as the frozen contract states.
Versioned current mapping, required execution, and complete cost coverage remain
pending. This document changes none of those gates.
