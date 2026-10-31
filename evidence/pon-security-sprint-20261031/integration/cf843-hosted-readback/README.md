# Published cf843 hosted CI: selected readback

This package preserves a read-only review of published source
`cf84391a474ee1f3ac78f4a907bd95184b816a54`, tree
`c7609a5502641739505862f2e4cd3c1e06ce1041`. It contains selected original artifact
members, provider-decoded job logs, normalized provider metadata, and an explicitly
derived summary. It is not a complete campaign artifact mirror, a re-execution,
or qualification of the later integrated source.

## Actual outcomes at that source

| Run | Result and retained boundary |
| --- | --- |
| [Admission / DAA 41155114590](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41155114590) | Both x64 and ARM64 reached real native execution after successful environment setup and exact-source checks. Each had 16 passing native gates and three failing pressure gates; finite service did not qualify. |
| [V5 legal costs 41155114605](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41155114605) | Both architectures completed V3/V4/V5 and independent readers. V5 had 144 cohorts, 11,772 first-admission calls and 654 distinct fixture packet IDs across paired cohorts. Actual V5 wall time was 127.348 s x64 and 174.269 s ARM64, within the unchanged 610 s outer bound. |
| [Branch encoding 41155114551](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41155114551) | Head jobs passed on both architectures. Both prospective-merge jobs failed source identity before native execution; the event expected the old base. |
| [Required baseline 41155114648](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41155114648) | Additional head failures remained: dependency policy, one data-availability native test, and finite from-zero confirmation readers. These failures are independent of the stale prospective-merge base. |

V5 first-admission calls are per-cohort observations. The same 654 fixture
identities recur across paired cohorts; the count is not newly accumulated global
chainwork or production-network throughput. Its binaries were stable before and
after capture, but shared hosted hardware was not exclusive. No later patched
reader or new head is implicitly certified by that earlier run.

## Finite admission details

All rows below refer to the original fixed 30-second phases, 24 hostile actors,
original two-second calls and two listeners. Source before and after matched the
published head on both architectures.

| Fresh-caller observation, per phase | x64 | ARM64 |
| --- | ---: | ---: |
| Planned honest bodies | 21 | 21 |
| Actually offered / accepted on time | 7 / 7 | 14 / 14 |
| Unoffered bodies | 14 | 7 |
| Authenticated distinct from-zero hostile callers | 3,637 | 3,628 |
| Authenticated distinct correct-product/false-trace callers | 2,493 | 2,201 |

On x64 every phase retained one round with `confirmed=false`, including the
no-attack baseline. ARM64 retained a successful first confirmation and a failed,
late History/independent-verification second round in every phase. Both readers
reported consistent input but `finite_qualification=false`. Successful admission
of the requests actually offered does not fulfill the original 21-body plan.
The baseline also failed, so these observations do not attribute every failure
to adversarial pressure.

The x64 receiver-owner supplement additionally lacked terminal receiver reports
in all three phases; its reader could not find the regular `baseline.json` and
reported inconsistent input. ARM64 had completed receiver-process and caller
observations, but original and supplemental finite qualification still failed.
The actual nonzero native exits, partial logs and failed reader outputs remain.

## Other failures and old-base scope

The prospective merge `7f0b951967c0304351df6e938211e9c12791da1d` has ordered parents
`dd6e1c3cbeacbdc532b0679297835b3a0aac78f0` and the published head above. Those
failed events expected `9fedf7ecbbe07177069c030592b4e03dcffebb81` instead. The
source check correctly refused the mismatch. A later metadata refresh does not
turn these prior failures into passes.

The main all-features dependency graph failed cargo-deny 0.20.2 against RustSec
commit `2295466c4e9df26647fd67d8fa1c705ac2fc7f81`: bincode 1.3.3
(`RUSTSEC-2025-0141`), derivative 2.2.0 (`RUSTSEC-2024-0388`) and paste 1.0.15
(`RUSTSEC-2024-0436`) were unmaintained; tracing-subscriber 0.2.25 had
`RUSTSEC-2025-0055` for ANSI log injection. The fuzz graph passed. These are the
retained policy diagnostics, not proof that an exploitable consensus failure
occurred.

The runtime shard had 136 passing and one failing data-availability test:
`cell::discovery::tests::first_manifest_read_preserves_cold_warm_status_and_exact_rejection_counts`.
It unwrapped `Io(WouldBlock)` / OS error 11 at
`crates/trnm-data-availability/src/cell/discovery/tests.rs:407:10`. Its final source
check passed; no flake classification or repair is inferred here.

Protocol-contract and both architecture cost jobs ran five named native controls
successfully, but their subsequent confirmation reader returned
`CONFIRMATION_TARGET`. Named libtest execution success did not qualify the finite
confirmation target.

## What is retained and verified

`summary.json` is the explicitly derived review. `manifest.json` lists every
payload's stored and decoded byte counts/SHA-256, its origin, the original run/job
IDs, and the immutable downloaded archive bindings. The source ZIP hashes were
matched against GitHub artifact metadata, and every selected ZIP member was then
byte-compared against its original member after packaging/decompression. The
verification result is retained in `packaging-verification.json`.

Both approximately 100 MB admission ZIPs and the quality ZIP are deliberately
omitted, as are native binaries. Their artifact IDs, original byte counts and
SHA-256 remain. ZIP basenames in the earlier summary identify the retrieval files,
not additional files promised by this selected package. V5 observations are
preserved through the fetched decoded job logs and metadata; its full archive
was not downloaded by this review.

Gzip payloads decode to the exact selected original bytes; no diagnostic or
terminal output was edited. Provider job logs are the decoded text returned by
the GitHub plugin, not a claim of byte identity with GitHub's downloadable log
archive. Provider metadata snapshots are normalized JSON. Neither packaging nor
byte verification reruns any native campaign, verifies model effectiveness,
changes a prior failed gate, or grants installation, consensus or new-head
qualification.
