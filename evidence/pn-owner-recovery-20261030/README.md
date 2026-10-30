# PN owner recovery: local controls and historical readback

This is development evidence within the existing PN0–PN6 plan. It grants no
production, model-installation, whole-chain post-quantum or public-service
qualification. [The manifest](manifest.json) records the exact archive and member
hashes. The archives preserve original failures as well as successful controls.

## TPQ1 ephemeral replay consumption

[Original PQ evidence](pq-owner-original-evidence.tar.gz) contains commands,
source hashes, exact source snapshots, the RED/GREEN logs and scoped lint output.
The original native parent was `b23c0ef85f058507185b2ccb404a5d648e447c06`.
The same two changed Rust files were carried onto the parallel reader continuation
`24b265834daea34947adbb5903d887e3f6043838` without changing their verified bytes.

The original implementation accepted the real FIRST ML-DSA fixture in five
SQLite temporary/in-memory configurations, closed the connection, then accepted
the same authorization again with sequence one. The RED selection had 13 passing
tests and one failure. Checking SQLite's actual main backing before owner
initialization makes all 14 selected tests pass, including the original twelve
owner controls and an ordinary disk file whose basename is `:memory:`.
The 887 other library tests were filtered, not executed by that selection.

Strict scoped Clippy and rustfmt returned zero. The retained Clippy build-script
warning reports an unqualified SQLite I/O boundary because a relocated toolchain
was addressed through a symlink. A subsequent canonical-RUSTC call reused that
build-script observation. No guard was changed, and neither call is I/O
qualification. That separate qualification needs its original controlled build.

Rejecting temporary main backing does not establish physical power-loss safety,
host trust, rollback resistance for a complete copied database, production
activation of TPQ1, or replacement of the remaining classical authorization paths.

## Independent History accounting readback and convergence

[The independent readback archive](history-independent-readback.tar.gz) preserves
the initial local reader proposal, its RED/GREEN controls, original artifact
member hashes and the subsequent independent review of the parallel `24b2658`
reader. The integrated production reader adopts that parallel implementation;
the earlier local proposal is historical evidence and is not a second runtime.

Original source: `b23c0ef85f058507185b2ccb404a5d648e447c06`. Original GitHub run:
[41007753791](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41007753791).
Artifact ID: `12957120443`; original ZIP size: 74,599,831 bytes; SHA256:
`754e3cd072d14f608051898a6e00a13469c51f73e75e4ae6fa38ef8a761e54f0`.
The full original ZIP was independently downloaded and all 1,575 manifest members
verified. This small archive contains the readback records and member index,
not a second copy of that original ZIP.

All 5,336 original CPU samples, including 473 legitimate negative stored-credit
samples, satisfy the adopted reader's original reservation and conservation
checks. Original runs two and three meet the unchanged reader criteria; run one
still fails complete receiver/verifier state equality. No native campaign was
rerun by reading these records. Original CI failures, strict-History deadline
failures and the absence of a three-of-three campaign pass remain failures/open.

The parallel reader also preserves u64 counter ranges, the original burst cap,
owned start reservations and full/live/settled CPU attribution. Independently
comparing its business-gate function bodies against b23 found no change to
profile selection, admission, depletion, phase requirements or full readback.

[Terminal settlement controls](terminal-settlement-controls.tar.gz) extend one
existing test method without changing the production reader or its fourteen-test
roster. Both one-owner and two-owner signed live balances first pass accounting,
then fail the original terminal-quiescence gate in both phase and full-report
readback. Legitimate booked credit never becomes evidence of completed settlement.
