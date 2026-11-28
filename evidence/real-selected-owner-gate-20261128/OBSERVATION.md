# Actual selected-owner gate: incomplete, first failures retained

The original two SQLite owner tests have **not executed**. The real
`trnm-pon-node` wrapper check has **not started**. Earlier 6/6 pure binding
controls do not establish either result. This evidence-only change preserves
the first actual-crate attempt without changing source, profiles or acceptance.

## Exact source and preparation

The tested source was commit
[`c471cba4aad9112dfb7226cd524b286093e176ea`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/c471cba4aad9112dfb7226cd524b286093e176ea).
Its **whole commit tree** is `2cc77da9bda193616f8831ad4cdc7037816080a9`.
`9db8871c16d333904670bcae5b16945dcd6ce8e6` is specifically its
**`trillionnium` Rust subtree**. Earlier commentary omitted that subtree label;
the frozen manifest and source bytes were unchanged, and that wording correction
did not trigger another run.

All 1,717 Rust-subtree blobs were reconstructed and hash checked from that
commit. The actual Cargo metadata resolved 26 workspace packages. All 162
registry archives matched the committed lockfile checksums and were copied to
an isolated offline source directory. This was a selective exact-source
checkout, not a complete checkout of the repository's historical evidence.
No existing checkout, target, credential or service configuration was changed.

## One original absolute deadline

The frozen engineering gate used the original Cargo profiles, `--offline
--locked`, two jobs and `RUSTFLAGS=-D warnings`, with one 240-second absolute
deadline. The intended sequence was the two actual SQLite tests followed by
`cargo check --offline --locked -p trnm-pon-node --lib`.

| Observation | Result |
| --- | --- |
| First actual DA compilation | Exit 101 after 98.444729368 s; eight original fixture files used through `concat!` were absent from the selective capsule. |
| Preparation correction | Those eight files were copied from the same fixed commit and Git blob hashes checked; no Rust or profile change. |
| Corrected compile within the same deadline | Started with 29.616950 s remaining; killed at the original deadline after 29.446099349 s, exit -9. |
| Original two SQLite tests | 0 executed, 0 passed; pending. |
| Actual wrapper check | Not started; pending. |

The missing fixtures were a capsule-preparation error, not evidence of a Rust
logic defect. The original stdout/stderr and failure receipt remain intact.
Post-deadline kill/reap and source-hash readback finished about 0.428470 s after
the deadline; this is not described as a total wall time below 240 s. The
deadline was not reset. Earlier 9 loader, 11 arithmetic and 6 binding controls
were not rerun. No additional historical inputs or XW calculations were read.

`GATE_OBSERVATION.json` is an explicitly derived compact projection. The two
stderr files, `FROZEN_GATE.json` and `CONCAT_INCLUDES_PREPARATION.json` retain
original bytes. `ORIGINAL_ARTIFACTS.json` records the complete retained archive
and each original member's digest; the 573,081-byte archive is not embedded in
this review packet. Its version-pinned native readback verified chunk, archive,
decompressed-content and member hashes.

## Separate remote CI first failure

The earlier [PR #1019 run, attempt 1](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/46094675971)
tested head `4f0a1ea9c37a545a454dd17b3901cf800340311e`, not the later
selected-owner commit. Its x86-64 head service-model job ran all five named
Rust tests successfully, then the original confirmation-report validator
rejected `CONFIRMATION_TARGET`. The original source explicitly requires
`finite_target_met` as well as invariants; named libtest success is insufficient.

In the unchanged 4 s window, the baseline independently confirmed one signed
transaction at 2.798563002 s latency. The 16-worker pressure phase confirmed
zero, retained `PUBLIC_REQUEST_DEADLINE`, and an unconfirmed latency lower bound
of 3.906008755 s after its 0.093991245 s business-start delay. The report's native
invariants were true and its finite business target false. This identifies the
rejected condition; it does not identify its causal source or establish a PFT
regression. No rerun, deadline change or acceptance change was performed.

The CI child receipt and systemd log here are original artifact bytes;
`CI_FIRST_FAILURE.json` is a derived projection tied to artifact `15246075425`
and the exact raw report SHA-256. The original native `gh` artifact download
timed out after 45 s and was retained; an independent authorized artifact read
subsequently retrieved and hashed the original ZIP without rerunning CI.

All observations remain engineering results. Native adoption, current user
permission, FinalUse, model quality, payment, production activation and a real
second user remain unestablished.
