# Native selector repair and transaction identity observations

**HOLD_NO_GO.** This continuation repairs collection and adds an identity
diagnostic. It establishes no business-throughput rate or production activation.

## Original failed attempt

The exact-head [four-axis run 42634668898](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42634668898)
on `24bd150a2683b5a375171d062af8256852db5321` completed with failure. Native job
`129219543615` completed both libtest builds and strict component Clippy. Its
runner completed the M06 experiment and four root observations, then retained
two planned Node processes as NOT_RUN because the native inventory contained
both `ingress::public_v2::tests::write_half_closed_or_disconnected_signed_submits_waiting_or_queued_do_not_start_work`
and the corresponding V3 path. Its function-only selector correctly refused
two matches. This is a collector failure, not an executed cancellation failure.

The [original complete artifact ZIP](original-ci-components.zip), artifact ID
`13684603519`, is retained byte for byte. SHA-256 is
`a21332e0ff41d47d133bada5048face5142ea9e3bd458ea543404aab6649cd84`.
The [recheck](recheck_original_ci.py) uses the unchanged strict block reader,
original raw stdout/stderr and process receipt; it checks all 84 records,
retains all 12 measured pairs per distribution and resolves the repaired six
selectors against the actual original Node inventory. It starts no native test.
The [derived readback](original-ci-recheck.json) preserves the failed status.

| Senders | Reference median ms | Candidate median ms | Candidate change | Faster pairs |
| ---: | ---: | ---: | ---: | ---: |
| 2 | 4.867278 | 5.669892 | +16.49% | 4/12 |
| 64 | 7.726511 | 7.399924 | -4.23% | 8/12 |
| 256 | 10.696232 | 10.379788 | -2.96% | 12/12 |

These are the original CI's component samples, separate from the earlier local
host samples. There is no uniform wall-time benefit. Per-arm CPU, confirmed
unique business TPS and future tail performance remain unknown. Matching roots
and signature checks are correctness observations, not throughput numerators.

## Collection and identity changes

The runner pins the complete V3 TCP owner path and retains its unique-match
guard. Five regression controls cover both real owner names, missing V3,
duplicate V3, unexpected matching owners and the unchanged five unit selectors.
The dedicated workflow runs these controls alongside native collection.

The execution report adds the independently versioned
`trnm-campaign-transaction-identity-observation-v1` extension. It deduplicates
timely transaction hashes across phases and runs while preserving all original
confirmation-round counts. Unknown rounds and missing positive identities
withhold an exact total; known distinct hashes form a lower bound. A regression
with the same hash in all 27 planned rounds keeps 27 confirmation observations
and one distinct hash. Independent business transactions and TPS remain null.

The prepared-source checks run 36 execution-report, five selector and 17 strict
block-reader controls. The original selector refusal, preparation-only preflight
failure in a copy without Git metadata, and subsequent full-worktree validation
are separate observations. Source hashes bind the prepared files; these checks
do not authenticate a native execution or replace either original service gate.

Original Host and thirty-second campaign budgets, every failed attempt and
strict acceptance logic remain unchanged. Independently useful tasks with
complete costs, complete cold/hot version delivery and model-service net value
still require their original task owners and source-bound observations.
