# C1 selected static validation: c09dbbe992

This package preserves the selected static validation of commit `c09dbbe9921da12db8bf7240a8a95a0e9a789e50` (tree `f15a7ee4a0f5455eaf965db01dcd49e02a5f22b6`). **577 top-level Python controls and five static Cargo commands completed within the retained selected scope. Native validation is separate and is not included in this static archive.** Whole-chain post-quantum qualification and production activation remain false.

The original interrupted observation and the later recovery are retained independently. The first integration command has only 18 progress dots, no terminal receipt and no overall source-after snapshot; its terminal state remains **unknown**. Those dots are excluded. The recovery is a separate execution, not a continuous successful run inferred across the interruption.

## Observed results

| Retained observation | Complete commands | Count included | Basis |
| --- | ---: | ---: | --- |
| Initial selected Python run | 9 suites | 204 outer tests | Nine receipts, exact log digests and terminal `OK` |
| Separate resumed Python run | 18 commands, including 4 suites | 270 outer tests | Four complete suite results; seven readers and seven workflow bodies also exited zero |
| Original fixed QROM roster | Within resumed `named_tests` | 81 named controls | Exact registered, started and successful ID sets |
| Historical fixture controls | Within resumed `historical_controls` | 8 named controls | Separate fixed supplemental roster and completion |
| Current implementation controls | Within resumed `current_implementation` | 14 named controls | `test_w1_qrom_current_implementation_audit` |
| Static Cargo checks | 5 | No native tests counted | Preflight, three locked/offline metadata commands and formatting |

The Python total is **204 + 270 + 81 + 8 + 14 = 577**. The three QROM groups contain exactly 103 distinct successful IDs and no overlaps. The current 14 are separate from the workflow-gate 14 already included in the original 81. Nested negative subcases, prefreeze runs and incomplete progress are not added. The integration suite's 60 methods include 46 direct methods and 14 inherited reader controls. No skipped, failed, expected-failure or unexpected-success cases are counted as successes.

Outer unittest logs establish completed suite counts; their source AST roster cross-check does not invent individual runtime receipts for dot-mode logs. The QROM completion files do provide exact runtime success IDs.

## Source binding and limits

All complete Python receipts and static Cargo observations identify C1 and the same tree. The initial source-before snapshot and resumed source-before/source-after snapshots are byte-identical: SHA256 `81966162e2ae881348ae09cb94879b8b705fd309fba1d79b1d30aeb86f676b1f`. They cover 5,135 materialized tracked files totaling 171,498,180 bytes and record 22,777 unmaterialized sparse paths. These are **sparse static snapshots**, not a claim that the entire checkout was materialized. The preserved later partial observer record independently checked the materialized bytes, modes, hashes and Git blob IDs; it does not replace the initial run's missing source-after record.

Packaging independently checked every receipt/log hash, complete terminal result, source identity, recovery record and QROM success roster. It checked the retained workflow bodies and fixed test rosters against targeted C1 Git blobs, and cross-checked the 474 outer test methods from source. Packaging did not rerun tests or rescan the full Git source tree. The original files remained unchanged while the archive was produced and reverified.

Native validation was still in progress when this static observation was packaged. No native test total, native success, Clippy result, hosted C1/C2 CI result, deployment result or whole-chain security conclusion is inferred here. A later native archive and its own source/time/command summary must be added separately; preserve this static archive and the unknown first-run terminal state. An evidence-only follow-up commit is not the revision on which these workloads ran.

## Files and verification

- [static-summary.json](static-summary.json): derived result and explicit qualification limits.
- [static-source-verification.json](static-source-verification.json): snapshot scope, targeted source checks and workflow body bindings.
- [static-test-roster.json](static-test-roster.json): 474 source-declared outer methods and 103 observed QROM success IDs, with distinct provenance.
- [static-raw-index.json](static-raw-index.json): every original file's path, byte length and SHA256.
- [static-raw-c09dbbe992.tar.xz](static-raw-c09dbbe992.tar.xz): 160 original files, 15,184,911 uncompressed bytes, including both original harnesses and the interruption/recovery observations.
- [STATIC_SHA256SUMS](STATIC_SHA256SUMS) and [verify_static.py](verify_static.py): portable integrity and observation checks. Extra future native files do not enter the static count.

Run `python3 -B verify_static.py` from this directory. In the original workspace, `python3 -B verify_static.py --originals /workspace/scratch/d4d2da8133e2` additionally compares every archive member with its unchanged original file. The verifier reads evidence only; it never launches the validation workloads.

The raw archive SHA256 is `0e84878ae27b3c1895eada4cd72105326ac89fe10b9d3608dc90139ba53f4b36`; its compressed size is 574,216 bytes. Raw paths and logs retain their original provenance. Recorded timestamps and original absolute paths describe the observations, not portable execution instructions.

Static packaging timestamp: `2026-11-11T04:15:30.785451+00:00`. This README describes the static observation at that time; add a separate index for later observations rather than rewriting the original terminal history.
