# C2 GitHub failures: retained time-slice readback

Candidate source is `cc4dd8bdd89309c635831db30b508af2f89419d7`, tree `161d3a4e8ab8c865869352339ec8c66f6609449a`. This packet preserves selected existing text evidence from PR #782. It performs no new GitHub query, test, workflow retry, proof, source edit, or ref change.

The separately retained local exact-C2 qualification reported **770 passing test methods**. That result does not make remote GitHub checks green. These saved PR observations are time slices: the earlier has 103 checks, 17 completed, 86 in progress and one failure; the later has 104 checks, 71 completed, 33 in progress and eight failures. Neither is a final all-checks verdict. Prospective-merge rows are attached to candidate C2; their actual merge source is not independently requalified by this packet.

## Confirmed findings and limits

| Retained failed check | What the available original evidence establishes |
| --- | --- |
| `retained-pressure-failure` | Fixed historical artifact `11531476198` returns HTTP 404. Historical run `37730166589` is readable and lists zero artifacts; the same identity can list 12 current-run artifacts. Expiration versus deletion is unknown. The fixed archive remains unavailable, so FAIL/HOLD remains; no replacement sample is supplied. |
| Fresh challenge service, x64 head | Actual fresh native test exits 101 at `fresh_challenge.rs:244`. It fails the unchanged four-second/six-depth business target after writing its report. The wrapper `FRESH_NATIVE_PROCESS_REQUIRED` refuses the nonzero exit; it does not indicate a missing binary. |
| Cross-architecture cost, ARM64 | The strict report gate returns `CONFIRMATION_TARGET`. Five named native invocations return zero, which does not override the failed business observation. The manifest remains `passed=false`, `execution_finished=false`. |
| Original native campaign, x64 head release | The actual printed result records `ORIGINAL_THREE_RUN_CAMPAIGN_FAILED`: all three predeclared observations return 101 with `original_criteria_met=false`. Build returns zero; phase-startup error lists are empty and report-validation errors null. Exact inner panic/business-predicate attribution has not been independently completed. |
| Protocol-contract, head | Available log confirms the original from-zero command/outer service exits 1 after successful build, source and OpenSSL preparation. Its inner cause remains independently unattributed. |
| Cross-architecture cost, x64 | Failure appears in the saved PR snapshot; inner cause is not independently attributed here. |
| Fresh challenge service, prospective merge | Failure appears in the saved snapshot. The head diagnosis is not copied onto this row. |
| Protocol-contract, prospective merge | Failure appears in the saved snapshot; inner cause is not independently attributed here. |

## Original four-second target remains intact

For the x64 fresh challenge case, the attack-free baseline independently confirms one transaction at depth six in **2.894233678 seconds**. Under 16-worker fresh pressure the independent client confirms zero transactions. History replay 0 is accepted. Replay 1 runs from 3.386899779 to 4.085282455 seconds and is refused with `PUBLIC_REQUEST_DEADLINE`. There is no final independent confirmation observation and no post-window success credit. Both invariant targets remain true, no attack is accepted, and the receiver matches a valid honest prefix. The pressure finite business target is the failing term in the retained source assertion.

The same job's original retained-packet test returns zero but reports `finite_target_met=false`, so its strict wrapper rejects `CONFIRMATION_TARGET`. Its retained final pressure-replay diagnostic also records `PUBLIC_REQUEST_DEADLINE`.

For ARM64, baseline confirms 1/1 in **1.794255963 seconds**. The pressure phase confirms 0/1 even though all seven signed submit acknowledgements succeed within the original window. The 3.944495557 seconds remaining at business start are exhausted without independent confirmation. Submit acknowledgements are not confirmation. Raw invariants/accounting/no-attack/valid-prefix observations remain true; a false full-state-equality field is not described as an attack rewriting State.

The observed public-service contract is 0.25 CPU and 2 GiB, with the original four-second window and 16 pressure workers. This packet does not attribute the entire failure to CPU quota, establish a common cause across jobs, or make a regression claim. Budgets and assertions are unchanged.

## Public contents

`PUBLIC-ALLOWLIST.json` is the only file-copy allowlist. Each `files[]` entry uses `path`, `bytes`, `sha256`, and `kind`; copied files also identify `source_relative_path`. Paths are relative to this packet. Publish only those files plus the allowlist itself. Do not recursively publish any source directory named inside a copied manifest.

The packet includes the two original PR snapshots, selected failure-job logs and API metadata, manifests/status receipts, the small fresh/original service logs, the bounded phase projection, ARM64 summary, and the original campaign log/result payload. Original text copies are byte-for-byte and checked against unchanged sources. The campaign JSON payload is extracted from one identified original log line and labelled as derived.

ZIP archives, ELF/binaries, SQLite databases, full native report dumps, private analyses, and all unselected members are excluded. Original manifests can enumerate excluded members; retaining a manifest does not assert that this packet contains its entire archive.

The earlier ARM64 readback helper `KeyError: cases` and the direct-SSH capacity refusal are retained as diagnostic failures. They are not relabelled as test or proof outcomes. Original tool-response text is retained as strings, preserving large integers without JavaScript reserialization. No failed evidence is replaced by a later helper success.

See [report.json](report.json), [source-copy-inventory.json](source-copy-inventory.json), and [PUBLIC-ALLOWLIST.json](PUBLIC-ALLOWLIST.json).
