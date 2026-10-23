# Source-specific native reruns

These files preserve both unsuccessful and successful native observations. The
`results.json` files, where present, identify the exact source commit and tree,
commands, exit codes and wall-clock duration. `chain-54-correct-clippy` is a
log-only followup on the source identified below; it has no `results.json`.
A later fix does not change an earlier result. Command duration can include
compilation.

| Directory | Exact source | Observed result |
| --- | --- | --- |
| `chain-p0-native-a0` | `a0cd8ecf507cc4b6259e6bfe25fc37a1845660a1` | The new V4 fixture failed `CONTINUITY_REWARD_QUEUE`; sparse fixture heights had omitted required per-height native transitions. Other completed steps retain their own results. |
| `chain-p0-native-54` | `54fae446d956be1e3095537aa02035e310ad03b0` | The corrected two-generation V4 native test passed. The V3 observer test failed `MEMBERSHIP`; the shared-64 fixture failed `UnknownParent`; the existing pinned-peer CLI observed two transport errors. These failures remain failures on this source. |
| Same directory | Same source | All four explicit release W1 producer/verifier campaigns completed. Their stdout is the original JSONL, including unsupported arms, missed attempts, relation failures, budget refusals and recovery. They do not certify the other failed tests. |
| `chain-54-correct-clippy` | Same source | Strict Clippy for the actual MVCC, Node and worker packages passed. The earlier invocation with the nonexistent worker package name remains recorded as a command failure in the original run. |
| [chain-390-native](chain-390-native/results.json) | `390617cbe7b169843f60c5622ec26d2531f385d3` | Corrected membership/quorum/observer, shared-64, pinned-peer, public-pool/from-zero and strict Clippy steps passed. `applicability-negative` still failed: expected 18 profiles, observed 19. This batch is not all-pass. |
| [chain-390-operational](chain-390-operational/results.json) | Same source | One-second paced growth failed `WORK_BUDGET`; original public V3 multiprocess baseline and both hostile modes each confirmed 0 of 3 planned signed rounds. The mixed target retained a missing-parent-directory failure alongside a passing mixed-call test. Four functional restart/recovery/cut/DA commands passed. |
| [chain-390-measured-followup](chain-390-measured-followup/results.json) | Same source | Ten-second paced growth completed 800 unique confirmations. The exact narrow network-only test passed after creating its original report parent directory; formal final confirmation follows the hostile worker joins. Neither result replaces the operational failures. |
| [Source494 final archive](chain-494-final-native/SCOPE.md) | `4940b7a8072761807c5da75b322eecb05a5f193f` | The actual authenticated-v1 campaign failed: baseline/from-zero/late-product each confirmed 0/3 planned signed rounds and acknowledged 0/25, 0/15 and 0/15 offered honest Submit attempts. Equal final states remained at the initial seed tip. |
| [Source494 static results](chain-494-final-native/expanded-results/chain-494-final-static/results.json) and [corrected source observers](chain-494-final-native/expanded-results/chain-494-correct-source-observers/results.json) | Same source | Format, strict Clippy, the precise formerly failing applicability case, 12 W1 reader controls, 33 source-integrity controls and 948-link source check passed in their named invocations. Two original harness invocation failures remain retained. |
| [Earlier authenticated comparison attempt](chain-494-final-native/expanded-results/chain-a51-auth-comparison-v2/results.json) | `a51a2eeab84e3c1ff59e4df1a1088e1c16dd5a13` | Format failed before the business campaign ran. Its original output is retained in the same compressed archive. |

The source390 native observations exercise the fixes to the V3/V4 membership
decoder, fixture parent activation, and initialization of both empty Node stores
before the finite pinned-peer window. The earlier source54 failures remain
unchanged. See [source390 scope and six metrics](CHAIN_390_SCOPE.md) and its
[derived observations](chain-390-observations.json) for the exact source/tree,
unique-ID checks, denominators, latency samples and remaining failures.

The [transport manifest](transport-manifest.json) records byte counts and SHA-256
for these original files. Host paths in raw logs identify the retained execution
context, not installation instructions or production service identities.
The source390 addition contains 333 original files (29,758,583 bytes), selected
only from the three directories above. Transfer archives/chunks, publication
authentication logs and other repositories are excluded. The derived JSON and
this navigation are separate from the original-file transport manifest.

The later [source494 archive](chain-494-final-native/SCOPE.md) preserves all 310
original members (33,198,520 uncompressed bytes) in an 8,861,501-byte compressed
file, with its original member manifest. Only five small JSON members are
expanded for navigation; this is not a fully extracted collection. The compressed
archive, manifest and expanded copies all have physical-file hashes in the main
transport manifest. Expanded copies do not multiply native observations.

## W1 accounting boundary

The four JSONL files in `chain-p0-native-54` record same-target constructed tasks,
all producer attempts and three verifier implementations. Repeated receiver
requests are not unique blocks or transactions. The original shared CPU domain
uses a 100 ms start reserve: refusal means insufficient credit for this reserve,
not necessarily a zero balance. Hardware, source, target, input identities and
deduplication must accompany any derived ratios.

The runs are finite, single-host development measurements. They do not establish
independent operators, an adversarial lower bound on work cost, public-network
availability, model efficacy, or installed and subsequently qualified updates.

## PN0–PN6 convergence, 2026-10-23

The [convergence index](pn-convergence-20261023/SCOPE.md) preserves original red
observations, source-bound combined growth/migration/public-entry results,
paired Hepta component observations and explicit remaining phase exits. Overlay
results, clean source identity, release binaries and prospective-merge gates
remain separate evidence. See its [file manifest](pn-convergence-20261023/MANIFEST.json).
