# Source-specific native reruns

These files preserve both unsuccessful and successful native observations. The
`results.json` in each directory identifies the exact source commit and tree,
commands, exit codes and wall-clock duration. A later fix does not change the
result of an earlier run. Command duration can include compilation.

| Directory | Exact source | Observed result |
| --- | --- | --- |
| `chain-p0-native-a0` | `a0cd8ecf507cc4b6259e6bfe25fc37a1845660a1` | The new V4 fixture failed `CONTINUITY_REWARD_QUEUE`; sparse fixture heights had omitted required per-height native transitions. Other completed steps retain their own results. |
| `chain-p0-native-54` | `54fae446d956be1e3095537aa02035e310ad03b0` | The corrected two-generation V4 native test passed. The V3 observer test failed `MEMBERSHIP`; the shared-64 fixture failed `UnknownParent`; the existing pinned-peer CLI observed two transport errors. These failures remain failures on this source. |
| Same directory | Same source | All four explicit release W1 producer/verifier campaigns completed. Their stdout is the original JSONL, including unsupported arms, missed attempts, relation failures, budget refusals and recovery. They do not certify the other failed tests. |
| `chain-54-correct-clippy` | Same source | Strict Clippy for the actual MVCC, Node and worker packages passed. The earlier invocation with the nonexistent worker package name remains recorded as a command failure in the original run. |

The subsequent integration candidate fixes the actual V3/V4 membership decoder,
activates each native fixture parent, and initializes the two real empty Node
stores before beginning the existing finite pinned-peer server window. Those
fixes require their own native observations; none is retrospectively applied to
the logs here.

The [transport manifest](transport-manifest.json) records byte counts and SHA-256
for these original files. Host paths in raw logs identify the retained execution
context, not installation instructions or production service identities.

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
