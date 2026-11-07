# W1 admission acceptance readback notes

Working source: `fix/chain-w1-ingress-contract-20261107`, based on
`3d1b6507671ec694ce58e86d4063a125c8deeb66`. These notes describe the local changes
and checks, not a new original-resource native service qualification.

## Owned changes

The original acceptance subtask edited `scripts/pon_public_v3_phase_read.py`
and `scripts/ci/test_pon_public_v3_phase_read.py`. A later explicit parent
assignment also owns the policy vector/readers and current native digest
assertions described below.

The default readback schema is now
`pon-public-v3-multiprocess-phase-derivation-v4`. It adds the
`pon-public-v3-business-completion-v1` object to each original phase. The raw
native workload, thresholds, success flags, budgets and execution are unchanged.

The original native multiprocess source fixes three seven-block business rounds
at t=1/5/9 seconds within one absolute 30-second phase. The new readback reports
every planned round, including missing/unknown rounds, with a fixed denominator
of three. Its scheduled latency includes delay before the actual round starts.
It also reports actual-start latency separately when that clock is known.

A readback-supported timely confirmation requires the native in-window flag,
an end strictly before the original phase end, and retained matching
transaction/included-block/tip, depth-six, cumulative-work and non-authoritative
confirmation facts. Missing facts remain unknown. Successful ACKs, receiver
state equality and later/cold confirmation cannot substitute for those facts.
Conflicting clocks/context/depth/work are refused.

Empirical successful-only p95/p99 retain their known/unknown sample counts.
Whole-offered p95/p99/max remain null unless all three scheduled rounds have
supported in-window confirmations and known scheduled latencies. Three samples
do not supply a population tail guarantee or a fairness claim. The reader does
not authenticate an actor, prove W1, establish physical resource bounds or
verify attacker CPU/bandwidth. Original service flags remain unchanged.

`analyze_for_retained_schema` reproduces immutable v1/v2/v3 outputs without the
new extension. The standalone `phase_summary` preserves its historical default,
so the original retained-campaign reader's exact historical shape is unchanged.

## Executed checks

- `bash scripts/project-preflight.sh`: PASS before edits.
- `python3 scripts/ci/test_pon_public_v3_phase_read.py -v`: 66 tests passed.
  Ten added business-cohort controls cover delayed start, missing rounds,
  failed/late/cold outcomes, missing evidence despite successful ACKs, unknown
  clocks, failed startup, original deadline, context/depth/work mutation and
  duplicate/extra rounds. Existing tests also prove v1/v2/v3 reproduction.
- `git diff --check -- scripts/pon_public_v3_phase_read.py scripts/ci/test_pon_public_v3_phase_read.py`:
  PASS.
- Hash-bound readback of the existing historical raw campaign
  `evidence/pon-upgrade-implementation-20261018/native-rounds/chain-390-operational/public-v3-multiprocess/report.json`,
  SHA256 `c662cf7d71adec835eb22e60058e3eccb7dc3faa88a31e262ec1bd4bdc069233`:
  the original native gate stays false; baseline/from-zero/late-product each
  stay 0/3. Each phase retains one unconfirmed round plus two unobserved rounds,
  and every business tail remains null. This is historical readback, not a
  measured result for the current code.

## Retained validation invocation failures

An initial invocation of `test_read_original_native_campaign.py -v` was refused
by argparse because that special test runner requires explicit real-artifact
pins. No native or parser test ran in that invocation.

The correctly pinned invocation then executed 19 tests with 19 recorded error
occurrences caused by `os.link` from the workspace artifact to `/tmp` returning
`EXDEV` (different filesystems). The original artifact setup/readback succeeded;
counterexample fixture cloning failed. No source/test assertion was modified.
A same-command retry uses `TMPDIR=/workspace/scratch/270e2a9ce94f/acceptance-tmp`
so the fixture and original occupy the same filesystem. The retry passed all
19 tests in 24.287 seconds. The first failed observation remains recorded here.
The unchanged real-artifact pins were manifest SHA256
`12406cc156e57c130fa14af2b50b386031ec3640ce7f0234ed5bc9f0a700aac3`,
source `9e705ccf75b7318dcc4bda4815956f58beb10e72`, tree
`521ae87a28060d545979069b189eebbc74a71fd8`, with `--retained-subset`.

## Required source-pin updates owned by root

`config/pon/pq-cross-branch-corpus-v1.json` pins both edited files. Refresh their
exact Git blob IDs in the normal source-contract process. No exact test-count
gate for this 66-test script was found; existing CI invokes the complete reader
suite by filename. No new original-campaign run is implied.

## Current r16 policy binding continuation

The parent changed the actual signed resource contract in `public_v3.rs` to
`resource-revision-r16` for the shared classical authentication CPU sublimit
and earlier existing-domain startup check. This subtask copied that exact
contract into `config/pon/public-resource-profile-vectors-v1.json` and recomputed
the three raw and three arithmetic IDs using the original domain-separated
hash encoding. All five historical raw revision entries r10--r14 and both
historical r13/r14 arithmetic entries compare exactly with their original
Git content. Revision r15 is deliberately absent because its branch is not
integrated. The existing 64-KiB input bound stays unchanged; current config
length is 28,508 bytes.

Current config SHA256:
`9113980f13a3620cf9ca5a3c665f781bb3bf1a3c0d58bd1e5e958b185ad66c22`.

| Bits / 2,000 ms | Raw r16 policy ID | Arithmetic r16 policy ID |
| --- | --- | --- |
| 8 | `4abdedfb5e177f310e2fb836347cb040e647addf2405f2e4cf78b5e4baa4cd5d` | `dcb42bd05cba86e27798eabd46d5eb2fd242c9b783e644a5e6fe833dc3b764af` |
| 12 | `8428e1b62713405142ad1aa4ac688f9b455c865c1ffc3781fa75cab5c122a082` | `5bd53bb34c9246f80b4559184bc3851d65ea70080695ddb5b13610ff70238f8b` |
| 16 | `75a918355d0172da4f4ce9319b2d4d69ba826a4543b60ba2f84462c1d5f5704b` | `bf938bddbbdbc1cc0b95c08a30d41fc0a92d9033908e42be9a19bcc07ce4a906` |

The policy reader and its seven exact-vector/schema controls accept precisely
that current revision plus the retained historical revisions. The phase reader
accepts r16 raw/arithmetic as distinct profile identities, retaining original
paid CPU scope: reactor authentication is still outside the mutation CPU
observation, and response/auth sublimits cannot be summed as disjoint physical
CPU. Its complete suite now passes 67 controls.

In `tests/public_v3_multiprocess.rs` only the two current raw/arithmetic
8-bit digest literals changed. In `tests/support/multiprocess_support.rs` a
comment explains that `RawR14` is a historical selector spelling for current
plain W1; `policy_observation()` supplies the real revision. The selector and
all host-job bytes, workloads, deadlines and success criteria are unchanged.
No other support file was edited.

Final owned paths requiring normal source pins are the config above, both
policy readers/tests, both phase readers/tests, and those two native test
files. Final `git diff --check` passes for all seven paths.
The same 19 pinned real-artifact compatibility controls were repeated after
the r16 policy extension and all passed in 22.506 seconds with the same
filesystem-local `TMPDIR`; all original artifact contents remained unchanged.

## Follow-up semantic counterexamples

The parent requested a final review of partial failed phases and zero-work
confirmation facts. The original producer's panic wrapper currently emits a
new error-only object rather than retaining its phase rows; a bounded read of
all ten matching retained JSON files found no existing error-plus-partial-rows
object. Nevertheless, the v4 branch previously accepted such an object while
silently replacing its supplied confirmations with an empty list. It now
preserves explicitly supplied rows under the original 30-second metadata,
records the phase error and keeps original acceptance unchanged. Any phase
error suppresses an all-offered finite tail even when success-only rows exist.
Absent observations are never reconstructed.

The prior v4 comparison also allowed a synthetic zero/zero work threshold to
satisfy the numeric >= relation. The original native confirmation computes
`required_work(included_target) * 6`, where required work is at least one for
every legal 256-bit target. The new necessary check requires a threshold at
least six, divisible by six, and actual delta at least that threshold. It does
not infer the included target or certify an execution. Zero, below-six and
non-multiple counterexamples now refuse.

Two focused controls were added. The complete phase-reader suite now passes
**69 tests**, including unchanged v1/v2/v3 reproduction. The two phase files'
`git diff --check` remains clean. Their blob pins must reflect this last edit.
