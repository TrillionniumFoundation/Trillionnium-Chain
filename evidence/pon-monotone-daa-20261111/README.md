# Strictly increasing DAA compression and typed native-result binding

This continuation is based on #863 at `249f772cc2a2ace5e363fd5fbfec4241a26f4d4d`.
The frozen implementation is `d23488c5f9b4a6696c3799b12f14b8af0a1b81fc`, tree
`72b106b4458299c37da146b0218b8f5276195b6d`. Publication commits that only add this
packet are distinct from that executed implementation.

The joint release state remains **HOLD_NO_GO**. There are 18 unknown environment
inputs and 13 open proof obligations. Actual CP, CG, CQ, six-successor and lifetime
failure bounds remain null. A successful finite regression or source check does
not qualify them.

## What the witness establishes

The ordinary branch reaches height 65 with cumulative required work 130. The
compressed branch shares heights 0 through 15, then sets each timestamp to the
actual parent's timestamp plus one second. It reaches height 64 with cumulative
required work 793. All parent-child timestamp edges in this experiment increase
strictly; the ordinary and common branches also satisfy that restriction.

Relative to genesis, the unchanged periodic arithmetic is:

| Retarget height | First timestamp | Last timestamp | Signed span | Effective span | New per-block required work |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 16 | 0 | 150 | 150 | 150 | 2 |
| 32 | 151 | 166 | 15 | 38 | 7 |
| 48 | 167 | 182 | 15 | 38 | 31 |
| 64 | 183 | 198 | 15 | 38 | 123 |

The desired endpoint span is 150 seconds, with lower clamp 38 and upper clamp
600. The altered branch therefore has total work
`31*2 + 16*7 + 16*31 + 123 = 793`; the ordinary branch has `65*2 = 130`.
This supplements the existing negative-endpoint witness, whose three spans are
`-42, -199, -356`. It shows why requiring a child timestamp to exceed its parent
would not, by itself, eliminate this finite compression-and-credit behavior.
No such consensus rule is installed by this patch.

The existing [joint DAA audit](../../docs/protocol/pon-nakamoto-v1/details/JOINT_CONSENSUS_DAA_AUDIT_20261108.md)
explains the boundary. These are declared logical validation clocks, not measured
wall-clock mining cadence. Work generation, discarded attempts, private
precomputation, cross-fork quantum state, adversarial resource share and honest
network competition do not acquire physical bounds from these observations.
A reachable heavier branch is not by itself a profitable quantum attack or a
contradiction of a stated common-prefix probability theorem.

## Implementation and evidence separation

The existing negative-endpoint PNH1/PGH2 test identities, report schema and reader
remain intact. Two additional native tests use a separate
`pon-native-monotone-daa-v1` report and fresh export directory. The new PGH2
fixture uses namespace `joint-daa-monotone-endpoints-v1`. Both new native
profiles use observed-clock activation. The historical negative PGH2 experiment
retains its original non-observed activation behavior; its admission clocks are
still checked.

Each native run must generate and verify 114 complete PNW1 packets: 15 common,
50 ordinary and 49 altered. It also checks real owner admission, branch
activation, refusal to select the longer lower-work branch, changed-header
proof binding, cold head/state equality and all retained packet bytes. Four
runs are not 456 independent attack samples; shared or repeated packets are not
new statistical observations.

The new monotone reader recomputes every retained full W1 product/transcript,
actual branch ancestry, MTP, target, parent-plus-one schedule, all three positive
spans, linear work totals and declared activation/cold observations. It does
not execute native M06/application admission, verify AAM1 account proof
semantics, reopen SQL, authenticate host/source execution, or replay all failed
nonce attempts. Its report keeps those scope flags false.

The new temporal-reference regression contains 114 `TemporalHeader` records,
not 114 cryptographic proofs. The actual native and reader results are reported
separately below.

## Execution results

| Check | Frozen-source result | Evidence |
| --- | --- | --- |
| Native DAA integration target | 4 passed; 0 failed, ignored or filtered; 65.77 seconds test body | [Native terminal](native/terminal-readback.json), [raw native archive](native/native-run-d23488c5-v1.tar.gz) |
| Locked Cargo graphs | 26 workspace members; 176 default / 181 all-feature packages | Raw native archive, `graph-summaries.json` |
| Formatting | Whole-workspace `cargo fmt --all --check`, exit 0 | Raw native archive |
| Strict Clippy | Affected DAA integration target, all features, `-D warnings`, exit 0 | Raw native archive; no whole-workspace Clippy claim |
| Temporal DAA reference suite | 33/33 PASS | [Core commands and full logs](python/core/execution.json) |
| Complete CI-contract suite | 168/168 PASS | [CI execution](python/ci-contract/execution.json) |
| Source-integrity controls | 43/43 PASS | [Core execution](python/core/execution.json) |
| Native risk reader | 27/27 PASS on retained historical fixture | [Risk and qualification validation](python/joint-risk/validation.json) |
| Joint qualification controls | 34/34 PASS; consistency exit 0; qualification promotion refuses exit 3 | [Risk and qualification validation](python/joint-risk/validation.json) |
| Work-time recovery attempt 03 | 106/106 named controls + 13/13 historical boundaries; both campaign commands exit 0 | [Recovery summary](python/work-time-summary.json) |
| Repository, inventory and current corpus | PASS; 915 exact blob pins | [Core execution](python/core/execution.json) |
| Complete local tracked-source identity | 26,619 entries / 2,530,888,134 bytes; before and after identical | [Source before](python/source-identity/source-before.json), [source after](python/source-identity/source-after.json) |

The one local independent-reader recovery completed at 2026-11-12 01:22:13 UTC,
with outer exit 0 and all ten commands returning zero: source-before,
four readers, four suites and source-after. The
[actual reader validation](readers/validation.json) and
[complete reader recovery archive](readers/four-profile-recovery-v2.tar.gz)
record these results:

| Schedule / profile | Complete independent W1 verifications | Three signed spans | Suite methods | Passed | Explicit skips |
| --- | ---: | --- | ---: | ---: | ---: |
| New monotone / PNH1 | 114 | `15, 15, 15` | 26 | 25 | 1 |
| New monotone / PGH2 | 114 | `15, 15, 15` | 26 | 26 | 0 |
| Original negative / PNH1 | 114 | `-42, -199, -356` | 22 | 21 | 1 |
| Original negative / PGH2 | 114 | `-42, -199, -356` | 22 | 22 | 0 |

Every reader recomputed ordinary height/work `65/130` and selected height/work
`64/793`. All 460 report/packet inputs matched the sealed native archive and
retained identical sizes and SHA-256 values before and after execution. The
complete tracked-source identity was also checked before and after against
`d23488c5` and its exact tree. These checks bind the recorded input bytes and
source checkout; they do not authenticate a separate physical host.

The suites executed 96 methods in total, including their positive checks:
94 passed and two explicitly skipped the PGH2-only AAM1 witness mutation on
PNH1. They are not 96 negative controls. The local runtime recorded actual
8-GiB address-space and 1,800-second per-process CPU limits, and recorded that
its cgroup control files were unavailable. No remote resource-scope execution
or physical work-cost bound is inferred from those limits.

Counts are scoped and overlap: the 33 temporal DAA methods are included in the
106 work-time methods. They are not summed as independent security samples.

All result counts refer to their named suite and exact input scope. PNH1 has no
PGH2 AAM1 witness, so the profile-specific witness mutation test is inapplicable
there; any such skip is reported explicitly, rather than counted as a pass.
The old and new independent reader positives must each complete all 114 W1
verifications before returning PASS.

## Evidence integrity repair

The Python risk-ledger reader previously compared whole parsed native result
objects using ordinary Python equality. Eight retained numeric-type changes
were accepted without an independently retained original bank checkpoint.
Examples include `false` versus `0` and integer `1` versus floating-point `1.0`.
The correction uses the existing canonical JSON function to bind parsed types
and values exactly. The same changes now refuse with
`R_NATIVE_OUTCOME_BINDING`.

An external original bank checkpoint already rejected every rewritten bank
before this change, and that protection remains. The returned native
confirmation result comes from the independently checked native terminal;
this defect did not demonstrate native false confirmation. Raw lexical forms
such as JSON integer `-0` are outside this parsed-type repair. The retained
negative-zero controls use floating-point `-0.0`.

The [complete risk record](risk/README.md) preserves the old source, all mutated
banks, both successful and unsuccessful original runs, and the historical
fixture. The first full risk run encountered a missing empty fixture directory;
only a scratch copy restored that directory, with all 31 original files
byte-identical. Final frozen-source risk tests pass 27/27.

## Source pins and retained unsuccessful observations

Five current-corpus blob pins were already stale at the parent commit. The
[original mismatch record](preliminary/inherited-corpus-mismatches.json) preserves
both the recorded and actual parent blobs. Only those five reviewed entries
were refreshed; the 915-pin corpus and 823 required-path roster were retained.
The historical W1 contract, its immutable `b16bae2824e6c8236ef2011fc93a74df3ac7f039`
source identity and all old contract bytes remain unchanged. Its ordinary check
against the current source still refuses `SOURCE_BYTES`; the separately named
historical replay never becomes current native cost qualification.

The [first work-time attempt](python/work-time-attempt-01/execution.json) is
retained with exit 1: its reference class failed temporary historical checkout
before any of the 13 reference or 106 named controls completed. The complete
fixed historical contract had already passed its 1,747-entry / 27,613,671-byte
check. Any corrected attempt is a separate observation.

The second local work-time attempt lost its execution connection and has no
completion record. It remains `UNKNOWN_NO_COMPLETION_RECORD`; its missing final
record is not converted into a zero exit or a test count. Recovery imported 149
actual Git objects from the complete historical checkout, retained an unpublished
local helper ref and used normal depth-one local fetch to establish the genuine
historical shallow boundary. The final minimal shared/sparse checkout and full
attempt 03 passed in the default environment, without an alternate-object
environment override. No source, historical contract or test was changed.
[The complete recovery archive](python/work-time-recovery.tar.gz) retains all
three attempts, original unsuccessful probes, command streams, object lists,
pack payloads and their hashes.

The local execution environment was briefly unavailable and then recovered.
The original risk/core/CI files were found intact with their original hashes;
no successful log was reconstructed from a conversation summary. An additional
remote recovery driver was prepared but never launched. Its uncertain upload
and the independently verified intermediate checkpoint are recorded in the
[environment record](recovery/local-environment-and-checkpoint.json).

The original native durable-start acknowledgement timed out. Read-only recovery
later found its actual fresh output directory and exact command records; the
original runner completed all required commands at 2026-11-12 00:22:16 UTC.
A planned create-only fence did not have an observed creation/terminal result.
Because the original directory had already won the runner's exclusive admission
condition, the proposed replacement was abandoned. No replacement native
command was issued. The fence request retains its unobserved terminal state;
no `FileExistsError` or durable job exit is invented.
The raw original requests, timeout responses and runner bytes are retained in
the runtime recovery archive.

The initial implementation was pushed normally as ProfHepta and opened as
[Draft PR #920](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/920),
stacked on #863. Initial publisher preflight, source-before, source-after, push
and PR creation returned zero; the publisher PTY independently exited zero with
complete captured output. Its 44 original files are preserved in the publication
archive. To recover the original archive through the repository, an intermediate
evidence-only commit, `31f7740ed57eb3bca2e17f7e0a5f4f63cb320f5f`, added only the
native archive, exact descriptor and a scoped publication observation. Its
normal push returned zero and the remote ref was read back exactly. The
subsequent `gh pr edit` failed because its GraphQL request used the deprecated
classic Projects field, so that helper's final exit was one. A separately
recorded REST PATCH then returned zero and an exact body readback matched.
Both observations remain in the
[intermediate publication recovery archive](publication/native-intermediate-publication-recovery-v1.tar.gz).
The final evidence child also changes only this evidence directory and does
not claim that native tests were rerun on publication-only bytes.

The original remote reader launch had two timed-out acknowledgements and no
observed execution. A successful create-only write, followed by independent
file-info verification, established the 905-byte fence at that driver's first
exclusive `open('xb')` gate. Its SHA-256 is
`b9c1336fe41972e9cba1f0e8bfeb1ea5072347ec82a2650bad249ddcc934cbfe`.
This verified reader fence is distinct from the unobserved native fence above.
The old reader launch remains UNKNOWN; a late original cannot pass that first
gate. No remote reader supervisor exit is inferred.

The partial RPC download retained 36 verified chunks, 13 explicit timeout
observations and eight read requests whose completion was unknown when their
controller stopped. A subsequent normal Git fetch and blob read recovered the
complete 4,657,951-byte native archive from the intermediate commit. Its full
SHA-256 matches the independently retained original descriptor, and all 36
saved chunks match the corresponding byte ranges. The local checkout stayed
at the frozen implementation; no checkout or new native run occurred.
The [Git readback receipt](publication/intermediate-git-readback.json) records
the exact publication commit and blob. The one local reader recovery is
reported separately above; its runtime, command records, source and input
checks do not become authenticated host or physical-cost proofs.

A [source-head hosted CI snapshot](ci/source-d23488c5-snapshot.json) records 21
workflows: 11 success, 3 failure, 6 in progress and 1 queued. This metadata-only
snapshot is not whole-CI success and does not establish causes for the QROM or
native-campaign failures. A later
[source-head diagnosis](ci/source-head-diagnosis-summary.json), observed at
2026-11-12 01:13:56 UTC, records 13 success, 5 failure, 2 in progress and 1 queued.
Its [complete retained logs and comparison records](ci/source-head-diagnosis.tar.gz)
support the following narrower findings:

| Failed workflow | Observed refusal | Attribution supported by retained evidence |
| --- | --- | --- |
| QROM closure | Fixed source identity mismatch for `store.rs` | The same refusal occurs at exact parent `249f`; relevant checker, input and workflow bytes are unchanged. |
| QROM implementation | Verifier input is 11,172 bytes against a fixed 9,233-byte upper bound | The same refusal occurs at the exact parent, with unchanged checker, contract, input and workflow bytes. |
| Native public campaign | Original three campaigns return 101; finite experiment criteria remain false | Original source/build guards pass. Baseline and attack phase observations are preserved; runtime cause and patch causation remain undetermined. |
| W1 work-security | Fixed 8-count gates reject 13 passing tests; fixed 6-count gates reject 11 passing tests; fresh-service targets also fail | The two specific count refusals also occur at the parent. Fresh-service deadline/confirmation-target failures remain separate dynamic observations. |
| CodeQL export | Analyses/checks do not complete and stabilize before the deadline | The parent has the same wait error. This incomplete export is not a report of a particular code vulnerability. |

The diagnosis retains 28 complete connector-decoded job logs, selected original
native command streams and manifests, artifact identities, and 20 file-identity
comparisons. It did not rerun any workflow, change a gate, or waive a failure.
Later publication-head workflows have their own identities and must be read
separately; no whole-CI success is asserted.

## Why the release gate stays closed

Bailey–Sattath's [variable-difficulty analysis](https://arxiv.org/abs/2403.08023)
explains the idealized mismatch between linear work credit and square-root
quantum query cost as difficulty increases. Its oracle/cost assumptions are not
a measured W1 device implementation or a native profitability bound. Applying
a strictly increasing square root to total chainwork preserves real-valued
branch order; integer rounding can create ties. Reweighting every block changes
classical reward-to-cost calibration and needs a new joint proof.

The existing joint qualification contract still needs: valid lower cost
envelopes for every legal classical and quantum implementation; a resource and
clock model including setup, caches, withheld results and retained quantum
state; joint bounds for adversarial ready credit and honest progress under
actual delivery/participation assumptions; a native-to-model reduction; and
CP/CG/CQ plus stopping-time confirmation and lifetime composition. These are
proof obligations, not missing test-count thresholds. The original confirmation
rule's depth and required-work conditions remain unchanged.

The sole development plan and installed joint qualification contract retain the
same unresolved obligations. This delivery does not merge the separate #893,
#900 or #907 implementation candidates, activate production, or assert that
unrelated hosted CI lanes are green.

## Retained packet and byte identities

[SHA256SUMS](SHA256SUMS) covers every delivered file except itself. The primary
raw archives retain the original observations, rather than substituting their
summaries:

| Archive | Retained content |
| --- | --- |
| [Native execution](native/native-run-d23488c5-v1.tar.gz) | Four fresh native reports and packet sets, full native command logs, source identities, locked graphs and the executed binary identity. |
| [Independent readers](readers/four-profile-recovery-v2.tar.gz) | Complete local reader/suite streams and outcomes, unchanged input/source checks, both driver versions and the original unknown remote launch plus verified fence and transport recovery. |
| [Risk binding reproduction](risk/typed-binding-reproduction.tar.gz) | Old reader and mutated banks, original accepted aliases/refusals, missing-directory failure, and the historical fixture with its restoration record. |
| [Work-time recovery](python/work-time-recovery.tar.gz) | All three attempts, unsuccessful probes, historical-object recovery records and original pack payloads, plus the successful 106+13 run and campaign outputs. |
| [Hosted CI diagnosis](ci/source-head-diagnosis.tar.gz) | Complete retrieved job logs, selected raw experiment records, upstream artifact identities and exact parent/source comparisons. |
| [Native runtime recovery](recovery/runtime-recovery-v1.tar.gz) | Original format/native requests, timeout responses and runner bytes; unknown states remain explicit. |
| [Initial publication](publication/publication-d23488c5-v1.tar.gz) | Original normal push and draft-PR creation command records. |
| [Intermediate publication recovery](publication/native-intermediate-publication-recovery-v1.tar.gz) | Successful evidence push, the failed GraphQL PR edit and separately successful REST repair with exact readback. |

The native archive SHA-256 is
`6c33da56842862608e365acb7c69d72175538556a2a76b74254f7b0357de9c81`;
the reader recovery archive SHA-256 is
`3762a24d24818b0113544d0e96c96cb34897de7abbb37b8701b18c4a076cbe5f`.
The native archive records the executed DAA test binary as
`c6c95546c4a8d70178c39b04ec3b6cb7349285fa6e777cdaad0729d9fa5e142e`.
This is identity metadata for a 233,816,096-byte executable; execution
provenance is limited to the retained host records.
