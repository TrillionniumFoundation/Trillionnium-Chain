# SP27-02 coordinator handoff — 2026-11-12 UTC

This is a task-local handoff. The shared conference catalog, plans and
coordination directories remain coordinator-owned and were not updated here.

## Current scientific decision

**The attack mechanism remains UNKNOWN.** The original fixed-order pair is
retained as baseline 1/1, pressure 0/1. A new balanced, minimum-dose stage series
qualifies its own healthy controls and stage interventions, and all its business
operations confirm. It does not reproduce the old sustained-pressure failure.
Neither result alone establishes a unique cause or a general liveness guarantee.

| Batch | Executed source | Original identity | Observed business result |
| --- | --- | --- | --- |
| Original fixed-order pair | `8ebcdb01016946a131f9067ebe1ace39b9c4f260` | run `43052900246`; job `130634539770`; artifact `13871459353` | Baseline 1/1, 16-worker closed-loop pressure 0/1; original failure preserved |
| First repeated health | `0bc51795a978494af1b4659712ecf78c290c1a88` | run `43125548321`; job `130876572920`; artifact `13902664465` | 3/3 strict confirmations; no pressure |
| Separate same-source health | `ff35430d27eea56dd803e05aa6d48573e37ed4c9` | run `43131129775`; job `130895251212`; artifact `13907325153` | 3/3 strict confirmations; no pressure |
| Balanced stage series | `ff35430d27eea56dd803e05aa6d48573e37ed4c9` | run `43131129970`; job `130895252279`; artifact `13906427974` | 5/5 healthy/sentinel phases and each of four pressure arms 2/2; 13/13 attempted/invoked/completed |

The batches have their own original identities and Host records. Do not pool
them into one success fraction or infer a source-induced speedup. The new series
uses `H H H / T E L V / H / V L E T / H`, fresh state per phase and 16 single calls
per pressure phase at a planned 100-ms offset. The old pressure phase used 386
closed-loop calls and pressure-dependent business release. Those interventions
have different exposure and release rules.

## Findings that are supported or refuted

1. **Supported:** the original pair's native deadline failure and the new
   series' strict confirmations are verified against original ZIPs, retained
   executables, executed Git sources and Host readbacks. No endpoint or success
   record was reconstructed from a chat conclusion.
2. **Refuted:** all 370 original `WORK:Transcript` responses were full native
   replays. Actual flags and source paths show 52 full replays and 318 exact
   rejection-cache returns. A legacy full-work span is not a replay counter.
3. **Supported:** the new stage interventions actually reached the intended
   stages for all 16 body-checked inputs in each pressure phase. Late and valid
   each had 16 full replays per phase and no cached rejection. Transport and
   early Work spans were explicitly unstarted; missing CPU fields remain null.
4. **Unknown:** how much of the old confirmation failure is caused by transcript
   verification, arrival/queue effects, startup/order, cancellation or shared
   client/receiver compute. The old meter has zero recorded mutation-CPU
   refusals and nonzero final credit, so exhaustion is not an observed cause.
5. **Unknown:** a general attack effect or population latency difference.
   The new series has only two observations per arm; actual arrival profiles
   differ, and valid inputs also exercise state, admission, fork choice and
   storage. Descriptive pair differences are not causal estimates.

Source reasoning, exact counts and primary receipts are in
[SOURCE_AND_MECHANISM.md](SOURCE_AND_MECHANISM.md) and the
[complete descriptive result](batches/ci-43131129970/descriptive_statistics_v1/DESCRIPTIVE_RESULT.md).

## Measurement contract and actual consumption

The historical V1 reader is retained byte for byte. V2 requires endpoint `< T`
and the native final gate. T−1, T and T+1 are covered, including endpoint below T
with native gate false. The six original historical ZIPs were actually reread:
35 phases, 93 planned operations, 13 confirmed, 32 observed/unconfirmed and 48
unstarted. No exact-T endpoint or below-T/false-gate positive case was found;
the verified historical corpus has zero changed credited counts.

| Contract or actual output | SHA-256 |
| --- | --- |
| Existing strict reader/06 contract freeze | `fd063440ee6d10ccaaf28ca70a0fc371e1a1a77cd67ac52f95f1cef885863920` |
| New strata analysis contract freeze | `fa048f1c0f92b421c34738bfee05e88d0923aed0ab5f3787ef6a411c2cb8e2f3` |
| Actual strata consumer receipt | `51e0e351a93f3fe70fef3e809c0e2204a1eb7dcfbe5c5fd9d7c3e03f8e66c8f1` |
| Actual unchanged SP27-06 analyzer summary | `62608533f1d4ae0da36f0bc3b6c8be327dda2991c63ccbb6f6bdc76074c97a70` |
| Current measurement/root collaboration ACK | `940f83428728cda79e0647446b569d300cf6a29086bedc8cc365e8b5020c6067` |

Root independently invoked the frozen stage audit against the same verified
input directory and reproduced all 13 derived files byte for byte. The current
measurement agent actually reread that result and both new root receipts.
This is a real current collaboration acknowledgment. The historical Agent 06
author and original coordinator acknowledgments remain **NOT_OBSERVED**.

## Preservation, resources and reproducibility

Every batch contains exact consecutive slices of its original platform ZIP,
an ordered parts manifest, whole-archive SHA-256 and create-only reconstruction
commands. Derived analysis is separate from original records. Platform archive
hashes, member hashes, native binary hashes, source/tree declarations, run/job
identities, Host boots and permissions are preserved. The source collector uses
create-new records, retains incomplete/unstarted positions and stops on a failed
health/sentinel or integrity gate. Failed records have not been replaced.

The original native Host checker, fixed resource configuration and historical
pair/helper are byte-preserved; see
[SOURCE_PRESERVATION.json](SOURCE_PRESERVATION.json). The native window remains
4,000,000,000 ns; CPU is 25,000/100,000, memory 2 GiB, swap zero, tasks 256,
unprivileged UID/GID, no-new-privileges and zero capability bounding mask.
The cooperative exclusive parent lease is verified. Dedicated physical CPUs,
an exclusive cpuset and continuous absence of unrelated physical host load
remain **NOT_VERIFIED**. No relaxation supplies success credit.

The old local diagnostic draft, patch and original
`PUBLIC_HOST_KERNEL_PARENT` failure remain **NOT_VERIFIED**. The native code has
multiple predicates for that error; it is not evidence of a particular missing
directory, errno or permission failure. An extended bounded search of all newly
recovered original text batches also found no matching original; its scope is
recorded in [the search extension](validation/PREVIOUS_FAILURE_SEARCH_EXTENSION.json).

The [README](README.md) provides native execution and read-only reanalysis
commands. Source checks, Rust build/units/Clippy, reader and Host negative
controls are retained in [the actual validation ledger](validation/ff354-source/MANIFEST.json).
Scientific qualification remains separate from CI process exit or build success.

## Main manuscript and the full cost result

The integrated English manuscript is in the private paper workspace
`papers/verification_cost_liveness/` in
[Papers draft PR 9](https://github.com/TrillionniumFoundation/hepta-papers/pull/9).
It includes actual SP27-06 consumption and the complete Agent 01 source/raw/model
bundle. The Agent 01 history contains 384 histories, 480 processes, 3,072 sessions
and 28,792 attempts, including misses and exhausted sessions. The 18,380 attempts
in exhausted sessions are 63.837% of attempts; this is not a CPU fraction. The
full lifecycle expression retains preparation, failed search, drop/restart and
verification costs. No successful-only shortcut or positive credit/reward claim
is substituted for that result.

The prior-work comparison distinguishes Broken Metre, DoSVER/DoSDET, Speculative
DoS, ThreadNeck and Denial of Sequencing. Metering mismatch, costly invalid input
and thread bottlenecks are established prior work. A distinct claim about native
receiver lifecycle and independent confirmation remains conditional on a
qualified causal result; the present manuscript states that boundary.

## Actual registration status

**NOT_VERIFIED.** No actual paper ID, registration receipt or authenticated frozen
submission metadata was recovered. A current read-only cloud-browser attempt
failed twice in its runtime before any submission dashboard could be observed.
This does not imply the paper is unregistered or the site is unavailable.

The [official CFP](https://sp2027.ieee-security.org/cfpapers.html), read again on
2026-11-12, specifies Cycle 2 abstract registration on November 10 AoE and paper
submission on November 17 AoE: respectively **2026-11-11 11:59:59 UTC** and
**2026-11-18 11:59:59 UTC**. Title, abstract and authors freeze at the abstract
deadline. Internal source/PDF edits are not submission-site edits. No registration
or manuscript upload was performed. The coordinator must bind an actual paper
ID and its frozen metadata before treating this draft as an existing submission.

## Branch delivery

- [Chain draft PR 919](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/919)
  targets `docs/chain-sp2027`; work is isolated on
  `test/chain-sp27-02-native-mechanism-20261111-e815`.
- [Papers draft PR 9](https://github.com/TrillionniumFoundation/hepta-papers/pull/9)
  targets `conference/sp2027`; work is isolated on
  `research/sp27-02-native-mechanism-20261111-e8159a5f`.
- The exact executed native source is `ff35430d27eea56dd803e05aa6d48573e37ed4c9`.
  A later evidence-only branch commit does not relabel that execution source.
  Native workflow path filters do not rerun pressure for evidence-only changes.
- Publication uses the authorized ProfHepta HeptaRuntime channel, fast-forward
  task branches and draft PRs. No merge, self-approval, protected-branch bypass,
  release activation or shared coordinator update is part of this handoff.
