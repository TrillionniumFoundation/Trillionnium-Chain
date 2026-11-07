# R17 response-signing reservation: final retained evidence

## Decision

**HOLD / NO-GO for original service qualification, release and activation.**
R17 reserves an authenticated request's response-signing principal and worker
slot before native dispatch. It partitions the existing authentication budget;
it does not add Host capacity or promise that every committed submission can
deliver an ACK. Native commit facts remain authoritative when a response cannot
be signed, encoded or delivered. This addresses a concrete resource-ownership
gap, not the cryptographic validity of a forged W1 transcript.

The frozen final candidate is `40194538c7d74d860f9f0460d9f5f886df13281c`, tree
`977db7f413da494051d84ed3eecd1eb0522dfd12`. This ordinary merge has parents
`2f66491d06453d9b5c9a1783f9441fb1d07619a3` and the reviewed live integration
target `04bbc81e4aad9b29fef29385d3262297e2cb17df`. All tracked paths outside
documentation and evidence, including code and Cargo files, are byte-identical
to 2f. The merge preserves all 173 upstream evidence and specification blobs
unchanged. The three test-repair commits remain in its history and change
retained test fixtures, one Legacy test owner scope, source pins and the sole
development plan; production behavior after f97 is unchanged.

The integration change is tracked in [draft PR 780](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/780).
The normal source push was read back through Git and the GitHub PR API with
`40194538c7d74d860f9f0460d9f5f886df13281c` as the remote head, under actor
`ProfHepta`. [The publication receipt](validation/final-source-publication-attempt-3/published.json)
retains that observation. PR780 targets `fix/chain-six-axis-performance-20261103` at the reviewed live base
`04bbc81e4aad9b29fef29385d3262297e2cb17df`.
This separate evidence branch preserves full failed observations without
repeatedly changing the PR source merely to archive diagnostic files.

## What the code guarantees within its scope

- Admission order remains bounded ingress, receiver-local Cookie, budgeted
  authentication, authenticated account authorization, then native work/state.
- The original classical authentication budget supplies the response's
  100 ms principal and one of its two worker slots. The unique reservation
  survives cancellation until its actual owner settles or retires.
- A held classical reservation can reach the signer even when later ordinary
  authentication work exhausted free credit. It creates no new attempt, byte,
  slot or CPU allowance, and does not retry the signature.
- A reservation that was not used can release its healthy CPU principal/slot
  after cleanup. Attempts and bytes are not refunded. Unknown accounting or an
  unwinding owner retains the original fence.
- The PQ path retains its original 8,192 attempts, 64 MiB input and 2 CPU-second
  lifetime ceiling. A known overrun of the original PQ CPU lifetime cap still
  refuses a held signer.
  The current PQ transport is Head/History only; this is not a PQ Submit claim.
- Busy, timeout and unknown are service outcomes. They do not establish
  consensus invalidity. Receiver binding remains local admission authority;
  the transferable consensus proof and task-bound business consumer retain
  their separate scopes.

## Exact source validation

The exact final composition `40194538c7d74d860f9f0460d9f5f886df13281c`
passed its complete retained Public V3 selector: **249 passed, zero failed and
one existing ignored benchmark out of 250**. All seven Legacy readback controls
passed. Strict workspace/all-target/all-feature Clippy with `-D warnings`, all
five original negative source/CI/policy/readback controls and three locked
dependency graphs passed. The actual selector executions took 50.644 seconds
and 199.778 seconds respectively; compilation and Clippy reused the valid
native cache for the byte-identical code. Source identity and both lockfile
hashes remained unchanged. These are completed component results for 401;
they do not grant original fixed-Host service qualification.

The earlier candidate `2f66491d06453d9b5c9a1783f9441fb1d07619a3`, tree
`0c39dd48d86a71d8269f77fd23f193c4e99fa7a4`, passed its complete retained Public
V3 selector: **249 passed, zero failed and one existing ignored benchmark out of
250**. All seven Legacy readback controls passed. Strict workspace, all-target,
all-feature Clippy with `-D warnings` passed, as did the original negative
source/CI/policy/readback controls and all three locked dependency graphs.
Source identity and both lockfile hashes remained unchanged in that execution.
These are retained historical results for 2f. The repository's committed native
test profile and genuine PQ provider were preserved; desktop component results
remain separate from original fixed-Host qualification.

The retained Public V3 selector contains 250 tests. An existing ignored test
remains ignored; it is not reclassified as a pass. Its name is
`pq_caller_authentication_complete_cost`, a paired-cost benchmark requiring a
fresh output directory. [The final 401 case readback](validation/native-final-composition/original-case-readback.json)
retains that reason and all four formerly failing queue-case results, bound to
the original final-run stdout digest. [The historical 2f case readback](validation/native-retained-repair-attempt-3/original-case-readback.json)
remains separately retained.
The final patch against the
complete 436 module preserves all 843 existing assertion calls, 21 existing
wait calls and 174 Duration expressions. The three eight-request fixtures
authenticate their original grants first, observe two actual worker reservations,
then two occupied channel slots, before sending the final four pending bodies.
Original queue/worker bounds, cancellation checks and deadlines are retained.
Failure-only diagnostics leave the original helper assert outside their branch,
executing at its original point on every loop. The earlier failure had no metrics
snapshot: a peak of
six was a source-supported scheduling possibility, never an observed counter.

Completed final-composition validation records:

- [401 native selector, Legacy tests and strict Clippy](validation/native-final-composition/summary.json)
- [401 negative source, CI contract, policy and readback controls](validation/source-final-composition/summary.json)
- [401 locked default, all-feature and fuzz graphs](validation/graphs-final-composition/summary.json)

Retained earlier validation and fixture history:

- [2f native selector: 249 passed, zero failed, one ignored; Legacy tests and strict Clippy](validation/native-retained-repair-attempt-3/summary.json)
- [2f negative source, CI contract, policy and readback controls](validation/source-retained-repair-attempt-3/summary.json)
- [2f locked default, all-feature and fuzz graphs](validation/graphs-retained-repair-attempt-3/summary.json)
- [First repair: 246 passed, 3 failed, 1 ignored](validation/native-retained-repair-attempt-1/summary.json)
- [Second repair: 246 passed, 3 failed, 1 ignored](validation/native-retained-repair-attempt-2/summary.json)
- [Final fixture patch](validation/retained-regression-fixes/queue-fill-channel-before-pending.patch)

The full f97 GitHub node library observation was 1,201 passed, four failed and
31 ignored. Its four queue-fixture failures and the Legacy Clippy failure are
retained. The targeted replacement tests do not relabel that full run or prove
that the entire workspace passed. Earlier native, driver-path, tool-timeout,
source-control and historical-artifact retrieval failures also remain in the
manifest. Desktop validation is not original fixed-Host acceptance.

## Original fixed-Host service result

The original 0.25 CPU, 2 GiB memory, zero swap, 256 PID, zero CPU burst and
4-second / 16-hostile contract was preserved. The fresh f97 head and
prospective-merge artifacts have actual before/after cgroup identities, limits,
unit digests and privilege captures, with no Host read errors.

Both fresh pressure samples acknowledged all seven honest Submit requests,
but completed zero of one required independent six-depth confirmation. Their
corresponding baselines completed one of one. Head pressure completed three
History page imports before the fourth import reached the original deadline;
merge pressure completed one before the second did. The successful History
network replies (4/4 head and 2/2 merge) do not mean the independent native
imports completed. Both retained fresh samples report `no_attack_accepted=true`.
Their failed confirmation targets remain service outcomes.

Original and fresh observations coexist in the two complete archives:
[head artifact](github-artifacts/13580342341/metadata.json) and
[prospective-merge artifact](github-artifacts/13579839179/metadata.json).
The historical local readiness refusal remains in the earlier retained evidence;
it is not the status of these actual GitHub executions.

## Three complete original campaigns

These are retained observations of source `f97c3bc5aedebcf80b2a95648c6291525e0b0a9c`,
tree `fb08f394499cc5847d0e47986bfc97ea2767fed4`. The newly started 401 CI must
be read from its own source-bound receipts; it is not assigned these outcomes.

All three original campaigns actually executed all 0/24/24 phases, with the
original 1,024 signed seed transfers, four seed blocks, 21 planned business blocks per phase,
30-second phase deadlines and three planned confirmation rounds per phase.
Each round was scheduled at 1, 5 or 9 seconds against the same absolute phase
deadline. All three processes returned 101; none hit its 600-second outer
controller timeout. Reports were generated and validated; startup-error lists
and report-validation errors were empty.

| Phase across three campaigns | Planned confirmations | Timely success | Observed, not confirmed in time | Unobserved |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 9 | 3 | 3 | 3 |
| From-zero hostile | 9 | 0 | 3 | 6 |
| Late-product hostile | 9 | 0 | 3 | 6 |
| Total | 27 | 3 | 9 | 15 |

The completion fraction is **3/27 (11.11%)**, not 3/12 observed rounds.
All nine phase criteria failed. The three successes independently meet depth
six and positive required work delta. The nine failed confirmation observations
are null; no late success is inferred. Finite p95/p99/max for all 27 offered
tasks remain unavailable. For only the three successful baseline samples,
scheduled-latency p95/p99/max is 22.703333176 seconds; this conditional n=3
statistic is not the service's offered-population tail.

Honest Submit ACKs were 84/84. Of 65 History calls, 64 had successful network
responses; native import accepted 56 and rejected eight on service deadlines,
with one call having no import-stage observation. These stages are not interchangeable.

All six hostile phases had 24 requested and ready actors. Across them the
clients made 14,064 calls: 13,920 observed WORK refusals and 144 call errors that
returned after the original window, with no attacker Submit ACK. The receiver recorded 13,922 full-work
refusals, 140 unknown outcomes and zero accepted hostile work. These stage
counters do not count uncached transcript replays. Client/server
denominators differ and are retained separately.

The 36 public-phase captures and six controller resource captures independently
confirm nine phases' actual public parent placement and original limits.
All 144 hostile processes were in the
separate 4 CPU / 16 GiB / Nice 10 controller cgroup. Controller resources are not
added to the receiver's allowance. These capture-time observations do not claim
exclusive physical hardware or continuous limit monitoring.

All 3,967 retained budget samples reported no depletion. The minimum sampled
stored credit was 1,782,441,336 ns against the original 100,000,000 ns start
reserve. Maximum observed sample gaps were about 100.126 ms in baseline and
149.424 ms under hostile work; the result does not prove that every instant was
observed. All 520 projected-start-ineligible samples had two live owners, so
slot saturation is not reclassified as depleted credit. Distinct meter, flow
and freshness reads are not treated as one atomic snapshot. The 24 meter/flow
and 370 flow/freshness differences do not invalidate the independently checked
internal flow identities. The [source-bound snapshot audit](audits/budget-snapshot-audit.json.gz)
checks the separate lock acquisitions, same-lock freshness projection and all
retained flow equations.

The original criterion requiring real paid depletion was therefore not
observed. Baseline itself failed, so the available evidence does not attribute
the result solely to attack pressure, SQL, fairness mechanisms or R17.

Sources: [original campaign result](github-artifacts/13580931898/readable/results.json),
[complete archive metadata](github-artifacts/13580931898/metadata.json),
[independent audit](audits/campaign-final-audit.json.gz), and
[original Host captures](audits/original-host-receipts.json).

## Full 4,105-block History: four original lanes failed

All four original History lanes compiled and executed the same retained named
test, which started and returned 101 in each lane.
They ran under the verified original public Host limits. Source and binary
identity remained stable before/after execution. The head was f97 and the
prospective merge was `6cd7b65b6c766e75c9fcaef8983a537922569be4`; their complete
source trees were identical. These are actual failures, not unexecuted lanes.
Headers advance by logical ten-second intervals; these cases do not establish
a real-time long-duration qualification.

| Architecture / source | Successful import returns before failure | Failure |
| --- | ---: | --- |
| x64 head | 4,028 | Original 1,800-second server lifetime expired; next History RPC was connection-refused |
| x64 prospective merge | 2,792 | Same original server-lifetime boundary and RPC refusal |
| ARM head | 4,104 | Final advertised-complete page's import hit the original approximately 30-second request deadline |
| ARM prospective merge | 4,104 | Same final import-expression deadline |

The ARM servers had not reached their lifetime; they stopped on cleanup after
the import failure. Reorganization and SQL termination observations show real
work occurred, but durable-committed-block and activation-cursor observations
remain null. Successful import-return counts must not be called durable
activation. Full synchronization, cold reopening and corrupt-index refusal did
not complete as a qualified sequence. Host OOM counters were zero; whole-parent
CPU and throttling cannot be assigned to an individual History stage.

The four complete ZIPs include all 4,105 packet files and native databases,
with original GitHub digest verification. The first generic extractor refused
4,140 entries against its 4,096-entry bound after download verification. The
subsequent reader extracted only 30 bounded text files per archive. No test
was retried or made successful by that evidence-reader correction.

Sources: [independent History audit](audits/history-final-audit.json.gz),
[x64 head](github-artifacts/13581963076/readable/history-native/manifest.json),
[ARM head](github-artifacts/13581768766/readable/history-native/manifest.json),
[x64 merge](github-artifacts/13581848094/readable/history-native/manifest.json),
[ARM merge](github-artifacts/13582163092/readable/history-native/manifest.json).

## Other gates remain distinct

| Gate | Current evidence and disposition |
| --- | --- |
| Native State full capacity, refund and pending reorganization recovery | All four original x64/ARM head/merge lanes passed the exact retained ignored test. This is not the PN1 identity-capacity/churn supplement. |
| PN1 live identity capacity/churn supplement | Not qualified. It still needs its own original finite 4,097-identity workload, real capacity occupancy, churn/replay controls, honest completion and depletion overlap. |
| Independent WAN | Not qualified. Same-host processes and hosted CI do not supply independent operators, failure domains or the original long-duration workload. |
| Retained historical pressure artifact | The referenced artifact 11531476198 returned 404 and its run listed no artifacts. The retrieval gate failed; expiration/deletion/authorization cause was not established. |
| Anonymous fairness | Not established by Cookie binding, finite ACK success or sampled budget availability. |
| Effective-work lower bound and single-node economics | Not established. Complete economic recording is not a break-even or hardness qualification. |

Original GitHub runs: [priority gates](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42388392598),
[three campaigns](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42388392619),
[W1 observations](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42388392549),
[full baseline](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42388392583).

The source push triggered a new, separately identified CI set for 401. At the
retained 2026-11-07 18:35:29 UTC [initial snapshot](validation/ci-401-final-source-initial/summary.json),
all 16 workflows were in progress, including the new
[priority gates](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401831787),
[campaign](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401832002),
[W1 observations](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401831771)
and [baseline](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42401831625).
That snapshot grants no new CI qualification and does not change the retained
f97 results above.

## Integrity and reproduction

[qualification-summary.json](qualification-summary.json) records source identity,
completed component checks and the distinct failed or unqualified service gates.
[driver-outcomes.json](driver-outcomes.json) and
[driver-outcomes-final.json](driver-outcomes-final.json) retain earlier failed
publication/readback attempts and their later recovery without changing the
original results. Whole-tree whitespace diagnostics on upstream raw process
streams remain recorded; those original bytes were not reformatted. Authored
source and document whitespace was checked separately.

[files-manifest.json](files-manifest.json) records every retained source path,
original byte length and SHA256, published path, encoding, stored length and
stored SHA256. Large text compressed by this publication is losslessly
gzip-compressed with timestamps fixed to zero. Original GitHub ZIPs are retained unchanged, each alongside its
API metadata. The raw archives are primary evidence; readbacks and independent
audits are secondary interpretations with explicit scopes and limitations.

No source-integrity check, file digest, test fixture repair or artifact retention
grants deployment, consensus activation, independent adoption or release.
