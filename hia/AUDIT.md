# Whole-tree inventory and HIA migration audit

## Work toolchain prerequisite and actual bd620 component results — 2026-11-17 UTC

Both push run 44041831642 and PR run 44041858435 actually completed the
general, State-root and independent component-consumer jobs successfully.
Root read all three push ZIPs and every member, then ran the public consumer
against the exact bd620/tree8a273 source. Its complete 383-test result
(376 general, seven State-root, zero skips) exactly matched the hosted report.
This is evidence readback; it does not rerun the runtime or revalidate the
original Rust compiler-event chain.

Push Work job 133897989699 failed before native execution: 64 mandatory source
controls passed and the actual compiler/std identity control errored. Original,
qualification and readback were skipped. The PR Work source-control failure
and full log remain separately preserved. These failures are not promoted.

Only native and original job prerequisites change: install locked Rust 1.95.0
plus rust-src, select its actual bin directory through GITHUB_PATH, and set
RUSTUP_TOOLCHAIN. Both later evidence-only stages are unchanged. Local actual
1.99.1 negative control reproduced the failure; the explicitly selected 1.95
compiler passed all 65 controls with zero skips. The old hosted default version
was not captured and is not inferred from that local negative control.

The [complete follow-up record](qualification/work-owner-toolchain-ci.json)
binds the full diagnosis, raw controls, component artifacts and exact patch.
All 46 jobs retain 20-minute deadlines, all 36 HIA bootstrap gates remain, and
the 133 native /six reader closures are unchanged. Fresh four-stage hosted
qualification on the successor remains required. All nine whole-project
gates remain OPEN, with zero of 26 Rust packages retired.

## Complete Work/Host evidence and bounded CI stages — 2026-11-17 UTC

Parent is `c3901ff19c26815205d9cdd6975fc24ecc51ae88`. The inventory remains
**41 kernels /20 foundations /119 HIA files**, with all 26 Rust packages retained,
zero retirements and nine whole-project gates OPEN. This candidate has
**46 jobs /36 native bootstrap gates**, each still limited to 20 minutes.

### Actual findings and repairs

The PR component job in [run 44019959997](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44019959997)
was cancelled at its actual 20-minute limit: 339 printed successful test lines
did not constitute a completed suite. The run ended with 41 successes and one
cancellation. The separate [push run 44019939486](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44019939486)
completed 42/42 jobs; that result does not replace the PR cancellation.

Full discovery now assigns all 383 tests to disjoint general (376) and State
root (7) jobs. An independent consumer requires complete started/completed test
rosters, zero skips, both actual successful predecessors, exact head/run/attempt,
the consumer's actual Git tree, all original-adapter results and all six raw
artifact files. No test or deadline was removed. The first private consumer
missed comparison with its own tree; an actual synthetic helper counterexample
and the corrected negative control remain recorded. This was a helper-level
finding, not an observed hosted or runtime exploit.

The old foundation helper separately accepted eleven synthetic negative
controls: floating counts, boolean/floating attempts, nonfinite JSON constants,
overflowing numeric literals and floating archive/source byte counts. Exact
recursive JSON comparison, finite-number parsing and strict member metadata now
reject those cases. Thirty-three Foundation/Execution/Genesis controls and two
actual optimized-entry refusals passed. An initial validation driver used the
wrong cwd and failed one module launch; the corrected driver ran the same full
roster. The observed failure remains distinct from runtime behavior.

### Complete new Work/Host development qualification

The frozen 133-input source
`ded1230a8810c345bd705070045228b4b72078f35f007747351aa5a01c19908c`
actually reran all native histories and the original implementation. Its 175
primitive controls now retain 9,489 calls, 538 buffers, 7,800 full snapshots and
6,010,134,406 logical captured bytes. Native execution includes 61 histories,
27,843 progress records, three traces, 27 trace controls, 14 signal controls and
18 CLOCK faults. Actual original execution includes 57 histories, 44 retained
tests, two CLOCK positives and 18 controlled faults, with 20 raw-reader controls.
Normal vDSO fault behavior is not inferred from the private fault adapter.

Two coherent c248 public-reader false accepts remain preserved. The repaired
source actually passed one positive and fourteen negative full public bundle
controls. Full private review/pack took 352.407 seconds and independent complete
readback took 240.630 seconds. Their status is PRIVATE/NOT_BOUND; neither is a
hosted four-job qualification. The eight HIA inputs and full 133-input graph
match this integrated candidate. The common foundation helper changes only the
separate CI-reader closure, to
`106c29eef6b8a3264ddf0bf6957a83b793e106892b6e7d6c4d2e7be71beea4ca`.
The integrated original graph and exact committed CI still require execution.

Native, original, complete qualification/pack and independent readback are now
four dependent jobs. Their complete predecessor packages retain the actual
original executable, sources and raw evidence. Observed native plus original
development time was 1,171.858 seconds before bootstrap and packaging, so this
separation preserves the 1,200-second job limit. Hosted stage times remain
unobserved for this candidate.

### Readback, current evidence and cleanup

Root independently read all nine c390 Batch/Prefix packages, M05, Application
and Work/Host, including complete original executables and source observations.
The old c390 Host scope still lacks its earlier full primitive arenas and
controlled original CLOCK comparison; new ded evidence is not grafted onto it.
Of 1,011 declared Prefix fixture methods, 936 executed and 75 remained
unexecuted paths.

The current Work/Host development view is 50,018,340 bytes in eight volumes:
20,178 content objects, 4,004 verified Git objects supplying 4,675 logical
references, and one explicitly external 574,468,200-byte original executable.
It represents all 25,677 primary members plus 194 supplements. The complete
261,160,948-byte original package remains separately retained. The final reader
uses immutable Git object semantics and root actually reread the full view and
external binary. The [history index](qualification/work-owner-development-history.json)
binds every replaced old volume and record to complete, byte-compared c390 Git
objects. No Git history was rewritten.

Ten duplicate c390 Batch/Host extraction trees were removed only after exact
whole-member comparison: 30,509 files /2,976,163,272 bytes. Original ZIPs, complete
archives, unique readback reports and failures remain. The
[root integration record](qualification/work-host-integration.json) and its
complete 1,947,276-byte observations archive retain the actual control/readback
evidence. Merged checks passed 80 groups with zero skips, 357 Bash fragments and
50 Python heredocs. Discovery inventories business tests; it does not execute them.

Production fixed-parent success, Node/Paid lifetime, original service budgets,
Some/CheckedApply, durable COMMIT and the other whole-project gates remain OPEN.
Private Node and M05 work is not claimed as part of this committed increment.

## Batch/Prefix integration and strict M05 evidence — 2026-11-17 UTC

Current parent is `876eb577dac61854c535a91ab1480f312d1d6173`.
Inventory: **41 kernels /20 native foundations /119 HIA files**.
Workflow: **42 jobs /35 independent native bootstraps**.
All 26 original packages remain, zero retirements are accepted, and nine
whole-project gates are OPEN. Older sections below retain their recorded dates.

### Reproduced findings and actual repairs

M05's old exact-876 public reader accepted four coherent changes to actual
original stdout: scalar integer to boolean, nested integer to boolean, callback
integer to float and observation-index integer to boolean. Recursive exact-type
admission now rejects all four. The frozen 26-input graph changed from
`7461a680b29d4d36a7a8b9770281eb9ead681fe7d29f4cb48a8d051592c4724b`
to `455c7e43897744cc6f22cf88f859f6f0e96d8bd6d4836e4aee379ba97b65fef7`.
Full 323 native processes /9,332 commands, actual original comparison /
153 retained tests, physical/guarded checks and final 21 source /five byte /
12 coherent-witness controls /22 actual public CLI calls reran and passed.
Three float count substitutions were separately refused by the CI summary
helper; those are not public CLI calls.

The Batch CI proposal skipped three original-only groups and still reported
PASS. Explicit transport/original scopes now require exactly six or nine
started groups, complete passing rosters and zero skips. Actual transport
passed 70 controls; each original profile passed 102. Four actual CLI scope
refusals passed. Seven new native jobs require transport scope and both
original jobs require actual original evidence.

New YAML serialization was valid but hid seven gates from the existing
bootstrap coverage reader. Literal multiline and normal indentation restored
the reader's view without changing parsed job definitions. Four guard groups
passed across 35 gates. The initial failure is retained; the guard was not weakened.

A shared Cargo incremental-cache cleanup refused a multiply linked file before
any deletion. That FAIL remains with zero deletions. Four duplicate M05 mutation
trees were removed only after each byte matched the retained baseline and
complete overlays.

### Batch/Prefix and exact source transitions

Only 42 final owner files, including 16 HIA sources, entered
[execution_batch](platform/execution_batch/README.md). Frozen 146-input source
`408d35eec10d0818ebbde4639459753c270ec7e7445156c59d4178418aa6681d`
actually ran 102 Batch methods /2,133 progress records, 186 Prefix histories /
936 executed methods /4,419 progress records, 30 physical controls and six scoped
lifecycles /69 methods /26 complete base reads. Of the 1,011 planned Prefix
fixture methods, 75 were not executed and are not passed tests. Actual original
comparison passed Batch102 plus nine retained tests and Prefix186 plus six.

Integrated native closure is 151 inputs,
`63576c082aa16d4768ab0bc461eb604ded5905e77334b4e0655123a592e7849f`.
Only the common-component map and five Work/Host inputs differ; all 60 composed
runtime inputs are byte-identical. Inventory and sole-plan pin change the original
graph. Frozen runtime PASS is not relabelled as integrated-graph execution.

The complete Batch archive is 107,152,632 bytes /
`2446b6d527a21e935be2bda8e4907feeabef28386f1ad16243deb9f05392d4ef`.
All 8,567 regular members /510,590,392 member bytes were independently reopened,
with one XZ stream, exact tar padding and full rosters. Eighteen parts were
physically reassembled. All 46,445 logical entries, 40,320 regular logical files
and previous failure objects remain. Two original executables remain externally
retained with full hashes; neither is falsely reported as embedded.

### Exact published 876 CI

[Run 44000856130](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44000856130)
completed all 33 HIA jobs. Application's 109-input source passed 328 native and
original histories, 335 transactions, 8,784 State commands, 32 physical controls,
186 integrity controls, 16 CLI refusals and eight original retained tests.
Complete new ZIP36,267,396 bytes and all raw/original observations were
independently reread. Its complete ZIP and prior c61 evidence remain in the
70,656,656-byte final Application archive.

Work/Host's producer ZIP is 247,580,107 bytes. Its inner archive contains 6,159
regular members /992,297,375 bytes, including the complete 611,199,752-byte
original executable. Full members, exact126/4368 source maps, three readers,
package, binding, consumer lineage and final job API were independently checked.
The separate hosted consumer actually performed semantic readback; local
verification did not rerun it. The final243,515,800-byte archive preserves both
producer/consumer ZIPs in39parts. Old175primitive controls still lack full raw
guard arenas; actual original controlled CLOCK1 faults remain OPEN.

[Archive manifests](qualification/ARCHIVES.md) and each component record bind
these results. Initial expired-URL HTTP403 and portable-reader path refusals
remain preserved. Refreshing a URL or separating recorded runner paths from
local extraction paths did not change a job outcome.

### Integration and continued closure

Actual integration passed89 existing CI/evidence tests, six Batch transport
groups,173Batch source controls/18CLI and four bootstrap groups. Final source
pin/inventory/structure checks are separately recorded. Default Config,
AccountPointAccess=None and workers1/2/4/8 delimit this Batch qualification.
Custom configuration, PQ/growth, Paid/Host request lifetime, authenticated block
acceptance, durable Node COMMIT, all targets and original service/research
obligations remain open. New private Node, Host CLOCK and M05 production work
is not part of this integrated source. No package or service is retired or activated.

## Work/Host integration and detached M05 repair — 2026-11-17 UTC

### Host owner, Application and typed mempool — current candidate

The current inventory is **41 kernels / 19 native foundations / 103 HIA source
files**. The same-worker Work/Host owner adds 23 final owned files, including
eight HIA sources, with two independent CI reader files. Every component has
one implementation directory. The 26 original Rust packages remain, with zero
accepted retirements and all nine whole-project gates OPEN.

| Native owner | Exact-source actual execution | Remaining integration |
| --- | --- | --- |
| [Same-worker Work/Host](platform/work_owner/README.md) | 61 native histories / 27,843 progress records, 175 primitive controls, three actual traces, 27 trace and 14 signal controls, 18 native CLOCK1 faults; 57 actual-original histories / 27,841 progress records, 56 joined workers and 44 retained original tests | Earlier request deadline, shared Paid account/checkpoint, production fixed-parent positive, actual original CLOCK1 faults, Node/batch lifetime and original service acceptance |
| [Default M06 Application](platform/execution_application/README.md) | At c61: 328 native and original histories, 335 real PNX1 transactions, 8,784 State commands and nine native processes; 32 physical controls, 181 integrity controls / 16 actual CLI refusals and eight retained original tests | Complete batch and workers, all configurations/PQ, authenticated block acceptance, expected-root checks and durable Node COMMIT |
| [Typed M05 mempool](platform/mempool_typed/README.md) | Final detached-checkout source: 323 fresh native processes / 9,332 commands and complete original comparison / 153 retained tests; 38 physical processes / 50 commands, 26 guarded calls, 18 source controls, five byte and eight coherent-witness refusals / 18 actual public CLI calls | Production PNX/signature adapters, actual Node nonce leases, persistent pool/recovery and original service budget |

Work/Host's 126-input source is
`e56d53654a6168df96cddf23c5f079f2a0ea188d45dd55d9f15f71015c823a91`.
The actual worker retains the original acquired boot/parent/limit identity and
performs every original W1 progress checkpoint against that immutable snapshot.
The verified parent FD remains live across CPU, memory and PID reads; all three
reads finish before parsing, and the FD closes before the second fresh Host check.
The main thread joins the real child before after-sampling or output. Ordinary
Host, cancellation, deadline and CLOCK panic paths retain their different error
orders. A new standalone entry cannot renew an earlier Node request budget.

The Work/Host reader previously accepted three self-consistent changes to actual
Rust stdout: domain integer to boolean, progress integer to boolean, and thread
identity integer to string. The final reader checks the complete original row
schemas and rejects all three. Its 25 development test groups, complete original
binary pack/readback, four archive negatives and actual detached native build
passed. The 175 earlier primitive guard arenas were not retained as complete
raw snapshots; this missing evidence is explicit and cannot be reconstructed
from success counts. Original controlled CLOCK faults also remain OPEN.

Typed M05's final 26-input source is
`7461a680b29d4d36a7a8b9770281eb9ead681fe7d29f4cb48a8d051592c4724b`.
Its 179,254-byte ELF remains
`c3146c28c3102c7d5b3afde6f357319bb5e09a69b9ce7e86a1d878f87e58c85c`.
At c61, the component's default development preflight rejected GitHub's exact-SHA
detached checkout before native qualification. The complete original failed CI
ZIP and raw preflight error remain retained. The explicit `--audit` option now
selects the existing read-only boundary for this checkout; default `--dev`,
canonical origin, disabled activation and workspace checks remain enforced.
Readback rejects the execution-only option. The new source genuinely reran every
native, original, physical, guarded and public control in a real detached checkout.
Earlier eight reader false accepts, compiler-path and linker failures remain
historical failures. Signature/replay/nonce traits remain explicit test adapters.

Application's executed c61 104-input source is
`05bc59407cb4b8da2bb23350a88397594418801652150019b95afc3d9ccfe2d1`.
Its fourteen-image 4,246,848-byte ELF is
`898952d546182defb65eb553966a7eebebe2b7799935b743c5fae17c24bd1a0a`.
The [exact c61 CI record](qualification/execution-application-ci.json) binds
[run 43983845998](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43983845998),
job 133706836939 and artifact 14283854229. The complete 36,198,231-byte original ZIP,
every native/physical/control stream and actual original stdout were independently
read back. Its 91,371,888-byte original binary is retained in full. Remote compiler
paths remain original CI observations; no local path or execution was fabricated.

This integration adds five Work/Host include mappings to `hia/components.json`.
The gate also binds every inspected component key, growing Application's closure
from 104 to 109 inputs. Its new source set is
`b4f1121ba5545bbdf1fccc317e9bc8be21918b1215a83518cfb7be411432bb70` and requires fresh exact-commit CI.
The previous c61 native/original result remains bound to c61. The development
original graph and every actual earlier execution also retain their own identity.
The inventory and final plan pin changes require fresh original comparisons.

The [Work/Host record](qualification/work-owner-development.json),
[M05 record](qualification/mempool-typed-development.json),
[Application development record](qualification/execution-application-development.json)
and exact c61 CI record distinguish development, hosted execution and remaining
work. The final Work/Host semantic archive is 26,328,788 bytes; its
[CI repair archive](qualification/work-owner-ci-development.tar.xz) is 4,748,140 bytes.
M05's final archive is 13,481,848 bytes, preserving 14,389 logical files and
3,993 regular payload members, including the complete original binary.
The c61 Application CI archive is 35,301,924 bytes and contains its original ZIP.
[Archive manifests and reconstruction instructions](qualification/ARCHIVES.md)
bind every volume and the complete original archive. Each volume set was actually
reassembled and compared with the original bytes. Archive storage does not run a
test again or change its qualification.

The workflow now has **33 jobs / 28 independent native bootstrap gates**.
Work/Host uses a producer followed by a separate complete-readback consumer;
both retain the original 20-minute job limit. The consumer requires a successful
binding from the exact head/run/attempt and refuses development NOT_BOUND or
PRIVATE_DEVELOPMENT_READBACK_PASS. The producer still reopens its complete package.
Fourteen actual inline admission controls passed, including the complete real
development package's refusal. The final integration's 89 source/evidence tests
passed. [CI development evidence](qualification/application-mempool-ci-development.json)
keeps this validation separate from the next committed source's hosted result.

All original resource profiles, four-second / 16-attacker acceptance conditions,
1,800-second history limits, configuration coverage and security/model obligations
remain in force. A finite owner, a storage archive or a successful HIA workflow
does not authorize old-package retirement or establish durable Node COMMIT.

### Audited predecessor 326837e

At predecessor `326837e4c5a8a6b3b99390063c08a47dc4f9d6a0`, the HIA
[push run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43938876560)
and [PR run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43939229249)
both completed all 29 jobs successfully. The ten new PaidCPU/State/Prepare
artifact ZIPs were fully hashed and independently read back. Those results
belong to that predecessor and do not qualify this candidate.

The [exact-326 failure diagnosis](qualification/ci-326-observed-failures.json)
and its [raw evidence](qualification/ci-326-observed-failures.tar.xz) retain
nine complete original ZIP identities and 9,478 members. Three before-budget
groups refused incompatible lock/dependency/test inputs before any native control.
The requested historical pressure artifact remains unavailable. Four actual
from-zero runs passed their five native tests and each confirmed one baseline
request, but their 4-second / 16-attacker pressure phases confirmed zero, with
one unconfirmed request and zero unknown outcomes. Both x64 history servers
actually exited normally at their original 1,800-second limit before the client
received RPC connection refusal. The 3,297 and 3,973 returned import calls are
not counted as durable commits; total resource-cost causality remains unresolved.

The [protocol-contract supplement](qualification/ci-326-protocol-contract-failures.json)
and [complete small raw archive](qualification/ci-326-protocol-contract-failures.tar.xz)
independently cover both lanes of run 43939229469. Each actually ran all five
native tests successfully; each baseline confirmed one request, while its
4-second / 16-worker pressure phase confirmed zero and left one unconfirmed,
with no unknown result. Business started within the pressure window. The
controller returned CONFIRMATION_TARGET failure. Preparation's
native_tests_executed=false describes its no-run build stage, and does not
describe the later execution. The head also recorded PUBLIC_REQUEST_DEADLINE;
the merge lane had no verification error. These observations do not establish
an infrastructure or Host-only cause and do not close original service gates.

## Execution owner integration and published-source findings — 2026-11-16 UTC

### Published predecessor 326837e — PaidCPU and execution foundations

The predecessor inventory was **41 kernels / 16 native foundations / 83 HIA source
files**. The 26 original Rust packages remain, with zero accepted retirements
and all nine whole-project gates OPEN. This increment adds 47 final owned
source files, including ten HIA files. Each component has one implementation
directory; authoring trees and intermediate builds stay outside the repository.

| Native owner | Actual final development execution | Boundaries still requiring integration |
| --- | --- | --- |
| [PaidCPU](platform/paid_cpu/README.md) | Six native owner histories, 83 observed budget operations, 67 arithmetic boundaries, 13 fault histories, 40 protocol controls and 10 trace refusals; actual original 83 budget calls, 67 boundaries, five scoped profiles, all 13 faults, 23 retained tests and the mandatory Linux clock positive | Complete paid request/account lifetime, general executor placement and original public-service budget |
| [State/View/Patch](platform/execution_state/README.md) | 68 native and original histories, 1,075 observations on each side, nine physical groups with 97 native calls, five retained original tests; 13 source groups / 141 controls and eight actual-bundle CLI refusals | Application commands, M06 batch/replay, mandatory transitions, fees/rewards/funds, expected-root admission and durable COMMIT |
| [Private preparation](platform/execution_prepare/README.md) | 723 native semantic cases, 52 physical controls and 52 processes, 723 actual private original comparisons and three retained tests; 13 integrity groups / 164 controls including 34 actual CLI refusals | Full batch workers and application, all configurations/PQ, block receipts and private Node admission |

PaidCPU's 58-input source set is
`9ba64e6369f2fae3c5d8ee879d2639f8993b1b0a98c9eeaab2d6ca09a744304f`.
The observed count of 83 budget operations is bound to the complete native
event streams and actual original calls; CI does not impose a scheduler-dependent
constant. The original comparison binds Rust 1.95.0, its full version output,
absolute compiler/Cargo bytes, 14 actual standard-library source files and two
compiled standard-library files. Complete fault captures bind task births,
terminal/reap state, actual executable arguments, auxiliary-vector changes,
private role markers and every raw output stream.

State's final 33-input source set is
`5b7e3afd86ca50047c4bb26eb63e7b631983d63754206458f21a0cc29af56bb8`.
The 97 physical calls include complete private journals with 53, five and two
direct calls, plus 37 process commands. The journal verifier rechecks full
65,536-byte heap observations, input/output bytes, continuity, unchanged rejected
calls, unused output tails and the two explicitly private counter injections.
Real moving `mremap` and the native response to syscall-level `ENOMEM` injection
are recorded separately from private ABI fixtures; host memory exhaustion is not claimed. Original comparison runs all 12 recorded stages with
absolute rustc/Cargo/rustdoc identities and exact production-source prefixes.

Preparation's final 47-input source set is
`77df26a897da5437f0d0ba2191558e49c615dc17966a793c241ea15e731a147b`.
The private owner performs complete legacy PNX1 validation, native SHA256 and
strict Ed25519, default installed Settings construction, attempt counting,
callback/cancellation order and Prepared lifetime handling. The actual original
comparison binds all ten stages, the selected compiler, independently retained
serde library objects and unchanged production functions with the sole test hook.
These preparation results carry no block-commit or Node admission authority.

The records and complete source-specific evidence are
[PaidCPU](qualification/paid-cpu-development.json),
[State](qualification/execution-state-development.json) and
[preparation](qualification/execution-prepare-development.json).
Their corresponding [Paid archive](qualification/paid-cpu-development.tar.xz),
[State archive](qualification/execution-state-development.tar.xz) and
[preparation archive](qualification/execution-prepare-development.tar.xz)
preserve the actual raw observations and historical failures. Exact repeated
bytes use content objects. State's 4,381 already-committed source files were
independently read from Git at `5c3d7089f24271a0ba6dbcc9d924fe505a361a3c`;
matching archive members explicitly name that commit, path, Git blob, byte count
and SHA256. The full 6,666-member source/raw archive can be reconstructed from
those existing Git blobs and the retained objects. No source or raw observation
is replaced by a summary. Original Rust test executables remain separately
retained in full during development; new hosted artifacts include the complete
independent executables.

Actual failures keep their original status. The first final State original
attempt exited 101 after stdout reported `ENOSPC`; its partial output and
zero-byte final report remain. After the original processes were confirmed
absent, the same frozen source passed all 68 histories and five retained tests
in a fresh output directory. Preparation's interrupted physical attempt retains
45 process receipts, a zero-byte report and an unavailable terminal outcome.
A fresh same-source execution subsequently passed all 52 controls. The Paid
component's earlier missing-import original failure and all earlier authoring
and comparison failures remain in their own source-specific records.

### Exact-source CI and the audited published predecessor

The workflow now contains **29 jobs and 25 independent native bootstrap gates**.
The added jobs cover PaidCPU, combined State native/physical/original execution,
preparation semantics, preparation physical controls and preparation original
comparison. Original preparation accepts only the complete native artifact from
the same commit, run and attempt. All five jobs verify every committed source
byte before and after execution, then bind raw outcomes. Failure packaging
preserves available streams and binaries while retaining special-file metadata
without opening those files. The original 20-minute job limits remain.

The integrated evidence and ownership tests passed **46 groups**. The complete
workflow passed 189 Bash fragment syntax checks, 37 Python heredoc parses, all
four bootstrap-test groups across 25 gates and duplicate-key YAML/structure
checks. The [CI development record](qualification/execution-ci-development.json)
and [full review evidence](qualification/execution-ci-development.tar.xz) retain
the 12 Paid and 11 execution-evidence boundary groups, actual recorded-fault
replays, source-specific reader checks, earlier rejected proposals and uncertain
launch observations. These development reviews do not count as new native or
hosted execution. The new committed-source workflow remains required.

Published predecessor `5c3d7089f24271a0ba6dbcc9d924fe505a361a3c` actually
completed all 24 HIA jobs in both the
[push run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43907395835)
and [PR run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43907690872).
Fourteen original GitHub ZIPs were fully hashed and independently checked:
all five Genesis native suites, actual Genesis originals and Thread CPU evidence
from both lineages. Each Genesis lineage passed 254 controls / 356 native
processes and 30 original cases / three retained tests; the Thread lineages
passed their complete 65-history native/original and physical evidence.
The [Genesis CI record](qualification/genesis-ci.json) and
[Thread CI record](qualification/thread-cpu-ci.json) bind that exact source.
These predecessor results do not qualify a later commit.

The [whole-project CI findings](qualification/whole-project-ci-findings.json)
and [priority diagnosis](qualification/priority-ci-diagnostic.json) preserve
other failures on the same published source. Both x64 history services reached
their original 1,800-second lifetime and exited normally; the next RPC was
refused before full synchronization completed. All three failed service lanes
retained `CONFIRMATION_TARGET` failures despite five successful named test exits.
The x64 no-attack baseline confirmed zero, while both ARM64 baselines confirmed
one; all three 16-worker pressure runs confirmed zero. Full Host/W1 page
observations identify a concrete implementation cost without manufacturing a
causal CPU fraction across caller threads and scoped workers. The original
0.25 CPU, 2 GiB, zero-swap, 256-PID, four-second and 16-worker conditions remain.

Next work joins the actual application commands, scoped batch workers, complete
joins and panic/cancellation order, one canonical replay, mandatory/reward/fund
semantics and private durable Node admission. Host/resource/W1 checks must run
inside the actual execution worker with fresh authority checks at every original
boundary. PQ/TLS, all targets, the model product loop, research obligations and
complete replacement of every retained package remain on the closure matrix.

## Genesis integration and second hosted Thread CPU repair — 2026-11-16 UTC

The current inventory is **41 kernels / 13 native foundations / 73 HIA source
files**. All **26 original Rust packages remain**, zero package retirements are
accepted and all **nine whole-project gates remain OPEN**.

The [Genesis owner](platform/genesis_store/README.md) constructs the complete
default Settings, genesis catalog, active selector, slot zero and seven-row
State inside the native HIA executable. It holds the private directory and
exclusive lock, writes and synchronizes the actual files, rereads their complete
contents, computes the native M06 State root and performs cold recovery before
opening the owner. The directory model remains private with cooperative flock;
continuous hostile same-UID mutation and physical power loss are not qualified.
Successor execution/admission, expected-root acceptance, arbitrary COMMIT,
reorg/replay/outbox/ACK, PQ/GSC2 and arbitrary Configs remain open.

The executed 45-input Genesis source set before final formatting is
`a0c3d62591815a2c86df1a77d243b79999f9cbe5238bca230fd15a4243dd3d8b`.
It actually passed **30 native semantic controls / 62 processes** and
**30 actual original comparisons / all three retained original tests**.
Final staged formatting removed exactly one terminal LF from each of the two
hosted Python verifier/test files. All other 43 inputs and both Python ASTs are
identical. The integrated 45-input set is
`032dacb01fc1df493017348f719f8e81eda293eef8f2542a71c3af8e4486c305`.
The actual native/original results above remain bound to the pre-format a0c3
set; final-source execution is required in the new committed-source CI.

The earlier `a0fa6c27d48779ae04a7c69cb175b92e00d714e5c443e46a49483c217b870046`
source actually passed all five native suites: 254 controls and 356 processes.
Only the registry-source verifier and its tests changed afterward; all nine
runtime artifacts remained byte-identical. The four earlier physical suites
retain their earlier source identity and are required again in current-head CI.
The [complete current record](qualification/genesis-development.json),
[current raw evidence](qualification/genesis-development.tar.xz),
[earlier native evidence](qualification/genesis-native-history.tar.xz) and
[first original failure](qualification/genesis-original-failure.tar.xz)
preserve the complete outcomes. The original source closure includes migration
and plan-pin metadata: these differ during integration, while all remaining
4,359 original inputs match. The earlier 4,361-input original execution keeps
its own identity; complete committed-source CI must execute the integrated set.

Published `535ce9865d6764de8184aab04204459f6f05001b` exposed a second real
Thread CPU controller defect in the
[push run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43895143250)
and [PR run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43895921099).
Both completed 65 semantic histories, 724 operations and 74 physical controls,
then the negative-control builder failed before its 12 mutations because it
still searched for exactly one space before `exit_group`. Original Rust did
not run in those failed jobs. The complete artifacts and job logs remain FAIL.

The repaired builder uses the already-parsed task, syscall and exact trace-line
positions for both the terminal insertion and child-exit removal. Ten integrity
groups include the full actual hosted trace, input and output; five padding
forms each reject all 12 mutations. The final 38-input set
`5fb10436e16e013927fb92437284ab999806005bd05e11b50bcb2786445d0805`
actually passed **65 native histories / 724 operations / 74 physical controls /
12 trace refusals / four signal-pairing refusals**, then **65 actual original
histories / 518 original-method calls / 36 retained tests and the mandatory
positive Linux clock test**. Native HIA, the adapter and both executable images
are unchanged. The [Thread record](qualification/thread-cpu-development.json)
and [current evidence](qualification/thread-cpu-development.tar.xz) retain the
new executions and both new hosted failures. The exact duplicate predecessor
archive is retained in immutable Git commit `535ce986`, with its path, Git blob
and SHA256 bound in the current record, rather than nested again in this archive.

The workflow now contains **24 jobs and 21 independent native bootstrap gates**.
Five independent Genesis native jobs cover semantic, crash, prefix, namespace
and corruption controls; the sixth requires the same run's complete semantic
artifact and actually executes original Rust. They retain the 20-minute job,
240-second native child and three-second cleanup limits. Every new job verifies
the complete current tracked source before and after execution; dependent
artifacts bind the same commit, run and attempt. The six new jobs use depth-one
checkouts because these checks require the full current tree and its Git blobs.
The existing history-audit job retains full history. New committed-source CI
results remain pending; these component observations do not close whole Node
or permit retirement of the retained stack.

## Prior 44b3 signal failure and e5-source repair — 2026-11-16 UTC

Published `44b3c6e622d009b6b92b270b4e1f5c82fc844b81` exposed a real
thread-qualification defect in both the [push workflow](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43884564137)
and [PR workflow](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43884851140).
Both completed 65 semantic histories, then failed in the first physical signal
control. The real SIGUSR1 and rt_sigreturn(-EINTR) were present; the live wait
expected one space after the TID while hosted strace used two. Original Rust
was not run in either failed job. Complete artifacts and failures are retained.

The repair changes only the qualifier and its regression tests. Horizontal
whitespace cannot cross trace lines or substitute another TID; full signal
pairing remains mandatory. Nine integrity groups passed. The new 38-input set
`e5a21a599c42fdfb57d2ae1a785071631306909c70fefad0a378676ec6d0317b`
then passed **65 native histories / 724 operations / 74 physical controls** and
**65 actual original histories, 518 original-method calls, 36 retained tests
and the mandatory positive Linux clock test**. Both native ELFs are unchanged.
The [current record](qualification/thread-cpu-development.json) and
[self-contained evidence](qualification/thread-cpu-development.tar.xz) preserve
the new executions, both hosted failures and earlier source-specific results.
The repaired source still requires its own exact-commit hosted CI.

All three continuity jobs succeeded in each `44b3` workflow: 659 native
controls, 572 actual original comparisons plus four retained tests and seven
capacity controls. These actual executions use the final 62-input
`a25df9cd4b5b107d56d69ba2f2da1ff13f39e895973ba38e3061432b373cbff0`
source set. Full 1,065,536-row capacity and fresh-process reread remain intact.
The thread failures prevent either workflow from being called fully successful.
**41 kernels / 12 foundations / 71 HIA files; 26 Rust packages retained, zero
retirements and all nine whole-project gates OPEN.**

## Continuity, thread lifetime and actual resource production — 2026-11-16 UTC

The current candidate inventory is **41 kernels / 12 native foundations / 71
HIA source files**. All **26 original Rust packages remain**, no package
retirement is accepted and all **nine whole-project gates remain OPEN**.
The new foundation sources and qualification controllers are the current
implementation. Development authoring scripts and intermediate source trees
remain outside the repository; necessary failures and exact source/runtime
evidence are retained as audit inputs.

### Published resource production actually completed

Published head `2e3e5dcaa6f899e4f42f2b390fb869255364824d`, tree
`266035460dde623358ce5e9ab0124d9453b8d5ce`, passed all fourteen HIA
jobs in push run 43863320729 and PR run 43863349518, both attempt 1.
The full typed-State produce → independent-process restore → bounds chain
passed in both lineages. Each actual Host job also ran the resource production
owner against that same job's successful sealed parent. The full artifact ZIP
API digest, all 514 regular members, original job logs and complete raw resource
and Host syscall audits were independently rechecked.

The PR used actual TID 5551 and push used TID 5854. Both bound all 52 current
inputs and the 310,539-byte resource ELF with SHA256
`a15fdbfd5c2102d91b5a349ffceb1b485e009265fb6a43c491f96b1fbf0a9e93`.
Three actual samples yielded four receipts and complete checks 1, 3, 5 and 7.
No fresh execution was invented during the independent replay. The complete
[production success record](qualification/host-resource-production-ci-success.json)
retains source maps, original production bytes, full traces, before/after
context and seal, complete logs and both run/job/artifact identities.
Whole Node, paid CPU and original service-budget acceptance remain false.

### Finite continuity owner and original ordering

Four new HIA sources compile into the native primary stage, complete classical
root, installed configuration context and continuity relation, with a native
Linux syscall emitter. They compose the byte-identical frozen TypedStore owner.
Actual staged-State reads, full row-offset indexing, exact account lookup,
maintenance, liabilities, reward due sets, recipient sorting/deduplication and
capacity checks run inside the HIA executable. The hosted controller provides
physical capabilities and test inputs; it cannot supply membership or a
successful continuity verdict.

This is the selected fast-activation prefix in the original store:
Delta materialization, complete slot-State decoding, ordinary check_state,
operation-local progress, then an optional classical root. Historical replay
and the reorg tail have their own order; this entry does not claim those call
paths. Four installed configurations are a finite non-PQ subset of Config.
All use Node::open(..., 1) and StateBackend::Legacy. A growth-reference task is
not PermanentAccountGrowthV2. Arbitrary valid Configs, disabled task profiles,
timestamp/network/parameter changes, PQ private anchors and retained rewards,
and GSC2 remain unimplemented here. Growth cannot request a classical root.

The captured development closure, before final hook whitespace formatting,
has 62 inputs, source-set SHA256
`8711a557c1b3ecc42e0d95ff980324dcba7176a735dddce0206b33263799c9d4`.
Its complete actual native run passed all 659 controls in 309.141244876 seconds:
572 semantic cases, 13 direct context ABI checks and 74 physical controls.
Before/after source identities matched; the four images, emitter, prefix and
final executable matched the independently checked final build. The 3,696,506-byte
native report has SHA256
`a97ab3912f175d1da5bfce6b1c137b339f6c3e0864fe20392e352bc4bd895f21`.
The same captured source then passed **572/572 actual original-Rust semantic
comparisons and all four retained original tests**. Its isolated wrapper took
348.060553935 seconds and exited zero with no collection errors. The complete
918,196-byte before/after source observations both have SHA256
`988bd741317a5f29db26bff65a48da278236adaba39c496991f93149977be803`.
The 944,940-byte original report has SHA256
`b523d694a14bf84fdec647e7a6f26ca5b306770ba8daf14722f249d181d5a52b`.
The actual executed Rust test binary was independently copied after execution:
610,970,008 bytes, SHA256
`87f0594efd7870f282f583eb70b0b4c6339475976b26f158bc591e0f4265c374`.
The full original production sources remained byte-identical. This is an actual
current-source development result; the new exact-commit CI remains required.

Final formatting removes exactly one trailing LF from the original-test hook
(11,758 to 11,757 bytes); all other 61 inputs are unchanged. The final 62-input
source-set SHA256 is
`a25df9cd4b5b107d56d69ba2f2da1ff13f39e895973ba38e3061432b373cbff0`.
Its source admission and actual 18.802374730-second build passed, and all four
images, emitter, prefix and ELF are byte-identical to the executed predecessor.
The full native/original results retain their pre-format source identity;
complete post-format execution is required in the new committed-source CI.

The seven retained maximum-row capacity runs belong to their exact earlier
source. They passed in 649.249914634 seconds, with each original 240-second
child limit unchanged. The real stream contains 1,065,536 rows and 36,837,812
bytes (SHA256
`716e8d4a9a117782596a727c4a300d4e7a1a62ff436885fbc81a7abbf384a702`).
Fresh-process complete reread, final-byte corruption, total-row overflow,
1,000,000-account and 65,536-working-key boundaries, and 65,515 exact recipient
identities were exercised. This does not qualify simultaneous maximum-size
values, cache eviction, physical power loss, GSC2 or durable Node COMMIT.

The original V2 run exited 137 after 566 partial observations with unknown
cause. Its removed temporary raw directory has not been recovered; recovered
source bytes do not reconstruct its missing raw execution. V3 original Rust
compiled but rejected an incorrectly qualified retained-test name. V5 passed
four retained tests and then hit a real GROWTH_PROFILE constructor assertion
before the 572-case comparison. Both actual failures, all surviving logs,
native bundles and exact source/hook identities remain in the
[development record](qualification/continuity-development.json).
Correcting the adapter to the original Legacy opener is qualification code;
the original Rust production functions remain byte-identical.

### Actual thread CPU differential exposed a missing backend branch

The three thread CPU HIA sources implement a Linux main-thread/one-worker
lifetime with 64 live stamp capabilities, kernel-random capabilities,
nonreused object serials and native generation identity. The production entry
cannot import a TID, generation, clock, baseline or measured charge. Clone
copies identity/baseline without sampling; checkpoint advances only on success;
finish consumes before wrong-thread or clock refusal; value drop consumes
without turning the primitive into the future paid-account Unknown latch.
The actual native adapter owns clone, guarded stack, private futex transfer and
shared clear-child-TID join.

The V6 native-only run passed 53 histories, 676 operations and 74 physical
controls. Its real original-Rust comparison nevertheless passed only **44/53**:
EINTR, ENOSYS and EIO at start/checkpoint/finish produced Some in original Rust
and None in native HIA. Those nine failures remain failures. All EINVAL cases,
21 natural histories and 20 controlled-timespec histories matched.

Independent inspection checked all 332 rustix 1.1.6 source files against the
exact Cargo.lock archive, actual linux_raw/time compile configuration and the
ELF64 target. Its clock_gettime_dynamic path returns on first success, refuses
first EINVAL, and otherwise makes exactly one real syscall fallback; the
ThreadCpuStamp .ok() conversion occurs after that backend branch.
The final owner implements this exact single fallback in HIA. Its 38-input
closure now includes Cargo.lock, the workspace Cargo.toml and the Node
Cargo.toml, with source-set SHA256
`5d77c85bb1978f502d7b09b59a36263b69f204515f1d85ef9df372675ea6aead`.
All original 53 input records remain a byte-identical 62,803-byte prefix;
twelve persistent-error histories extend the corpus to 65 histories and 724
protocol operations. The production image is 125,683 bytes with SHA256
`6ceba842c367c943b5304a6cc91aa1d255ba40355b538572de4c810973462edd`.
Actual native execution passed all 65 histories and 74 physical controls.

The actual original-Rust execution then passed **65/65 histories**, covering
518 original-method calls, all 36 retained original tests and a mandatory
successful positive Linux clock control. All 44 controlled-clock histories
completed, including the twelve persistent-error additions; the other 21
histories use actual clocks. Complete original/native sources, the executed
binary and all 332 locked rustix source files matched before/after checks.
The 1,070,635-byte original report has SHA256
`b0ab0a403f22e84c31a6b7463b9bae849533d49f42dc13100249fde7358733ff`.
The independently retained actual Rust binary is 612,166,040 bytes, SHA256
`ae232c3378e8a0e0486c0497b262b1d6a374beecf2670494124f96fcd3f4cc24`.
These are exact-source development results; all new committed-source CI jobs
remain required. The V6 44/53 comparison retains its original failed status.

Trace validation binds child calls to actual clone-start/exit fences, complete
unfinished/resumed syscall pairs, real signal delivery and rt_sigreturn.
Four earlier before-birth/after-exit mutation acceptances were independently
reproduced and fixed. The valid original trace still passes and all four
impossible lifecycle variants now refuse; that offline replay is not a new
native execution. SIGUSR1 and SIGKILL observations preserve their distinct
outcomes. A same-numeric-TID fixture tests native generation ABA; it does not
claim actual kernel TID reuse. The
[thread CPU development record](qualification/thread-cpu-development.json)
retains failures, dependency evidence, exact final sources and actual reports.

Shared signed i128 paid CPU epochs, reservations/debits/residual settlement,
global Unknown, poisoning, scoped executor spawn/join/panic behavior, Node
worker embedding and original service acceptance are separate missing owners.
A finite stamp primitive or independent meter cannot replace those contracts.

### Mandatory current-source CI and preserved failed handoffs

The workflow has eighteen jobs and sixteen independent native compiler
bootstraps. New continuity native, original-Rust and capacity jobs bind an
exact common head/run/attempt. The original-only job requires no native
compiler; that was independently checked with toolchain imports/environment
and subprocess execution disabled during complete source/corpus admission.
Thread CPU requires actual full original and native histories.

The helper reconstructs full source closures, checks each input against its
committed Git object, admits the complete canonical corpus, verifies archive
metadata and bytes, and transfers only verified regular files into a fresh
directory. Every full-capacity phase uses the same complete source/ELF and
cold restore consumes the complete actual preceding output. FIFO/symlink
metadata is retained in the raw archive without activating it.

Independent review found two controller defects before publication: including
a sibling packaging log changed upload-artifact's least common directory, and
failed dependent unpack inputs were absent from the failure archive. The
workflow now uploads one artifact directory and copies the log inside it;
dependent pack preserves the complete downloaded root and any binding and
transfer receipt even after refusal. Eight actual source/transfer test groups,
four bootstrap groups covering all sixteen snippets, and eighteen-job YAML
validation passed. The
[CI development record](qualification/foundation-ci-development.json)
preserves initial review, both defects, correction, complete test logs and
final independent review. These are controller checks, not runtime semantics.

Every new job still needs an actual exact-commit run. The original Rust,
formal/portability ownership, resource limits, service deadlines and nine
whole-project acceptance gates are unchanged. Namespace publication,
expected-root admission, active/event transactions, replay/outbox/ACK,
complete Node work and the remaining package graph must close before any
old implementation is retired.

## Exact-source CI completion and same-job resource production — 2026-11-16 UTC

Exact head `34ecf1bd11264bb78df19836e0eb4b6665ed2cec`, tree
`6e21f6fe51fad0a7e89fbbe6042c175bb5cba246`, passed all fourteen HIA
jobs in both push run 43848902425 and PR run 43849236024. The full typed-State
produce, fresh-process restore and bounds stages completed successfully in both
lineages. The actual Host production jobs passed 22 fresh checks with actual
TID, cgroup membership and executable observations; independent resource traces
and actual original-Rust comparisons also passed. The [Host success record](qualification/host-production-ci-success.json)
retains the complete production files and original log bytes. All prior failed
jobs preserve their original status.

The new resource production controller reuses only that same job's successful,
sealed parent. It checks the full previous eight-key before/after binding and
creator/current-service equality before locking. A fresh resource service must
preserve immutable parent identity and the original five limits, and may only
change its own current service identity. No previous report, fixture or supplied
counter acts as a fresh kernel lease. The source set now includes the complete
Host closure and all execution helpers: 52 exact inputs.

The production trace parser requires actual bounded reads through EOF for all
three counter files, exact captured parent FD ownership and close before the
second full check. The remaining Host calls undergo complete independent audit.
Actual fixture execution exposed an incorrect expectation that counter_reads
was cumulative; the owner correctly returns three reads per sample. Both the
failed observation and corrected real fixture execution are retained in the
[development record](qualification/host-resource-production-development.json).
The final pre-lock lease guard extends those sources; complete source and AST
bindings distinguish each observation. Synthetic refusal controls are not native
runtime or production success evidence.

CI runs all 18 new controller test groups before any parent provisioning, then
builds and runs the resource production image after successful Host production
in the same 20-minute job. Always-run checks retain source integrity and explicit
failure artifacts. The new source has no inherited production PASS: its own
exact-source execution remains required. Counts remain 41 kernels, ten native
foundations and 64 HIA files, with all 26 Rust packages retained and all nine
whole-project gates OPEN. Continuous State, paid per-thread CPU, full Node,
original service budget and retirement acceptance are not inferred.

## Complete typed State staging and capacity lineage — 2026-11-16 UTC

The candidate adds three HIA sources for streaming typed staging, a separately
compiled native root image in the same ELF, and its Linux emitter. Together
with the two new resource-owner sources, the complete inventory now has 41
kernels, ten foundations and 64 HIA files. All 26 original
Rust packages remain, zero retirements are accepted, and all nine whole-project
gates remain OPEN.

The frozen development candidate passed 603 native controls and ten controller
controls. Actual unchanged original Node methods matched 392 cases; all three
original bounded State tests passed. The first original-Rust comparison exposed
an empty-key SQL projection discrepancy. The final source preserves stored
empty-key and empty-value NULL projection refusal, callback order, dimension
checks before conversion, key-before-value conversion, and Delta repair/deletion
of invalid old rows. The original 374 inputs were retained and 18 added. This
is not complete SQL storage-type conversion or full serde error-chain parity.

The full classical State has 65,536 rows with 160-byte keys and 4,096-byte
values, totalling 279,969,808 typed-stream bytes. Its SHA-256 is
`cc4eaec0976403b6399b6233faa453524d6d306dc0425de8707de353b7b966b3`;
native and independent full-root calculations agree at
`f39d0e6c087d523385cebb2eaeda1f4115b5c116fd1de6d07a416c5039b45702`.
Produce, fresh-process cold restoration and bounds stages passed in
644.13996704, 621.776575668 and 71.819485816 seconds. All three bind the same
native executable, complete native/original source maps, head, run and attempt;
the cold and bounds reports include the exact prior report hashes. A corrupt
final value byte and a classical count overflow fail with zero output. The
growth dimension plus-one case passes without a GSC2 root claim.

The [complete development record](platform/typed_store/qualification/development-observations.json)
preserves these actual observations, initial/interrupted failures and their
exact source identities. Its base Git head is `453326b335af`; the new component
was an unpublished overlay, so `native_source_inputs_match_git_head` remains
false in those records. New mandatory exact-source CI must rerun all four jobs.
The full source is verified before and after each job, artifacts are tied to
head/run/attempt, and each capacity dependency must preserve the prior receipt.
FIFOs are archived as metadata rather than opened by artifact collection.

The final bundle entry independently reconstructs the current owned-source and
canonical dependency closure, verifies the complete set and its digest, and
regenerates the entire source-defined input corpus. It rejects missing or extra
inputs, digest forgery, noncanonical or aliased paths, dependency cycles and
re-exported helper claims. Actual XZ decoding is bounded by the source-defined
corpus extent and rejects truncation or trailing data. The integrated tests
passed nine groups, 81 controls and 11 public CLI invocations before any Rust or
native execution. Fourteen owned files now contribute to 28 native inputs;
the preserved 13-file development runtime records keep their original identities.

The 4,587,520-byte private native arena does not include memfd/tmpfs captures or
hosted-controller memory. Fresh-process cold restoration is not a cache-flush,
power-loss or durable commit witness. This owner has no namespace, continuity,
expected-root, COMMIT, replay, outbox or ACK authority. The original four-second
service gate and all original resource limits remain unchanged.

## Aggregate Host resource owner — 2026-11-16 UTC

The resource owner composes its two new HIA sources with all 35 byte-identical
Host helpers and the existing reviewed read-only adapter. Both generic explicit
include graphs were independently admitted and are Core-identical to the
specialized native builder's 48-function programs. The original Host HIA source
and all original Rust implementation bytes remain unchanged.

Each actual sample performs a complete fresh check, retains that exact parent
FD while reading CPU/memory/PID counters, validates all three bounded regular
files through EOF and UTF-8, parses in original order, closes the parent, and
performs the second fresh check. CPU deltas use a private baseline and four
checked subtractions; memory and PID values are point-in-time samples.
Failure does not publish qualified values or credit. The production parent
must be owned by UID 0; that is not a requirement to run the native image as root.

The [source-bound development record](qualification/host-resource-development.json)
retains the actual 183 native controls and 172 original-Rust case comparisons
covering 180 operations, plus 44 original Host tests. The original ignored child
probe remains ignored and is exercised by its original parent. In 148 cases the
actual unchanged `sample_counters` function owns the entire sequence; 23 use
explicit private mutation-phase fixtures and one checks the added private
baseline protocol. The fixed production `KernelBudget::open` and
`checked_parent` were not qualified by those fixtures.

Local ptrace denial remains UNKNOWN. A separate actual execution traced the
same fixture ELF and verified the CPU-to-memory-to-PID order, same captured
parent FD, EOF/type checks, and close before the second full fresh check. The
initial socket-creation denial and source-bundle omission finding are retained.
After complete source-set admission was added, all native and actual original
comparisons ran again; three integrity groups and seven actual malformed-bundle
CLI calls passed their required refusals. The final mandatory CI uses one native
run and the same source-bound corpus for actual Rust, and requires real trace
PASS rather than accepting UNKNOWN. It excludes live fixture namespaces from
artifact traversal while retaining complete direct receipts, build inputs and
original compiler/test logs.

Development results preserve their exact 30-input source map and the full
4,361-file original binding. New committed source requires fresh CI. Resource
production-positive execution, same-worker placement, paid per-thread CPU,
external child ownership, Node completion authority and original four-second/
16-attacker acceptance remain OPEN. No Rust package is retired.

## Observed production trace-normalization failure — 2026-11-16 UTC

After artifact collection was repaired, the actual `8690b8b` push Host job
`133202337683` retained its failed production evidence. The HIA process exited
zero, emitted four zero-error receipts with cumulative full-check counts
1, 2, 5 and 22, and matched its actual TID, fixed-parent membership and running
executable. The subsequent independent trace verifier failed with
`Unexpected metadata path`.

The original quote pattern could not consume escaped payload characters and
instead paired a closing quote with a quote on a later syscall line. Thus an
actual absolute metadata path was not normalized. The fix consumes a complete
escaped token and restricts normalization to the path argument of anchored
`openat`/`newfstatat` calls; it preserves read payloads and unknown paths.
The [diagnostic record](qualification/host-production-trace-parser-development.json)
retains the complete original 54,038-byte trace, job log, artifact identity,
receipts and failed status. Offline reinspection of those same bytes verifies
888 calls, all 22 complete checks and resource-descriptor cleanup. Fifteen
fixture/production controls pass, including escaped payloads, the exact failed
trace and refusal of a different parent or process-leader membership path.
No failed job was changed to PASS, and the revised committed source must still
execute a fresh production qualification.

## First hosted production observation and evidence repair — 2026-11-16 UTC

Both `dcd72f7` Host jobs passed real fixture syscall tracing and 145 actual
original Rust comparisons. Their production services then failed. Artifact
collection also failed with EACCES while traversing the intentional search-only
private fixture, so the inner production cause could not be retrieved and is
not inferred. The [complete job logs](qualification/host-production-ci-failure.json)
retain the actual source identity, both failures and passed preceding stages.

Artifact inputs now explicitly select reports, native builds, actual traces
and original-stage raw logs. Failure reports and child-log tails are also
printed with a strict byte bound and JSON escaping. Thirteen Host controls and
all four optimized-mode cases at each of eight compiler gates passed. No HIA
instruction source, original Rust or resource budget changed. A new exact-source
production execution is mandatory; this evidence repair grants no native PASS.

## Fresh physical Host checkpoint candidate — 2026-11-16 UTC

The candidate has 41 kernels, eight foundations and 59 HIA source files.
The fixed-parent Host owner freshly performs actual Linux reads and native
identity, context and five-limit checks. The rebuilt source passed 151 physical
controls plus 26 hostile-adapter controls; the complete 1,791-byte syscall
adapter instructions were independently reviewed. Core shape acceptance is not
a formal machine-code proof or a complete Node Host implementation.

Actual original Rust execution matched 145 private-file cases and retained 44
original Host tests. Its one default-ignored helper was explicitly called by
the original parent test. The full production Rust file was unchanged; a child
adapter was appended only to the existing test-only include. The initial E0753
adapter compilation failure is retained. This comparison does not claim the
original fixed-path production owner or resource sampler has been replaced.

Local tracing failed with actual PTRACE_TRACEME EPERM; mandatory tracing correctly
failed after the physical controls passed. A separate 20-minute hosted Host job
requires real tracing, actual original Rust comparison and a fresh production
image execution inside the fixed parent. The controller refuses existing parents,
local provisioning and source drift. Eight controls passed, including an actual
already-exited-child pipe capture. A real scheduled early-exit observation lost
283 bytes before the fix and retained all bytes after it; both native attempts
still failed, as the host lacks ptrace permission. The new hosted production
positive remains unobserved. Resource sampling, same-worker integration and the
original service gates remain open. All 26 Rust packages remain retained.

Both exact `453326b` HIA workflows completed all eight jobs: 257 component tests,
zero skips and 92,509 shared native calls in each. Its separate original W1
service campaign still failed in both pressure phases with zero confirmations;
attack-free latencies were 2.374779837 and 2.308299376 seconds. Those observations
are bound to that prior source and do not certify this new Host increment.
The mandatory Host job adds an eighth independently guarded compiler bootstrap;
all four optimized-mode checks execute at each of the eight gates.

## Native audit values and private raw bindings — 2026-11-16 UTC

The preceding AuditEvent/RawBindings increment contained 41 kernels and seven
native foundations, covering all 56 HIA source files. AuditEvent passed ten native tests/2,847 calls; its
unchanged original Rust crate passed three original unit tests and 1,849 semantic
cases. RawBindings passed seven native tests/16,597 calls; 16,471 original Rust
operations in 1,220 histories match its actual native output hashes. Both full
records are retained under `hia/qualification/` and exact committed-source direct
Rust/native CI remains mandatory. All 26 Rust packages remain, with zero accepted
retirements and all nine whole-project gates OPEN.

During development, two retained-compiler checks exited 137 before the Cloud
environment disconnected. Its temporary volume was recreated; unpublished source
and reports there were unavailable. The original cause is not established. The
published `1550620` tree was restored exactly, and the two new components were
rebuilt from the original contracts and recovered reference tests. Their new
native artifacts were independently compiled and executed. Old native passes
were not applied to the new source hashes. A new Core bool-to-integer cast
rejection and the earlier original-Rust adapter type error are retained with
their corrected successful observations; no compiler guard was weakened.

Both `1550620` HIA workflows completed eight successful jobs, 238 component
tests without skips and 87,813 shared native calls. The original service campaign
on that head still failed under 16-attacker pressure. Three historical budget
comparisons refused before native execution because Cargo.lock differed; their
same-input guards remain intact. A green component workflow does not certify
whole-node latency, model outcomes, PQ identity or retirement.


## Real private M05 queue ownership — 2026-11-16 UTC

The lane owner retains real queue bytes and fairness between native calls.
Local controls passed 41,365 owner calls and 2,042 canonical-policy regression
calls. The unchanged complete original mempool crate, separately compiled with
Rust 1.95, matched 41,248 public operations in 1,862 histories. Physical ring
wrap, interleaved owners, full clear/close erasure and actual allocator denial
are exercised. [Source-bound observations](qualification/mempool-owner-development.json)
remain distinct from the mandatory final-source hosted original/native run.
The Node's durable local-pool, signed admission and signer nonce ownership
remain open; a public in-process lane owner does not retire the M05 package.

## Observed qualification and bootstrap regression correction — 2026-11-16 UTC

Both exact-source workflows for `85b0b85c` completed all eight jobs: push
`43817777731` and PR `43817996123`. Each ran 224 component tests, zero skips
and 76,161 native calls. The newer source still requires its own qualification.

The concurrent `2f6556e7` bootstrap hardening is retained. Executing its
unmodified regression test exposed seven successful-control failures because
two expected strings used literal backslash-n characters while the actual
workflow correctly wrote newline-separated environment values. Correcting
only these expectations passed four tests and 28 optimized-mode controls.
The failed observation is recorded here; no rejection guard was weakened.

## Fail-closed exact-source compiler bootstrap controls — 2026-11-16 UTC

Seven HIA native CI compiler-bootstrap blocks previously used optimizable
Python `assert` for their PASS decision. They now fail closed under `-O/-OO`
and check the exact compiler SHA-256 and nonempty path before exporting
environment variables. The Rust serde_json reference artifact checks were
made optimization-independent. A new 4-test/28-case adversarial controller
is wired into the source/archive job. This changes neither native HIA machine
code nor any original Rust code. Hosted exact-source outcomes are required;
all package retirement, Node, PQ and nine integration gates remain open.


## M02 closure and StoreOwner initialization recovery — 2026-11-16 UTC

The new M02 HIA module implements the whole pure original consensus arithmetic
and time-policy closure, including all 512 Work bits, checked target adjustment,
parent-window error order and median-time admission. Actual native testing passed
6,308 calls. A separately compiled unchanged Rust original passed the same 5,344
semantic inputs against the independent oracle; the new hosted direct comparison
remains mandatory. Both source-bound observations are retained in
[the development record](qualification/consensus-work-development.json).

StoreOwner mode 3 now recovers only a unique verified context-bound genesis.
Its 197 physical controls passed, including all valid FORMAT prefixes, genuine
SIGKILL cuts, short writes, unknown outcomes, lock exclusion and cold readback.
An additional adversarial test exposed a prefix replacement between validation
and write; the native implementation now reopens and checks complete HEAD and
FORMAT records before an opened receipt. The initial bad observation is preserved
and the three final readback adversaries are refusals. This is a bounded physical
initialization closure, with no accepted whole-package retirement yet.

## Independent qualification jobs — 2026-11-16 UTC

Exact-source push run `43813295781` executed 224 component tests with zero
skips and 76,161 shared native calls successfully, then exhausted the combined
20-minute job while starting the original executor comparison. Physical native
StoreOwner qualification passed 52 controls in that same run. The whole run and
the matching PR run `43813498662` remain CANCELLED. The unchanged component,
physical-owner and original-executor commands now have independent jobs with
the same 20-minute limit, source/compiler checks and retained artifacts. The
eight-job new-source result remains pending until observed. The failing W1
16-attacker service campaign and mismatched-input historical budget controls
are separate open gates; no original service resource limit was widened.

## Optimized Python qualification refusal — 2026-11-16 UTC

The native StoreOwner's physical test controller had assertion-based disk,
readback and crash-cut checks, which Python `-O` and `PYTHONOPTIMIZE` would
otherwise remove. Its startup now refuses optimized execution before any
native operation. Three actual isolated optimized-interpreter refusal controls
(`-O`, `-OO`, `PYTHONOPTIMIZE=2`) and compilation of both changed Python
files passed. Exact-head hosted native/PQ qualification remains pending.
This changes neither the HIA machine code nor Node transaction ownership,
original service budgets, the 26 retained Rust packages or nine OPEN gates.


New M05 opcode 24 is a one-call **pure QoS snapshot proposal** with five
original-headroom/admissibility fields. Its qualification requires emitted HIA
machine code to match one actual original Rust `qos_snapshot` for each real
ingress/dequeue case; the preceding opcode-23 CI has six SUCCESS jobs, but
cannot qualify newly changed source. Nothing here owns the Node queue or
reduces any of the nine open migration gates.

The newest M05 candidate adds a single-call pure five-field post-dequeue projection (LQV1 opcode 23), checked against one actual original Rust dequeue observation plus an independent fairness-module differential. Exact-head CI qualification is pending. The projected fields do not authorize or mutate the real mempool; the complete Node owner and retirement gates remain OPEN.

## New M05 projection candidate and source-bound qualification

The `5524ce8b` six-job native CI completed successfully on its exact source:
222 tests and 70,998 shared native calls, with mandatory original Rust execution.
The newer queue post-pop count and dequeue-presence opcodes (20–22) require a
new exact-head run. The complete Node owner, all 26 original Rust packages, all
nine OPEN migration gates and PQ HOLD_NO_GO are unchanged.

## Scope and conclusion

The audited consolidated baseline is `59bd6ae4223caff6695dc9cf2ee2cdcdc6df5e88`.
The whole tracked tree, active Cargo package graph and all M00–M17 ownership
boundaries were inventoried. Detailed semantic comparisons and native tests cover
the implemented components listed in [the native guide](README.md). This is not
a claim that every one of the 702,001 retained Rust physical lines was manually
reviewed, or that every historical campaign passed.

**The full replacement is incomplete.** Forty-one kernel units and eight native
foundations account for all 59 candidate HIA source files. Native connected-stream
I/O, complete classical response codecs, Settings and streaming persistence exist, but no whole original package has
an accepted retirement witness. There is no complete HIA node executable,
typed branch/replay/outbox owner or complete native identity/signing stack. The
nine integration/qualification gates remain open.

## Baseline inventory

| Measure | Baseline count |
| --- | ---: |
| Tracked files | 41,834 |
| Tracked bytes | 3,999,565,648 |
| Evidence files | 36,222 |
| Evidence bytes | 3,804,721,963 |
| Active Cargo packages | 26 |
| Rust files inside those packages | 1,621 |
| Rust physical lines, including tests | 702,001 |

About 95% of tracked bytes are evidence. This is not 4 GB of independent active
application implementations. No identical Git blobs were found among active
workspace Rust source files in the cleanup inventory. Deleting whole source
packages merely because another file has a similar name would remove behavior.
The empty root README was an existing owner choice and is unchanged.

## All original package owners

The table preserves the original ownership contract. “Partial” means that only
named kernels are implemented; it never means the package can be removed.

| Package | Module | HIA coverage | Original retained responsibility |
| --- | --- | --- | --- |
| [trnm-types](../trillionnium/crates/trnm-types) | M00 | Unported | Shared task/identity/transcript/transaction data; delete consumption-consensus governance controls. |
| [trnm-executor](../trillionnium/crates/trnm-executor) | M06 | Partial: `executor/schedule`, `math/binary64` | Deterministic conflict scheduling independent of consensus. |
| [trnm-bench](../trillionnium/crates/trnm-bench) | M17 | Unported | Retained executor microbenchmark; not ledger throughput. |
| [trnm-mempool](../trillionnium/crates/trnm-mempool) | M05 | Partial: `mempool/lane_quota` pure policy and `mempool/lane_owner` real private queue | Typed signed admission, nonce reservations and durable local-pool/Node handoff independent of BFT. |
| [trnm-worker-agent](../trillionnium/crates/trnm-worker-agent) | M10 | Unported | Bounded real child process, task workflow and evidence adapters; not a miner. |
| [trnm-oracle](../trillionnium/crates/trnm-oracle) | M11 | Unported | Application evidence aggregation, not ledger quorum or voting. |
| [trnm-research-protocol](../trillionnium/crates/trnm-research-protocol) | M10 | Unported | Contribution/evaluation/lineage contracts independent of ledger consensus. |
| [trnm-protocol](../trillionnium/crates/trnm-protocol) | M00 | Partial: `protocol/id`, `protocol/hash`, `protocol/pnh1`, `protocol/pgh2`, `protocol/ilf2`, `protocol/ilf3`, `crypto/pon_hash`, `protocol/pnx1`, `protocol/state-root`, `protocol/state-root-compact` | Canonical transaction/fee contracts and explicitly selected bounded ILF2/tag23 and ILF3/tag24 witness codecs; complete ILM2/ILM3 decoding and actual parent loading belong to M06; no admission authority. |
| [trnm-peer-lease](../trillionnium/crates/trnm-peer-lease) | M04 | Unported | Cross-process scope/generation fencing, append-only replay and bounded Unix transport. |
| [trnm-data-availability](../trillionnium/crates/trnm-data-availability) | M09 | Unported | Signed storage responsibility and retention plus a separate TCM1/TCQ1/TCS1 configured-peer cell byte cache with pinned identity, bounded TCP repair and complete no-replace materialization; no block consensus or model-use authority. |
| [trnm-task-kernel](../trillionnium/crates/trnm-task-kernel) | M10 | Unported | Task/lease/capability/escrow local kernel; monotonic local sequence is not chain finality. |
| [trnm-mvcc-fee](../trillionnium/crates/trnm-mvcc-fee) | M06 | Partial: `state/json_string`, `state/json_value`, `codec/json_primitives`, `codec/json-number`, `codec/json-value-wire`, `codec/json-value-encode` | Deterministic ordered execution, fee deltas, checked derived commitments, explicit revision12 mandatory-capacity continuity, revision13 native model evidence, revision14 composition and revision16 bounded base/router/expert/mask updates with optional owner-pinned pre-genesis task windows; State publication remains with the Node owner. |
| [trnm-service-settlement](../trillionnium/crates/trnm-service-settlement) | M12 | Unported | Bilateral usage/escrow conservation; no consumption-derived voting power. |
| [trnm-control-plane](../trillionnium/crates/trnm-control-plane) | M16 | Unported | Observer/planner/guard only; does not grant consensus authority. |
| [trnm-state-import](../trillionnium/crates/trnm-state-import) | M13 | Unported | Bounded independently admitted export/import and root checks; no old proof decoder. |
| [trnm-release-bundle](../trillionnium/crates/trnm-release-bundle) | M15 | Unported | Build/SBOM/provenance contracts independent of consensus. |
| [trnm-checkpoint-store](../trillionnium/crates/trnm-checkpoint-store) | M03 | Unported | Independent exact CAS and durable Unix service; generalized owner frontier only. |
| [trnm-checkpoint-types](../trillionnium/crates/trnm-checkpoint-types) | M03 | Partial: `checkpoint/value_v2` | Extract canonical checkpoint/CAS record; remove safety-vote and validator types. |
| [trnm-crypto-primitives](../trillionnium/crates/trnm-crypto-primitives) | M01 | Partial: `work/encoding`, `work/field`, `work/matrix`, `work/verify`, `crypto/sha256`, `crypto/sha256_arena`, `crypto/sha512_arena`, `crypto/ed25519_group`, `crypto/ed25519_verify`, `crypto/sha256_stream`, `crypto/ed25519-sign` | Strict identity and exact experimental W1 verification, optimized production kernel plus scalar reference and structural producer comparisons; no work-hardness qualification. |
| [trnm-verification-profiles](../trillionnium/crates/trnm-verification-profiles) | M11 | Partial: `verification/closed_round` | Reusable evaluation/profile contracts and exact bounded integer BA normal form; no stake-quorum backend, model-parent authentication or general functional-equivalence authority. |
| [trnm-transport](../trillionnium/crates/trnm-transport) | M04 | Partial: `transport/replay` | Extract generation-bound authenticated frame admission; delete pacemaker and node scaffold. |
| [trnm-audit-events](../trillionnium/crates/trnm-audit-events) | M17 | Partial: complete public constructor, builders, Clone and Eq in `audit/event` | Consumer integration and dependency retirement remain open; the value has no consensus or durable authority. |
| [trnm-governance-guard](../trillionnium/crates/trnm-governance-guard) | M01 | Unported | Local proposal/timelock, role separation and optimistic version checks; no network governance authority. |
| [trnm-escrow-vault](../trillionnium/crates/trnm-escrow-vault) | M12 | Unported | Pure in-memory escrow conservation reference; no second production ledger or durability claim. |
| [trnm-pon-node](../trillionnium/crates/trnm-pon-node) | M15 | Partial: `transport/authenticated_request`, `codec/json-number`, `codec/json-value-wire`, `codec/json-value-encode`, `transport/authenticated-response`, `transport/signed-response`, `node/settings-development` | Native development composition with a single branch/replay/outbox SQLite owner, explicit maintenance choice, bounded public entrypoints, typed local error identity, checked history projections, explicit revision16 model/task-window CLI context binding, and optional fresh PQ transport-only ownership; account/task/install authorization is not PQ-migrated and no publicly qualified deployment is claimed. |
| [trnm-sqlite-io-boundary](../trillionnium/crates/trnm-sqlite-io-boundary) | M15 | Unported | Reused process-owned native SQLite boundary and executed-mutation transaction observer from c165; bounds History graph readback reuse to the same immediate transaction and fixed SQLite build. It adds no consensus or deployment authority. |

## Native toolchain boundary

The exact Hepta main revision was re-read as
`f33d8da316de8fdf27b504371f1a5310997ff548`. The actual compiler used by the tests
has SHA-256 `87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54`.
The original cold gate passed, with its original execution/cleanup budgets;
[the binding](qualification/compiler-binding.json) retains the complete scope.

Core v8 has a closed arithmetic/buffer/resource opcode set and internal calls.
The standard standalone ABI is a bounded stdin/stdout filter. Specialized Hepta
file publishers have real Linux adapters for file creation, writes, fsync and
atomic publication, but those adapters are not a general HIA node I/O API.
A complete node requires an explicit platform ABI, a real durable transaction
owner, network readiness, clock/randomness/stop handling and separate native
fault/recovery qualification. A byte buffer containing a descriptor number or a
caller-supplied “authorized” boolean cannot provide those capabilities.

The [Linux platform fixture](platform/README.md), [stream reactor](platform/reactor/README.md)
and [transaction owner](storage/README.md) use the fixed compiler to emit native
adapters around compiled HIA policy. The static ELFs perform actual syscalls;
no invented foreign-call opcode or host-language runtime implements the policy.
The first finite fixture's blocked-call deadline failure remains retained.
The reactor admits connected FIFOs/streams and uses epoll, monotonic absolute
deadlines, cancellation and private generation/rights slots. It does not admit
ordinary files or certify a hard fsync deadline. The transaction owner performs
actual locking, immutable transaction publication, HEAD replacement and sync,
then validates persisted data on reopen. The fresh-v2 format has executed the
complete 279,445,512-byte original State extent and 4,105 commits, with checked
file-offset and sequence exhaustion limits. It passed 52 physical controls and
170 native function controls. The exact parent rebuild matches that ELF. Typed
state transitions, interrupted initialization recovery and original service
latency remain unqualified; the local trace is UNKNOWN after ptrace denial.

The [state-root implementation](STATE.md) matched an independent bottom-up oracle
at 65,536 actual entries in 299.705821145 seconds in exact `96a0846` CI. The prior
353.568397442-second local observation remains retained. The same artifact's source,
maximum-count observation and later final-driver controls are bound separately
in [the retained report](qualification/state-root-development.json). Maximum
count with short values is not a test of every row holding its maximum value.
The unchanged original four-second service acceptance is not qualified.
The real Node directly owns `rusqlite::Connection` in `Node.db`, implemented
in `store.rs`. `TransactionScope` records SQLite operation boundaries; the
optional `OwnedConnection` wrapper is not that owner. Replacing checkpoint
values alone cannot retire this branch/replay/outbox store.

The fixed source evidence is linked in [the native guide](README.md). No
specialized filesystem, socket, cryptographic or full-node qualification is
inferred from the compiler fixed point.

## Observed integration failures

The fifth repaired candidate `4cc0464ff9632f2a493cb76d5b8b51eaad332dac` passed
[all three HIA jobs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43751782144):
189 tests, 56,884 shared-runner native calls, zero skips, failures or errors.
All five original Rust adapters ran. The [exact report](qualification/native-ci.json)
binds only that source set. OS 25/25, reactor 49/49 plus 13 native contracts,
and storage 48/48 plus 14 native contracts passed, with actual traces captured.
The complete-request job also passed 178 native request controls, 14 stream SHA
controls, 170 actual original-Node comparisons and six original tests. The source
job passed all 113 PQ negative tests and full historical readers; PQ stays HOLD.

The separate [actual executor comparison](qualification/executor-original-ci.json)
ran 5,274 cases against the unchanged original Rust library. It recorded 131
unsafe original results, 181 intentional differences and 27 expected version-skew
panics. HIA preserves the maximum reader dependency and satisfies the independent
conflict graph. Its status explicitly retains the original safety defect rather
than asserting identical unsafe behavior. This crate is outside the normal Node
dependency closure. Earlier source-derived model observations remain distinct.

Later sixth-batch sources require their own exact committed qualification.
Locally, complete response passed 11,420 controls, typed Delta passed 8,551,
Settings passed 16 tests (102 shared-runner plus 14 raw-pointer calls), and the
private-stack repair passed its 11 explicit observations. The bare signer spill
failure and slow storage attempt remain recorded failures. The integrated
response producer actually refused publication after denied cleanup. Original
Rust for these additions remains NOT_RUN until the dedicated mandatory CI jobs.
Typed Value construction and complete-State ownership remain distinct; complete
private owners and the original service budgets remain open. Earlier maximum-count state-root evidence stays bound to
its exact fourth candidate and does not imply a later full-State owner pass.

The complete original CI also exposed these distinct outcomes:

| Finding | Classification and action |
| --- | --- |
| Fifth executor adapter could not link transitive dependencies | Run `43749946614` passed the main suite but failed with E0463 before original executor execution. Exact Cargo-event library directories and twelve controls were added in `4cc0464`; run `43751782144` actually executed all 5,274 original/native comparisons. The failed run remains FAIL. |
| Fourth storage CLI startup failed without ambient Python path | Run `43746152828` failed with `ModuleNotFoundError` before storage/Rust/kernel tests. Explicit repository-root imports and fresh-cwd regressions were added in `96a0846`; exact run `43746877132` passed. |
| Hosted-cost missing-index dispatch could overwrite an old receipt in a copied candidate | Independent temporary-view reproduction found the prepublication fallback. Current CLI always uses the read-only checker; both missing and dangling index paths return 2 without modifying retained bytes. The actual failure is retained. |
| Three original retained stderr logs were absent from the third published tree | Introduced by ignored-file staging. The unchanged PQ archive reader failed in run `43741641815`; exact original bytes were explicitly tracked in `79fc1d4`, whose run `43741974022` passed. The failure and repair remain visible. |
| Distributed source inventory omitted `config/hia-migration-v1.json` | Introduced by the migration. Baseline had exactly 1,745 matching entries; candidate required 1,746. The unchanged original generator now adds the missing include and its original check passes. |
| PQ source corpus retains stale plan and generated-inventory blob pins | Introduced by the first and second migration commits, respectively. Those exact current-source bindings were refreshed under the existing reconciliation procedure. The fourth cleanup also requires the precise current public-readiness CLI binding because it adds archive dispatch; original checker functions remain unchanged. All 1,177 evidence pins and all unrelated source pins remain fixed. The unchanged checker succeeds with status HOLD_NO_GO, and all 113 original negative tests pass. This repairs source consistency and grants no native PQ acceptance. |
| Historical artifact `11531476198`, run `37730166589`, is unavailable | Existing retained evidence gap. The current download job found zero matching artifacts. No new sample substitutes for the missing original. |
| W1 original/fresh and arm64 pressure confirmation miss the original deadline | Actual service failure. All seven honest submission ACKs were observed, but independent native history replay reached the four-second deadline before six-depth confirmation. The three pressure outcomes remain 0/1. |
| Main baseline arm64 service gate already failed | Confirmed from run `43729710156`, job `132859243865`; only its outer controller was inspected, so its detailed cause is not asserted to equal the current deadline diagnosis. |

Current failure sources, exact job/artifact identities, ZIP hashes and refusal
observations are retained in [development-observations.json](qualification/development-observations.json).
The candidate service ZIPs were read and verified independently. Original
business code and relevant service scripts were unchanged between the baseline
and first candidate. Successful compilation, setup, invariant/accounting checks
and native unit tests do not turn a failed business confirmation into a pass.

## Cleanup result and limits

The current tree removes 607 obsolete checkout-repair files, 14 sealed CI ZIPs,
13 joint-resource archives, four large PQ triage streams, 885 public-readiness
pre-correction payloads, 32 hosted-cost containers/shards, eight D26 compressed
SQLite snapshots and 59 W1 complete-work containers: **1,622 removed copies
totaling 1,628,294,407 original bytes**. All remain recoverable by exact historical Git object with original
SHA-256/size bindings. The PQ capture's other 29 smaller records remain as
byte-identical current copies in its retained directory. This cleans current-tree
copies; Git history is not rewritten.

- [Checkout preparation archive](../evidence/pon-learning-outcome-composition-20261111/CHECKOUT_VISIBILITY_ARCHIVE.json)
- [Sealed CI ZIP archive](../evidence/pon-business-gates-819309-final-20261107/ci-819/ORIGINAL_ZIP_ARCHIVE.json)
- [Joint-resource archive](../evidence/pon-joint-resource-contract-20261109/ORIGINAL_ARCHIVE_INDEX.json)
- [PQ triage capture](../evidence/pq-authority-preflight-20261108-9d315/NATIVE_TRIAGE_ARCHIVE.json)
- [Public-readiness pre-correction archive](../evidence/pon-public-readiness-v1/PRE_CORRECTION_ARCHIVE.json)
- [Hosted-cost archive](../evidence/pon-work-security-eight-samples-20261101/HOSTED_COST_ARCHIVE.json)
- [D26 SQLite archive](../evidence/pon-business-gates-readback-20261107/D26_SQLITE_ARCHIVE.json)
- [W1 complete-work archive](../evidence/pon-w1-complete-work-20261101/W1_COMPLETE_ARCHIVE.json)

The sealed reader still checks all 810 original checksum entries and the exact
original seal, source observations and HOLD/FAIL counts. Missing or changed
retained files fail; they are not silently skipped or fetched from arbitrary
sources. The joint-resource reader preserves all 74 original checksums, 13
sidecars and the 4,052-member denominator. The PQ reader preserves all 1,050
original stored hashes, 147 gzip byte bindings and 543 followup bindings,
including the original startup UNKNOWN, red/green receipts and HOLD. Current
tests, authoritative ownership and historical counterexamples remain.
The public-readiness reader reconstructs the exact historical package and runs
its unchanged original checker against the measured source. It verifies 1,334
manifest entries, 2,588 source blobs, 793 source SHA-256 values and current plus
original Git tracking. Its [actual local PASS](qualification/public-readiness-cleanup.json)
retains all false current/public/native/activation claims. Only the present CLI
dispatch changes; the original checker functions stay byte-identical.

The hosted-cost reader executes the original checker in a private exact view,
validating all 208 manifest entries and 808 archive members. Five retained small
records and the original receipt remain unchanged. Its 16 negative tests and
actual prepublication dispatch failure are preserved in
[the report](qualification/hosted-cost-cleanup.json).

The D26 reader validates the full 617-file original package, all 614 prepared
files and 232 gzip streams against their stored and decoded hashes, complete
tails and preparation-plan bindings. It preserves all 609 other original files.
The original and archived reader observations agree; 15 negative controls pass.
It does not open SQLite, recover a Node or promote historical HOLD fields.

The W1 reader executes its unchanged original verifier in the complete 172-file
view, checking all 170 FILE_INDEX rows, 171 SHA256SUMS entries and 60 archives:
4,960 members / 4,463,919,709 decoded bytes. All 91 small records remain exact
retained copies, including ten logs explicitly added despite ignore rules.
The original and archived observations agree, and 15 negative controls pass,
including a genuine original-member verification failure. The 16,712-byte root
validation archive remains an unchanged required input. The four historical W1
service failures and incomplete CodeQL result retain their original identities.

The current PQ corpus pins 1,177 evidence files totaling 183,286,178 bytes across
46 packages; its validator actually reads those bytes. Other Rust tests embed
specific evidence with `include_str!`. A historical-object resolver must preserve
those readers' exact contracts before their current-tree inputs can be removed.
The audit checked Git object existence/type/size for the candidate set; complete
new SHA-256 archive manifests have been made for all eight completed sets.
Exact readers, complete original denominators and retained small records remain
mandatory; an inventory alone does not justify a weaker reader or deletion of
a required retained record.

## M05 lane admission source boundary

A new bounded HIA quota/fairness decision kernel encodes the original
`trnm-mempool` critical-reserve, borrowing and prefer-normal predicates. It
does not read authoritative queues, repair stale deduplication caches, reserve a
nonce, enqueue/dequeue a transaction, enforce admission locks or commit an
outbox. The [isolated M05 protocol](MEMPOOL.md) uses an original-Rust adapter
that includes `lane_quota.rs` and `lane_fairness.rs` unchanged, rather than
replicating their logic in a handwritten Rust oracle. A preliminary local run
checked 1,345 caller-model/actual-original-Rust cases. HIA native and full
original 26-package differential are **NOT_RUN** for this new source until CI
provides exact source/artifact evidence; no source-only verification changes a
migration gate.

## Retirement decision

Every original package remains represented in
[config/hia-migration-v1.json](../config/hia-migration-v1.json). The current
`--require-retirement` command refuses all 26 retirements. The remaining gates
are system I/O, persistent node/recovery, cryptography, node integration, the
original service budget, cross-target behavior, model loop, consensus research
and complete replacement/cleanup. Implemented parsers and pure proposals do not
mint the original private authorization types or commit state.

The sole sequence of further work remains the
[repository development plan](../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
