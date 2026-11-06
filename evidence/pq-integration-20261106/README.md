# PQ integration, actual validation and remaining qualification gates

This report concerns the existing draft [PR #723](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/723).
The latest combined code is `ca4e2fb9160d3e388e131624f7b3350ae4f5d56b`,
tree `ba691b8b5f06a0cfeb062261d6a33f0c086f06b0`. Its ordered parents are
the expiry-accounting candidate `ebd3c06da7d5f2bd136b7a24f24604508d420279`
and the later actual target `513e92dfc27044ef3e0c9d62e7ae504fa5bea38f`.
The target's Python marker compatibility change has been composed with the
strict supported-version policy and tested separately on this exact new source.

**Current conclusion: concrete authorization and validation defects have been
repaired and integrated. Whole-chain PQ, public-WAN operation, quantum-work
economics and production activation remain unqualified.**

The source with the broad validation below remains
`f85fea4e8da02404d513d074ceb35ad5292b017b`, tree
`0c1da9d2c13052b30af600e2a32a5eb286e985de`, integrated with the then-current
target `56897f125df27994efa1dda935f2c62eceb36de9`.
Its actual prospective merge `56ec6d4b9a429968cdb0dfa244c195b4551b7882`
has the same tree. A matching tree does not create a second execution.
The later ebd candidate has tree `367b4cadbf5d9ec0f3e4cfcbb0de4e6fc91a2895`
and f85 as its only parent; its completed native supplement retains its own
failure and source identity. Neither native campaign is relabelled as execution
of the newest combined source. Its changed corpus is an embedded provenance
input, so unchanged Rust bodies do not establish identical native inputs or ELF.

The publication commit containing this report has ca4e2fb9 as its direct code
parent and adds only evidence and plan observations. Its exact published
identity is recorded in the current PR update; this report cannot embed the
hash of its own containing commit. The earlier frozen EBD report and its
source/publication map remain historical archive members, not current claims
about this containing publication.

## 1. What changed and why

### TLS startup now rejects an unusable local identity before creating the owner

Previously the native TLS context checked the ML-DSA certificate/key and direct
CA signature but did not perform the local current-time, role and server-name
checks before opening the Node or announcing readiness. This was a startup and
availability defect. It is not evidence that a remote peer with an invalid
identity completed a successful authenticated session.

The repaired constructor validates against the single pinned CA, uses the
server/client purpose appropriate to the owner, and applies the configured DNS
name to server certificates with wildcards and subject-CN fallback forbidden.
It requires the exact two-certificate chain ending at the pinned CA. Invalid
profiles return `PQ_TLS_LOCAL_CERTIFICATE_PROFILE` before creating the Node or
listening. The client certificate does not acquire a server-name requirement.

The patch retains the existing handshake-time checks, TLS 1.3 hybrid exchange,
ML-DSA mutual identity, outer-TLS/inner-signer binding and original budgets.
The new negative controls cover wrong SAN, CN-only identity, wildcard identity,
expired and future certificates, inappropriate EKU, and root-as-leaf misuse.
The ordinary CLI control checks the refusal message, empty stdout and absence of
the Node directory. The role-specific positive control proves constructor
acceptance; it is not a new independent WAN handshake qualification.

Source:
[local TLS profile validation](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f85fea4e8da02404d513d074ceb35ad5292b017b/trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/context.rs),
[library controls](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f85fea4e8da02404d513d074ceb35ad5292b017b/trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/tests.rs),
[ordinary CLI controls](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f85fea4e8da02404d513d074ceb35ad5292b017b/trillionnium/crates/trnm-pon-node/tests/pq_tls_cli.rs).

### The original authorization fixes are now in the combined candidate

`submit_with_verified_parent_recovery` checks the classical network profile
before classical recovery I/O. This rejects the forbidden combination of a PQ
network owner with a classical recovery credential. It does not implement a new
PQ parent-state recovery protocol.

M15 `check_current` rechecks the expected checkpoint, the recorded time lower
bound, current root and publication expiry, role/content/generation and the live
Cell manifest needed for activation. Its read-only interface does not persist a
new time floor after every successful read. The embedding owner still needs
trusted current time and an independently fresh checkpoint.

The current tree has real ApplicationV6 account registration, rotation, task and
application owners. It must not be described as only a transfer prototype.
Neither those owners nor valid publication signatures supply a missing final-use
installer or activation consumer.

Source:
[parent recovery](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f85fea4e8da02404d513d074ceb35ad5292b017b/trillionnium/crates/trnm-pon-node/src/public_submit.rs),
[current release authority](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f85fea4e8da02404d513d074ceb35ad5292b017b/trillionnium/crates/trnm-release-bundle/src/pq_release.rs),
[full authority map](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/f85fea4e8da02404d513d074ceb35ad5292b017b/docs/security/PQ_AUTHORITY_SURFACE_AUDIT_20261031.md).

### Dependency and CI failures were corrected without weakening the gates

Five independent W1 lockfiles had drifted from the current shared crypto graph.
The actual Cargo 1.95 resolutions retain reviewed versions and checksums while
bringing the native-cost, verifier, zkVM host and both guest graphs into agreement.
Their locked graphs contain 69, 193, 306, 191 and 191 packages respectively.
The main workspace and fuzz locks were unchanged. A repaired guest dependency
graph is not a rebuilt guest image or a newly generated proof.

The repository-truth material verifier used
`packaging.Marker.evaluate(context="metadata")` with an environment whose API
did not support that argument. Both truth lanes now install the already reviewed
packaging 26.3 wheel in an isolated verifier environment, with its exact hash,
binary-only policy and install report. The verifier rejects unsupported versions
even for marker-free wheels. Explicit metadata-marker semantics and complete
declared environments remain unchanged. The original hosted packaging version
was not recorded; the controlled 24.2 replay demonstrates the API failure but
does not establish that the original host used 24.2.

The actual full-workspace registry contained 25 postwrite controls while its
reader required 23. The repaired reader selects all 25 and the original nine other
groups, for 60 unique selectors, preserving full compilation, actual ELF
identity, exact nonempty execution, and original time/resource limits. Reader
replay and a historical test log are never treated as a new native execution.

### Concurrent target changes were preserved

The real target advanced while `2e9deaf1` was being checked. Both histories were
merged into the earlier fixed f85 source, preserving both histories.
The combined corpus contains 592 pinned blobs and 511 required paths; the native
source inventory contains 1,269 entries. Complete tracked-source verification
covers 10,748 entries and 1,031,966,791 bytes.

The target adds Cell persistent transport and custody-window preparation,
storage/replay ownership checks and new controls. Pending/Done retain/repair
readback must match the original native context and owner generation before any
mutation. It does not reacquire funding or authorize redispatch of an already
completed effect.

Cell V3 uses ordinary public TCP and the `TCQ3/TCS3` wire contract. Its inventory
is a hint and payload validation remains mandatory; request and payload activity
share the original budgets. This transport does not provide PQ peer identity or
private-task confidentiality.

## 2. How the TLS regression was established

The tests-only source `7957a144312eece4e59837176191eb5dab247f09` was actually
compiled and executed on the independent desktop using Rust 1.95.0 and the
original profiles, two build jobs and single-threaded tests. The library reported
one pass and two failures; the ordinary CLI control reported one failure.
Both Cargo commands returned 101. The wrapper's successful exit means the
expected failures were reproduced, not that the old product behavior passed.

The first wrong-SAN assertion stops the failing CLI control. It would be false
to claim that every later negative was separately observed to fail on the old
code. The complete raw source matched before and after, and the actual
Cargo-advertised library harness, CLI harness and ordinary Node ELF hashes were
recorded. The pinned OpenSSL 3.5.9 provider was built from the exact source archive
using the original preparation script and exercised with real ML-DSA sign/verify
and wrong-message refusal.

Two earlier local builds were killed before tests ran, including a separate
reduced-debug attempt. They remain failed/incomplete observations and supply no
native verdict. The later `2e9deaf1` desktop batch was cancelled when the target
advanced, before any native compilation or test. Its preparation failures,
completed Python controls and cancellation/source readback remain separately
retained.

## 3. Source-specific validation

The following are observed executions. Nested child-test summaries, repeated
exact selectors, Python reader checks, benchmark samples and process-command
observations are separate quantities. An ignored test is counted only when its
exact invocation actually executes it. No grand total across overlapping scopes
is presented.

### Integrated source f85

| Scope | Actual observation | Interpretation |
| --- | --- | --- |
| Local locked dependency/material checks | Five locked/offline graphs; 23 material-verifier tests in isolated packaging 26.3 | Complete source before/after equality; no new guest image or proof |
| Independent desktop full-library attempt | Original 1,500-second ceiling; SIGTERM/exit -15 after 1,502.206865663 seconds; no parent test summary | Incomplete; retain the single paid-pending FAILED progress row without inventing its missing panic |
| GitHub x64/head complete Node library | 1,160 passed, 31 ignored, zero failed; the paid-pending test is explicitly ok in this separate execution | Three nested one-test summaries are not added; this result does not erase or diagnose the desktop observation |
| Independent desktop batch | 271 command/phase observations: 269 succeeded, one library timeout, one dependent readback blocked | These are not 271 unique tests; the overall durable job correctly exits 1 |
| Original native and TLS controls | 52 original exact controls; TLS 13 library / 4 CLI / 1 feature-off, all executed and checked by their original readers | Current-source repaired behavior; exact selectors overlap the complete library |
| Recovery and transaction ownership | Public-submit recovery suite 25 passed; its PQ-owner selector also checked; 13 transaction-scope exact controls passed | A repeated selector remains a subset, not an additional unique protocol case |
| Checkpoint/release/Cell components | Nonempty harnesses: checkpoint 11 / CLI 15 / cold 15 / cross-process 6; release 37; Cell current-authority 5 and one API doctest | Actual current-source component execution; no final-use installer or whole-store rollback qualification |
| New target controls | 26 additional exact executions: 16 Cell-library, 3 Cell-CLI, 7 example controls; original readers passed | The seven example controls are not the full V4 cost campaign |
| Seven new Node target controls | Desktop dependent readback remains blocked; all seven are explicitly ok in the same-source GitHub full-library log | Evidence is attributed to the GitHub execution, not retrofitted into the desktop batch |
| Strict Clippy | Independent desktop: all workspace targets/features, exit 0; GitHub full-PQ job: Node library/tests/all features, exit 0 | Preserve the different command scopes |
| Actual workspace semantic registry | Four architecture/head-or-merge lanes each execute the same 65 named controls: 60 semantics, 4 CPU/exit, 1 growth | All 25 postwrite controls execute; four repeated lanes are not 260 different tests |
| Four original ignored cost controls | History 64 complete calls; authentication 512 samples; root 408 observations; M06 216 timed samples and 1,728 bindings | All four exact controls and original readers pass under original parameters; samples are not test counts or quantum-economic qualification |

The f85 desktop source remains exactly 10,748 tracked entries and 1,031,966,791
bytes before and after the whole batch. Its original provider, profiles,
Cargo-advertised executable identities, process groups and raw logs are retained.
The complete GitHub PQ artifact has 107 original command receipts with matched
source/log/exit records and 310 indexed members. Its text artifact does not
contain Node/M06 ELF bytes, and three cost controls lack individual ELF SHA
receipts. The authentication cost report includes its actual binary SHA. Those
limits are retained rather than described as independent rehashing of all four
executables.

All four CPQ1 architecture/head-or-merge positions also have original source-bound
readback: the same 32 cases, 352 measurement rows and 64 samples per row in each
lane. The exact original reader reproduces the saved output byte for byte, and
the original 25 negative reader controls execute in each lane. These finite
observations do not establish quantum work or fork-economic security.

Four actual independent-C lanes also retain 20 fixed-seed signature comparisons,
391 C and 396 Rust verification observations per lane, including the 210-vector
Wycheproof corpus. Uploaded C executables were rehashed; the Rust oracle identity
comes from its original execution record. Four actual SDK lanes each retain 18
metadata pairs and 66 SDK plus 66 Rust verification observations. Five signatures
valid to the SDK exceed the product scope and are rejected by Rust. These checks
do not establish generic ML-DSA dispatch, a full TUF updater or final-use authority.
The SDK's cryptography/OpenSSL provider is distinct from the Node TLS provider;
its exact-version install report is not installation-time hash enforcement.

### Later expiry-accounting candidate ebd

Independent review found an observation gap: a stage can cross its original
deadline after the reactor's outer scan and refuse at an inner check, while the
generic error owner omits the expiry counters. This finding is separate from the
unresolved desktop FAILED progress row.

The correction preserves the original terminal error, pending closure, generic
errors and connection removal. Only an exact deadline/cookie error observed after
the original connection deadline can add an expiry count. A monotonic stop takes
precedence for deadline errors so a delayed error handler does not recategorize
an earlier shutdown. This is conservative observation, not reconstruction of
every concurrent shutdown/expiry ordering.

The original real-socket test is byte-for-byte unchanged. Four added controls use
real sockets, accepted-connection ownership, the original pending/cookie refusal
functions and actual removal/Drop. They check supported expiry, early shutdown,
EOF and cancellation, exact retained errors, one pending close, released
connection slots, unchanged deadlines and absent body/work effects. The
behavior-preserving helper-extraction red design was not executed; it is neither
an observed failure nor unmodified f85.

On committed ebd, 13 source gates have completed successfully, including 207
Python observations (104 CI-contract, 43 source-integrity, 38 corpus, 22 claim
guard). Every original command recorder verifies all 10,748 tracked entries and
1,031,980,491 bytes before and after. The native supplement completed with durable exit 1: 44 command/check
observations comprise 40 successes, one native failure and three blocked readers.
All ten R4 exact controls (four new and six retained) pass, as do their original
readers. The original History, root-digest and M06 cost controls each execute and
pass; strict Clippy for the whole workspace, all targets and all features also
returns zero. The complete tracked source is identical before and after, and
all owned process groups are reaped. The supplement does not repeat the full
Node library or the campaigns.

The authentication cost control records the native failure: Cargo exit 101,
zero passing and one failing exact test. Its original 512-sample export is
complete, with 67 unexpected outcomes/accounting observations and zero unknown
thread-CPU measurements. The original assertion at
`verifier_cache_tests.rs:437` fails. The original named-test reader and the two
dependent aggregate readers correctly remain blocked.

All 67 refusals occur in the sixteen-key-churn case and report
`PUBLIC_MUTATION_CPU_BUDGET`: 34 cached-arm and 33 original-arm samples.
The first refused sample is cached input 30, immediately after the 61st successful
timed call in that case. Each refused sample records zero additional charged
CPU, zero cache hits and zero key expansions. The other three cases conform to
their original expected outcomes, including the expected invalid signatures.

The unchanged owner has a cumulative two-second authentication thread-CPU budget
per case. Cookie signing, warm-up and both sampled arms share that owner. The
last admitted sample's accounting check rules out unavailable CPU measurement;
the source-bounded attempt and byte totals remain below their separate caps. The observed error and
unchanged control flow therefore identify the cumulative CPU gate as the refusal
point. These are refusals before verification and reservation, not 67 incorrect
cryptographic verification decisions or established product under-accounting.
The original cost acceptance condition remains unmet.

The raw timing rows do not separately export setup/warm-up CPU. Their sums are
not the entire case's accumulated charge. The passing f85 CI execution and this
failed ebd desktop execution differ in source, host and dynamically constructed
cookie/wire inputs, so they do not isolate why measured cost differs. The authentication implementation and the relevant
owner functions are unchanged; no evidence attributes this outcome to the R4
accounting correction. No budget is enlarged, sample removed, or failed run
replaced by a rerun.

### Later marker-contract composition ca4e2fb9

At final publication inspection, the actual target ref had advanced from 56897
to `513e92dfc27044ef3e0c9d62e7ae504fa5bea38f`, while the PR metadata still
reported the old base. The direct ref and exact Git object determine this scope.
The new target changes only the Python marker caller, two tests, their corpus
pins and six historical compatibility-evidence files. Both histories are kept.

The combined caller invokes `Marker.evaluate` once without the optional
`context` keyword. Actual fixed packaging 26.3 and the reviewed official 25.0
implementation default that parameter to `metadata`. The caller still supplies
the complete pinned environment and explicit empty/selected extra; marker
errors propagate without retry. Missing packaging and every version below 25.0
are still refused, including marker-free materials. The isolated 26.3 wheel,
hash enforcement and both CI installation paths are unchanged.

The original 23 and new target's 22 test-method sets have an exact 25-method
union. The effective-context control binds actual call arguments to the real
signature and applies its defaults. It also checks the real empty-extra metadata
behavior and preserves lock-file-only variable refusal. The new legacy-shaped
wrapper is a call-shape control on the supported installed library; it does not
authorize an actual 24.x verifier. The target's preserved historical 24.x success
logs describe that target's earlier contract, not this combined caller.

On this exact committed combined source, all 20 finite recorded commands pass:
207 source/CI/corpus/claim Python tests and 25 actual material-verifier tests,
six locked/offline dependency graphs, formatting, inventory, repository links,
truth and diff checks. The W1 graph sizes remain 69 / 193 / 306 / 191 / 191;
the main workspace graph has 175 packages. All command recorders and the batch
source-before/source-after observations agree on 10,754 tracked entries and
1,031,991,037 bytes. These are 232 Python test observations on this source;
they are not a cross-version total or native test executions.

Rust bodies, Cargo manifests/locks, workflows and native limits are unchanged
from ebd, but three changed corpus pins are compiled through the native source
inventory. No native Rust test, strict native Clippy, guest image or new proof
was executed for ca4e2fb9. The original f85 and ebd native failures, timings and
qualified component scopes therefore remain attached to those original commits.

Source: [combined verifier](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ca4e2fb9160d3e388e131624f7b3350ae4f5d56b/scripts/llm_runtime_release.py)
and [25-method controls](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/ca4e2fb9160d3e388e131624f7b3350ae4f5d56b/scripts/test_llm_runtime_release.py).
The exact recipe, raw logs, source identities, official-library readbacks and
independent reviews are retained in the terminal evidence increment.

### Business and operational gates remain unaccepted

The original four-second, six-depth service confirmation gate still refuses the
f85 source under its original worker and Host limits. A named native test
or process exit can pass while its independent confirmation reader correctly
rejects `CONFIRMATION_TARGET`; those are separate observations.

The original three-attempt, thirty-second native campaign also fails after a
successful release build. Each baseline confirms only one of three rounds; all
six pressure stages confirm zero of three and accept only seven of the required
21 work items. Final receiver/client states disagree. Accounting is available and
balance identity holds, but genuine paid-budget depletion is not observed in the
pressure stages. No actor cap/forced kill or outer startup timeout explains these
results.

The exact errors differ. The first two attempts and the third baseline reach
client History import and report `PUBLIC_REQUEST_DEADLINE`. The third attempt's
from-zero pressure ends at the challenge with `FRAME_DEADLINE`; its late-product
pressure ends at solution/body/response with `FRAME_DEADLINE`. Those two records
have no client-import entry. Missing import evidence is not successful import.
No supported, semantics-preserving small performance repair follows from these
reports alone. All original deadlines, workers and CPU/memory limits remain.

The original 4,105-block History control uses the classical public_v2 owner and
fails in all four architecture and head-or-merge positions. Both x64 servers reach their original 1,800-second
lifetime, after 3,325 and 2,799 completed returns respectively; the next History
request sees connection refusal. Both ARM runs record 4,104 successful import returns and receive a last-page
reply with `advertised_complete=true`, but the original import call reaches
its deadline with `PUBLIC_REQUEST_DEADLINE`. A final advertised page is not a
successfully confirmed client state. These are failures inside the original
control, not an outer command timeout. Their original host reports have no
recorded errors or OOM event; the 25%-CPU and 2-GiB configuration is unchanged.
No evidence attributes these four failures to the TLS constructor repair or the
later R4 accounting change.

The f85 CodeQL export also misses its observation deadline with empty
analysis/check collections. That is incomplete export evidence, not a reported
code finding and not a successful security scan. The final CI snapshot records
its timestamp and every unfinished or failed check explicitly.

At the frozen 2026-11-06 10:19:27 UTC cutoff, metadata shows 73 successful,
12 failed and one skipped check; workflow runs show ten successful, four failed
and one pending. The repository-truth baseline remains pending with zero jobs.
Its two CI lanes therefore provide no execution qualification for the packaging
fix, even though the separately source-bound local 23-test verifier run passed.
The readback covers 31 original jobs, 34 fully indexed artifacts (23,014 members)
and 4,319 losslessly retained text members. It verifies the full x64/head PQ
artifact; the other three full-PQ job successes are metadata only for their later
whole-library and cost phases. Earlier inspected stages remain explicitly partial.

## 4. Authority boundaries that remain open

| Surface | What exists at the tested source | Remaining acceptance condition |
| --- | --- | --- |
| Accounts and application authorization | Native pinned ML-DSA account/application owners, generations and nonce checks under explicit profiles | Complete legacy migration with prior PQ commitments and all production entrypoints bound to the intended profile |
| Parent recovery | Classical network-profile refusal before recovery work | A complete PQ parent-state recovery protocol and owner path |
| Node identity and private transport | Explicit loopback hybrid TLS with ML-DSA mutual identity and signer binding | Actual private listeners/clients, deployed certificate custody and revocation, malicious-handshake costs and sustained WAN qualification |
| Software/configuration release | M15 role quorums, root rotation, current-check kernel and bundle checks | A real final-use product consumer, atomic effect binding and a current independent checkpoint/time source |
| Cell release and activation | CPR2 current publisher checks, M15 manifest/activation rules and real Cell acquisition | Installation/CURRENT selection/activation boundary invoking current authorization; acquisition alone is insufficient |
| Recovery and rollback | Durable PNQ2 witness component and transactional current/CAS checks | Ordinary CLI witness wiring, protected independent custody and a domain that actually covers the stores being claimed |
| Finality | Nonactivating Ed25519 reference and read-only native certificate observation | A specified, implemented, tested PQ finality path and its real activation rules |
| PoN work and chain selection | Native work relation, finite strategy measurements and quantum/DAA research | Cheapest legal quantum work, reversible computation/data-access costs, difficulty and adversarial fork economics |

The PNQ2 witness protects exactly the resource, peer and request tables included
in its root. It does not cover account state, blocks, History, CURRENT or Hepta.
The M03 checkpoint daemon uses a different domain, root and wire contract.
Neither service can be substituted for the other. Restoring a local journal,
head and adjacent checkpoint file from one old snapshot cannot prove freshness.

The ordinary `pq-tls-serve` CLI still uses `open_with_pq_network` without an
independent witness. The library's ability to carry a witness-backed Node is a
component capability, not deployed CLI wiring or exclusive writer/recovery
qualification.

No statement in this report promotes classical-plus-PQ OR authentication, an
old valid signature, same-disk rollback metadata, a finite benchmark or a saved
proof to current production authorization.

## 5. Evidence and reproducibility

The frozen retained-history package contains 1,844 original files in 1,848 archive
members. Ten parts reconstruct the 14,283,750-byte zstd archive, SHA-256
`78142ab292525bcd911029ee07177bbad1630d74b512c0152125afbf0f89ab0f`.
It preserves the old failures and their original source identities. Its successful
verification means archive integrity and coverage; it is not a native-test verdict.

[Retained archive guide](retained/publication/README.md) and
[member/part index](retained/publication/archive-index.json) provide the exact
transport and review instructions. The terminal increment is separate so the
earlier snapshot is not silently rewritten into a successful final result.
The [terminal archive guide](terminal/publication/README.md) and
[terminal member/part index](terminal/publication/archive-index.json) preserve the
actual f85 and ebd outcomes, the later ca4e2fb9 Python/source gates, the fixed
CI cutoff, original failures, raw cost exports and independent readbacks. The separate index records its transport
hashes; this report is itself an archived member and does not embed a circular
hash of its containing archive.

The [source and publication map](source-publication-map.json) records all nine
local/server code-commit pairs and their independently checked identical trees. It
does not transfer executions between those commits. Documentation/archive-only
publication changes do not manufacture native results for the containing commit.
The [machine-readable disposition](qualification.json) keeps each pass, failure,
timeout and incomplete gate attached to its actual source and scope.

## 6. Disposition

The PR remains a reviewable draft. Original service deadlines, CPU and memory
quotas, worker counts, anti-downgrade rules, source-integrity checks and failed
observations remain intact. No protected-main merge or production activation is
performed as part of this continuation.

