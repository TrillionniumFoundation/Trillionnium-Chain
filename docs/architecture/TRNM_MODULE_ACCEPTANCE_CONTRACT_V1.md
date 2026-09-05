# Module documentation and acceptance contract v1

Status: candidate technical contract; not a development plan or activation record.
Primary module: M17. Consumers: M00-M16, module maintainers and release reviewers.

The execution order remains exclusively in
[`../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
This contract clarifies the meaning of the existing module coverage result. It
creates no second roadmap, delivery sequence, claimed completion, or release authority.

## Distinct acceptance facts

| Fact | Required evidence | Does not imply |
|---|---|---|
| Structural documentation coverage | unique source ownership, visible sections, contained paths, exact owner tokens, declared graph validation | detailed design adequacy or implemented behavior |
| Detailed design accepted | versioned interfaces, state machine, failures, recovery, limits, SLO definitions, test/invariant mapping, producer and consumer review | executable node integration |
| Scoped implementation accepted | unchanged exact-source tests, mutation controls, consumer replay, applicable independent review | protected-main integration or release readiness |
| Integration verified | protected merge and post-merge replay on that exact source | approved deployment or activation |
| Release qualified | applicable authentic external evidence, artifact/custody provenance, security and operator review | permission to activate a network |
| Network activation authorized | signed governance record bound to the accepted release and explicit activation boundary | retroactive approval of other sources or networks |

No state is inferred solely from the existence of a file, crate, test label,
SLO label, queue entry, green schema validator, or a prior commit's CI result.
`not-assessed` is not `accepted`; `candidate` is not `production`.

## Coverage report compatibility and meaning

`check_module_coverage_v1.py` retains its report schema ID and `result` field.
A `PASS` means structural source/documentation checks passed. Its deprecated
`technical_sections_semantically_checked` field is explicitly false; consumers
must not use that historical overstatement to infer technical acceptance.
`technical_sections_structurally_checked` is the precise replacement.
`detailed_design_acceptance` and `implementation_acceptance` remain `not-assessed`.
`production_authority` remains false.

Per-module `test_roots_explicit` and `evidence_roots_explicit` reveal whether a
module used its own roots or a repository-level fallback. A shared `scripts/ci`
or `docs/evidence` directory is valid navigation, but is not a module testkit,
proof of successful tests, or a signed evidence submission.

The reported dependency graph is the declared module graph. Static manifest
resolution, locked Cargo feature resolution, compiler acceptance and production
closure contamination checks remain separate required controls. An acyclic
registry cannot prove an acyclic actual dependency closure.

## Structural false-pass rules

Paths must be existing canonical repository-relative POSIX paths. Absolute and
Windows paths, parent/dot traversal, repeated separators, broken or escaping
symlinks and special filesystem objects are rejected. Internal compatibility
symlinks are permitted only when their resolved targets remain in the repository.
Workspace and external-contract members must remain inside their own workspace;
a member's Cargo manifest must remain inside the repository.

A module heading must be a real, visible level-two heading. Duplicate headings
are rejected rather than silently overwritten. Fenced examples and HTML comments
do not satisfy headings, mandatory markers, crate references or minimum prose
length. A peer level-two footer terminates the final module; its text cannot be
borrowed to make M17 appear documented.

CODEOWNERS checks use exact owner tokens from active rules. Commented handles,
username prefixes and standalone owner text are not membership evidence. This
check does not establish effective per-path ownership, provisioned module teams,
review eligibility, independent reviewers or two approved reviews.

These checks validate a stable checkout; they are not descriptor-pinned runtime
filesystem authority, a Markdown rendering security boundary or a semantic
proof of design correctness.

## Detailed design review inputs

A detailed module design must identify the following by exact source and version:

| Input | Required review material |
|---|---|
| Scope and authority | owned decisions, forbidden authority, producer and consumer boundaries |
| Wire/interface | typed request/response, field bounds, canonical bytes, errors, version compatibility |
| State machine | legal and rejected transitions, preconditions, expected revision, write set and terminal states |
| Idempotency | identity, replay response, expiry, nonce/budget effects and uncertain-acknowledgement behavior |
| Durability | durable barrier before each external effect, authoritative store, projections and restart cut table |
| Security | attacker capabilities, trust assumptions, key policy, abuse budgets and retained negative controls |
| SLO | unit, workload, resource/hardware scope, percentile denominator, threshold, measurement command and acceptance owner |
| Testkit | executable command and exact test selector for each invariant and relevant failure class |
| Operations | metrics, stale/error signals, recovery steps, rollback limits and operator escalation |
| Acceptance | source/tree, review role and independence, immutable raw evidence, known gaps and invalidation set |

Safety thresholds such as zero conflicting finalizations, zero duplicate debit,
zero signature-watermark regression and exact replay-root equality are distinct
from workload-specific latency or goodput targets. Performance thresholds must
be selected with a stated workload and hardware profile, not invented solely to
fill a table. A missing measured or approved threshold remains an open review item.

## Review, merge and activation ordering

Readiness for scoped source review requires unchanged exact-head and
prospective-merge checks plus applicable independent module, consumer and
security review. All existing protected-branch rules continue to apply.
Post-merge verification is necessarily performed after the protected merge;
it cannot be a prerequisite for creating or reviewing that same merge.

A non-activating source change may be reviewed independently of a later release
ceremony. It must preserve every relevant false production/testnet/release flag,
may not weaken an external-evidence requirement, and may not import candidate or
lab authority into a production closure. This does not waive external evidence
required for the particular behavior under review.

Release and network activation require their own applicable authentic evidence
and authorization. Hardware signing, an independently controlled monotonic
anchor, multi-host faults, physical power interruption, independent audits and
wall-clock soak campaigns cannot be established by these structural tests.

## Reproducible regression entry points

```bash
python3 scripts/ci/test_module_coverage_guard_v1.py
python3 scripts/ci/check_module_coverage_v1.py
```

The first command runs retained synthetic mutants, including the real coverage
entry point against a fixture. The second inspects the actual checkout. These
are different evidence scopes and must be recorded separately. The
`repository-truth` job in the existing `trnm-required-baseline` workflow runs
retained mutants and explicit head and prospective-merge regressions for pull
requests. Push/dispatch checks the event source and reports prospective merge as
not applicable. Diagnostic source archives contain only exact tracked source and
are not test acceptance. The job uses the already approved read-only hosted trust
class and retains the five stable required check names and existing gates. No
runner-policy exemption, actor allowlist expansion or write permission is added.

## Source-bound test execution

Primary module: M17. Consumers: every required-baseline package.
A Cargo target inventory binds each observed package, manifest, lockfile and
entry-point source to the clean exact Git head before execution. It is a
source-accounting control, not proof of target completeness, test success or
independent acceptance. A missing or foreign target is an error, not authority
to invent a test with a name copied from an unrelated log.

Every package process has a deadline. Parent exit zero is not success while a
child process group or output pipe remains alive, or when output collection
fails. Cleanup addresses the launched process group after leader exit as well.
This is not containment of descendants which deliberately create a new session.
Logs retain failed results and summaries must not turn timeout, skipped steps,
ignored tests or a missing toolchain into success.

The test profile optimizes only the pinned curve25519-dalek, ed25519-dalek and
sha2 dependencies. Debug assertions and integer overflow checks remain enabled
for each; workspace code keeps the default unoptimized test profile. This
addresses repeated cryptographic verification cost without changing any vector,
quorum, safety assertion, test selection, deadline or long-horizon campaign.
Performance improvement is a hypothesis until measured on the actual run; this
configuration is not benchmark evidence or production build qualification.

The external-watermark socket-replacement regression accepts connection refusal
only at the original listener, because a prior request's post-check may already
have terminated the daemon. It still requires rejection at the replacement
socket, a bounded non-success exit of the exact original process and unchanged
authority journal bytes. Other connection errors remain failures.

Full unified-workspace and per-package logs are retained as exact-source
diagnostic artifacts even when the command fails. Each execution binds commit,
tree and command before starting. Shell pipefail preserves both test and log
writer failures. A downloaded log is evidence of its own command/source only;
artifact upload success cannot turn the failed gate into acceptance.

The external contract workspace has a separately selected source inventory,
manifest and lockfile binding. Its compile/test/Clippy output and the later strict
boundary Clippy output are retained even on failure, with exact source commit
and tree. An error naming a package absent from that inventory is unresolved
source provenance, not grounds to invent or patch that package. These diagnostic
artifacts do not provide independent review or override a failed command.

### Inventory checkout and path identity

Primary module: M17. Consumers: both explicit Cargo workspaces.
The selected workspace must be its canonical path, not an alias of another
workspace. Declared members are unique canonical repository-relative POSIX paths
contained in that selected workspace. Duplicate declarations, absolute paths,
dot/parent traversal, repeated separators, and member or manifest symlink aliases
are rejected. This is stricter than documentation-navigation compatibility links:
Cargo manifests and target entry points must identify their exact tracked paths.
An ignored alias of a tracked source is not itself a tracked source.

All blob and tree lookups use the captured commit, not a moving HEAD. The final
checkpoint requires both the same HEAD and a clean working tree. These checks
reject observed checkout movement and late source mutation; they do not lock the
filesystem or defend against a concurrent actor that changes and restores state
between observations. Qualification still requires an isolated, immutable
checkout. The inventory does not prove target completeness or test acceptance.

The retained inventory regression suite includes real Git fixtures for duplicate
members, noncanonical member spellings, workspace escapes, member/manifest and
ignored-entry symlink aliases, workspace substitution, a commit created during
inventory, and a tracked source changed after its blob was checked. Positive
controls for both supported workspaces remain. Run:

```bash
python3 scripts/ci/test_cargo_source_inventory_v1.py
```

The native execution sync-fault and lazy corpus-mutation fixtures are test-only
consumers of source-bound qualification. Distinct database paths must not compete
for a single injected-fault slot. A duplicate arm for the same path must reject
without clearing the first owner, and dropping an older guard must not disarm a
newer owner after consumption. Unwinding must clear only its own pending fault;
worker rendezvous must be bounded even if a worker panics.

A signature-tamper fixture must alter a byte, verify that altered byte was written,
and require rejection before restoring the original bytes and requiring the
original valid read result. Writing a fixed byte into random signature data does
not guarantee a mutation. These fixture contracts neither change production
signing/storage behavior nor substitute for executable Rust and consumer replay.
