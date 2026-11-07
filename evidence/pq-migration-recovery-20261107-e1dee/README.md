# Admitted PQ migration handoff and checkpoint recovery observations

Disposition: **HOLD / NO-GO** for running-network migration, whole-Node rollback,
independent production custody and whole-chain PQ acceptance. This continuation
adds an executable admitted-checkpoint handoff, fixes checkpoint endpoint
displacement, and retains an actual ROG/X230 recovery exercise. It continues
[the sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and the existing draft PR #723.

## Frozen sources and actual execution

| Role | Exact commit | Observation |
| --- | --- | --- |
| Supplied baseline | `840522d0b65b4989f1a2a1d09c0ad51af1a1956d` | Original checkpoint implementation. |
| Original implementation plus identical public regressions | `555d2e5bb338fa67d8b08f77f2bd86d68850fbf5` | Both regressions actually fail on ROG; preserved in the red bundle. |
| Endpoint fix, handoff and probe | `2058225aa0d50ca57b1eb0d5f520d7f4eefae69b` | Complete checkpoint package: 56 passed, zero failed/ignored. Actual two-host exercise. Initial Node migration attempt: 6 passed, 1 failed. |
| Correct PQ destination test owner | `37ef49311db7e62df1b152b8a7b0fc9104d56c17` | Node migration 7/7, M06 migration inventory 7/7 and strict all-workspace/all-targets/all-features Clippy pass. |
| Preserve concurrent migration controls and current CI base | `9fb011c4af1f9f54353207f9ad9fbc54ab6235e3` | Checkpoint 56/56, Node migration with all features 7/7, M06 inventory 7/7, three default-feature NPQ6 integration controls, exact execution readers and strict workspace Clippy all pass. |
| Preserve concurrent M15 production fixes and rerun | `2c51e15e5b4f57b133b53cc9c386431e29563db5` | Original 73 executions plus both complete seven-test M15 modules: 87/87, all three execution readers and strict workspace Clippy pass. |

The public regression test blob is identical on red and green:
`623013c6d93589d120b9b6eec58698f60156294c`. The original checkpoint production
source is unchanged in the red commit. The checkpoint implementation, its public
tests and probe are unchanged between `2058225` and `37ef493`; `9fb011c` preserves
the same component blobs.
[The source map](source-map.json) records those comparisons. The later evidence
publication is not described as another native execution.

The 56 checkpoint executions comprise library 18, binary 15, cold recovery 15,
cross process 6 and socket ownership 2. The example's zero-test harness is not
counted. Python checks on `37ef493` pass 43 source-integrity, 38 PQ integration,
22 HOLD-guard and 9 provider-CI tests: 112 total. Repository/link checks, all
692 pinned blobs, the embedded source inventory, the locked offline Cargo graph
and workspace formatting also pass. Source checks do not qualify runtime effects.

Before publication PR #723 advanced concurrently to `f943c23b`. Its seven
commits add three NPQ6 integration controls, repair the reviewed legacy schema
reader and retain their original evidence. The updated PR base `0ca272d0` changes
two Python shard files while preserving the original combined test inventory.
Both histories are retained as ancestors of `9fb011c4`; neither is replaced.
The two conflicting workflow/corpus files retain both complete CI additions and
all required paths. The integrated corpus has 694 exact pins, all acceptance
flags remain false, and the six migration/recovery component files in the source
map are byte-identical to `37ef493`. The concurrent component's original
[execution record](../pq-boundary-followthrough-20261107/README.md) remains intact.
On the clean integrated source, the original 112 Python executions and all nine
source/graph/format/link commands pass again. Additional suites pass public
readiness 71/71, Rust baseline shards 9/9, CI execution 77/77 and CI contracts
104/104; the CI contract checker also passes. These suites import overlapping
controls, so their totals are not combined into a distinct-control count.
The publication check later observed concurrent merge `dfffc5b2`, which only
retained the same `0ca272d0` base. Merge `b35b6a7c` preserves that history and has
the **identical entire tracked tree** as the executed `9fb011c4`; no new native
execution is claimed for that history-only commit. Evidence candidate `b0dadfdc` added the first complete evidence set and updated
the sole plan without changing code or CI. Its publication attempt later stopped
before checkout fast-forward, preflight, dry-run or push when the remote branch
advanced again to `1c14fab4`; the complete stop and transport receipts are retained.

That advance contains the `a676947a` M15 canonical role-key decoder fix and the
`1c14fab4` sealed-object test correction. Merge `2c51e15e` preserves both commits
and the entire earlier evidence history. Its tree is
`3f62762d719765b920cb7c7f1c1621440f98818e`. The only changed production Rust file
relative to `9fb011c4` is `release_owner/proof_wire.rs`; the six migration/recovery
component files, Cargo graph and CI implementation retain their prior bytes.
The existing canonical wire spelling, complete-root checks and sealed metadata
identity guards remain required. This is a real production-source change, so
the earlier 73 native executions are not relabeled as executions of this merge.

A new native run on exact `2c51e15e` completes all 87 test executions: checkpoint
56, all-features Node migration 7, M06 inventory 7, default-feature integration 3,
root-separation 7 and sealed-object 7. All three actual-execution readers and
strict workspace/all-targets/all-features Clippy pass. The 35 original command
receipts and final complete record retain this exact source. The job terminates
successfully with complete durable output and no timeout, cancellation or
automatic retry. Its complete receipt is 35,642 bytes, SHA-256
`e7f9fca25ca1fe266818145ff28eaabfb406d3d14b4b06dc26b0374340d1762e`.
The earlier 11 `9fb011c4` ELF bodies are independently retained before reusing the
build cache; the original source checkouts and evidence records remain unchanged.

On clean `2c51e15e`, the source suites again pass 43/38/22/9 executions, and
public readiness, baseline shards, CI execution and CI contracts pass 71/9/77/104.
The 16 local command receipts retain identical source before/after, complete log
bytes and verified hashes. The 694 source pins, inventory, repository links,
locked-offline Cargo graph, formatting and CI contract checker also pass. These
Python suite counts still overlap; they are not summed as unique controls.

The final containing evidence commit updates only the evidence directory and
the sole development plan relative to the newly executed frozen source; no
additional native execution is claimed for that evidence-only publication.

### Concurrent M15 proof and sealed-object controls

The new role decoder accepts only the existing role-key strings `1` through `4`
and refuses aliases, unknown codes and duplicates at the typed proof boundaries.
The existing kernel still requires the complete role set and its key/threshold
constraints; the codec still requires exact canonical re-encoding. The sealed
production implementation is unchanged. Its tests now distinguish immutable
bytes from metadata identity: rejected writes may still change Linux timestamps,
and a changed identity must refuse read, copy, descriptor and exec handoff without
refreshing the retained pin. The two complete affected modules each contain seven
tests. These controls do not qualify a complete M15 launcher, CURRENT, FinalUse,
external effects or a production recovery deployment.

## Admitted source handoff

`Node::prepare_pq_migration_checkpoint` reads the retained admitted header,
packet, trace and complete checked State in one SQLite read transaction. It
constructs the inventory and the existing M06 migration anchor from that same
snapshot. A nonzero exact prior PQ-registry commitment is a separate required
input. No fresh classical signature establishes that prior binding.
The caller must independently authenticate and retain the source checkpoint and
prior registry. Matching a digest does not prove historical account ownership
or when its binding was established.

The fixture defines its restricted source genesis before creating any store. It
admits actual transfer and task-escrow commands, retains the complete admitted
source state, and compares balances, nonce floors, task obligations, immature
rewards and total issuance. Both flat and authenticated **source** backends are
covered. The destination uses the existing PQ network owner; its ordinary and
authenticated openers must reject NPQ6 without creating a database.

The initial ROG failure was an incorrect test opener:
`PQ_ACCOUNT_REQUIRES_PQ_NETWORK_OWNER`. The correction uses the existing
settings-bound `PqNetworkPolicy`, `open_with_pq_network`, and strict
`open_existing_with_pq_network`. It does not weaken a production guard. The
prior/next PQ CLAIM signatures, wrong prior signer, stale nonce, rejected source
classical transaction, state assertions, admission, activation, repeated-claim
refusal and original search budget remain in the test.

Ordinary source `work:*` and other unsupported rights still return
`PQ2_UNSUPPORTED_SOURCE_STATE`, including zero-balance rows. No admitted source
row is deleted or projected away. The new API does not establish source finality,
binding time, an exclusive source cutover, source asset locking or retirement.
Those remain prerequisites for a running-network migration.
The concurrently added integration positives use an explicitly trusted synthetic
source checkpoint and actual destination Node/W1 execution. Their third control
refuses unsupported state from a real admitted legacy source. They complement
the admitted-source handoff; all three are not represented as live-source migration.

## Checkpoint endpoint ownership

The original public regressions observe two actual failures: a rejected
nonprivate-parent startup removes an existing listener path, and another admitted
journal replaces a live endpoint. These are native Unix failures, not mocked
return values or an environment-only inability to bind.

Startup now checks the private socket parent before creating the endpoint lease
or removing/rebinding a socket. A separate exclusive `socket-owner-v1` lease has
a bounded versioned `TRNMCSL1` record binding the exact socket identity. Only the
exact stale socket previously owned by that lease can be removed. Unknown or
unleased sockets require reconciliation. Parent, lease, socket and bounded lease
contents are rechecked after the request is read and before journal operations;
same-inode lease rewrites are rejected. The lease supplies endpoint ownership,
not an independent freshness authority.

## Two actual hosts and the coherent-old-world counterexample

ROG executes the retained real checkpoint-owner probe; X230 retains its fresh
84-byte complete journal checkpoint in a new private namespace. The X230 file and
parent are fsynced. ROG's complete declared test namespace is restored from the
old snapshot: journal, head, lock and local pin. The fresh pin is then read back
from X230 and returned to ROG. The root reviewer independently reads both host
files and verifies identical bytes and SHA-256:
`6b1cbc4afafca25b15c40e849f827a387c3a1354be338494f1d2d7fe600e54d3`.

| Actual control | Exit | Observed result |
| --- | --- | --- |
| Restored old namespace plus returned fresh X230 pin | 1 | Refused: complete external checkpoint mismatch. |
| Retained current namespace plus returned fresh pin | 0 | Accepted at record count 2. |
| Valid alternate history with its own pin | 0 | Accepted at record count 2. |
| Current history plus alternate count-2 pin with a different root | 1 | Refused: complete external checkpoint mismatch. |
| Current history plus old count-1 local pin | 1 | Refused: complete external checkpoint mismatch. |
| Returned fresh pin temporarily withheld | 1 | Refused: independent input missing. |
| Restored old namespace before any fresh pin is returned | 1 | Refused: independent input missing. |
| Restored old namespace plus co-restored old local pin | 0 | **Accepted at record count 1: preserved counterexample.** |

Each refusal leaves the restored declared files unchanged. The missing-input
controls withhold a local input; they are not WAN partition or remote-service
outage tests. The two missing-input invocations are not two distinct business
security capabilities. Exact chronological receipts and original command logs
are retained in the archives and [two-host result](two-host-result.json).

The retained probe is 6,038,872 bytes, SHA-256
`8151dfced4ed72986279e6bb4404dd9ac96ff0b1ef3ddbe40e62aff249395b70`.
Its fields are explicitly synthetic. It exercises the real journal owner, not a
complete Node database, real account balances, revocation, CURRENT, FinalUse or
an external effect adapter. ROG and X230 are distinct observed machines; this
does not prove independent administration, separate power/backup custody,
physical power-loss recovery or the required sustained WAN qualification.
An independent custodian must also retain the latest frontier required for the
business effects being protected. This one-time export/restore exercise does not
deliver an external synchronization before every CAS or effect.

## Retained failures and reproducibility

The archives retain the two original socket failures; local Unix-bind EPERM;
the missing-cache attempts; two local Node compiler SIGKILLs before tests ran;
the cancelled check; the zero-test wrong-filter attempt; and the ROG 6/1 migration
attempt. The first local Node attempt retains only its actual terminal excerpt,
not an invented complete build log. A corrected result does not erase these
observations or the older TLS/full-Node failures already attached to PR #723.
Integrated preparation also retains the upload admission-capacity refusal
(no child submitted) and the first bundle-verification failure for missing
shallow-clone prerequisite `513e92df`. That attempt did not fetch or fast-forward
the source and executed zero integrated tests. These are not recast as native
test failures or successful executions.
The second `9fb011c4` integration attempt obtains its real missing prerequisite
through a normal exact fetch from the canonical origin. The unchanged bundle verifies,
the source fast-forwards normally, and the original native gates complete.
No shallow metadata or ancestor is fabricated.

The first `2c51e15e` preparation also stops before tests: the shallow source
causes Git to ignore local-clone sharing, so the new checkout lacks the imported
but unadvertised `b0dadfdc` object. Its clean HEAD remains `9fb011c4`; zero tests
execute. The complete 11 prior ELF bodies were independently copied, fsynced and
verified before that stop, and those copies remain retained.

The second `2c51e15e` preparation verifies the already retained `b0dadfdc` bundle,
imports it with ordinary Git, and normally fetches exact `1c14fab4` from the local
publication repository. The unchanged 1,179-byte reintegration bundle then
verifies and fast-forwards the new checkout to exact `2c51e15e`. The prior 11 ELF
copies are referenced and rehashed, not recreated or replaced. The original
`2058225` and `9fb011c4` checkouts remain unchanged.
 The publication expected-head
guard also stops on the concurrent branch advance before preflight or push;
the controller interpretation distinguishes its planned flags from executed work.

ROG validation commands retain Rust 1.95.0, the original Cargo profiles, jobs 2,
`--locked --offline`, single-threaded libtest and the pinned OpenSSL 3.5.9
provider. Validation commands using `record_pq_native_command.py` bind exact
tracked source before and after; preparation and transport have separate receipts.
Native executable identities are retained and rehashed on the executing host.
Executable bodies are retained there; the text archives do not contain them,
and readback reviewers do not claim to have locally hashed those binary bodies.
The optional counted-SQLite I/O boundary remains UNQUALIFIED in these runs.
A local publication-route probe passes preflight but its dry-run cannot obtain
Git credentials with terminal prompts disabled, and stops before pre-push. It
attempts no actual push and is not a native-test failure; the existing remote
publication route remains selected.

| Evidence archive | Payload members | Contents |
| --- | ---: | --- |
| [native-recovery-2058225.tar.gz](native-recovery-2058225.tar.gz) | 143 | Original red failures, initial green/failed Node observations, two-host inputs and recovery commands. |
| [native-migration-37ef493.tar.gz](native-migration-37ef493.tar.gz) | 56 | Corrected Node/M06 migration tests, Clippy and exact source/ELF records. |
| [native-integrated-9fb011c.tar.gz](native-integrated-9fb011c.tar.gz) | 116 | Integrated 73 native test executions, Clippy, original failed preparation and the exact prerequisite repair. |
| [local-validation.tar.gz](local-validation.tar.gz) | 77 | Earlier local failures, source checks on 2058225/37ef493 and preparatory controls. |
| [integrated-local-validation.tar.gz](integrated-local-validation.tar.gz) | 40 | Exact 9fb011c source checks and the schema/CI/shard suites. |
| [readbacks-and-controller-records.tar.gz](readbacks-and-controller-records.tar.gz) | 71 | Independent readbacks, archive review, original controller records and publication preparation. |
| [reintegrated-local-validation.tar.gz](reintegrated-local-validation.tar.gz) | 80 | Exact `2c51e15e` local suites, source identities and log verification; earlier `b0dadfdc` evidence-candidate checks. |
| [publication-stopped-before-1c14.tar.gz](publication-stopped-before-1c14.tar.gz) | 21 | Original transport and expected-head stop before checkout fast-forward, preflight, dry-run or push. |
| [native-reintegrated-2c51e15.tar.gz](native-reintegrated-2c51e15.tar.gz) | 166 | Exact `2c51e15e` 87-test run, strict Clippy, unchanged prior ELF custody and original zero-test preparation failure. |
| [reintegrated-readbacks-and-controller.tar.gz](reintegrated-readbacks-and-controller.tar.gz) | 10 | Independent complete/terminal readbacks, all-member/command review, ELF-record review and local publication-route refusal. |

Each payload count excludes its manifest. [artifact-index.json](artifact-index.json)
records archive lengths and SHA-256; [SHA256SUMS](SHA256SUMS) also covers the
human-readable report, source map, qualification, exact two-host result and
[recovery-red.bundle](recovery-red.bundle).

The remote archive's `x230-custody-receipt.json` is a decoded controller copy.
Its nanosecond timestamp was rounded by JavaScript integer precision; the pin,
fsync and host facts are unchanged. The root readback archive separately retains
the exact 815-byte X230 `records/custody-fsync.json` (SHA-256
`e572f6f146f02b771155706ba6ee90d8f4206910da977f0b267248c649a4837a`),
the raw controller receipt and the explicit comparison. Chronology uses the
original record. The derived copy is not represented as a byte-identical original.

Run `sha256sum -c SHA256SUMS` in this directory to check the delivered files.
Each archive contains a member manifest with full byte lengths and SHA-256.
The red regression bundle requires the baseline commit and can be inspected
with `git bundle verify recovery-red.bundle` in a clone that has that baseline.
It is retained as evidence rather than published as a separate rollout branch.

The machine-readable [qualification record](qualification.json) keeps all
running-network, whole-Node, independent production custody, whole-chain and
activation claims false. Complete supported source-state import/retirement,
independently established old-account bindings, whole-effect monotonic recovery,
independent custody and physical/WAN acceptance remain open. The generic Unix
checkpoint client's absolute deadline also remains separate unfinished work.
