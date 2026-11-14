# Native root and recovery V3: execution and retained observations

Status: **HOLD / RESEARCH ONLY**. This record accompanies
[PR #826](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/826),
stacked on [PR #813](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/813).
It records actual local component execution, exact source identity and remaining
qualification limits. No deployed root, production key, running service or
protected-main ref was changed.

## Exact source and result

The second local campaign executed **35/35 commands successfully** at commit
`a44344b25d12328fedd883a335585f03d059060b`, tree
`8b294a266c4198fd0a9acd1c3024685f5f333227`.
Both complete source checks verified **11,347 tracked entries / 1,117,628,403 bytes**
and produced identical records. The four mandatory native V3 selectors executed
**50 tests**, with zero failures, ignored or measured tests. Unrelated filtered
tests are reported separately in their selector observations.

The source evidence is in [source-before](attempt-a44344b2/source-before.json),
[source-after](attempt-a44344b2/source-after.json), the
[35 exact commands and log hashes](attempt-a44344b2/commands.json),
[campaign summary](attempt-a44344b2/summary.json), and the
[native selector summary](attempt-a44344b2/native-v3/summary.json).
The [qualification record](qualification-record.json) collects the observations
without turning unknown bounds into numeric estimates. A later commit containing
this evidence and the plan note is a delivery commit; it is not the source that
executed these native tests.

| Executed scope | Observed result | Retained record |
| --- | --- | --- |
| V3 crypto structure | 10 passed | [log](attempt-a44344b2/native-v3/crypto-structure.log.gz) |
| V3 actual crypto backends | 8 passed | [log](attempt-a44344b2/native-v3/crypto-native.log.gz) |
| V3 root authorization kernel | 12 passed | [log](attempt-a44344b2/native-v3/root-kernel.log.gz) |
| V3 durable native owner | 20 passed | [log](attempt-a44344b2/native-v3/root-owner.log.gz) |
| V2 actual signatures | 14 passed | [log](attempt-a44344b2/v2-signature-native.log) |
| V2 actual provider readback | 6 passed | [log](attempt-a44344b2/v2-provider-native.log) |
| V2 actual journal/reconciliation | 14 passed | [log](attempt-a44344b2/v2-journal-native.log) |
| Default crypto library | 175 passed | [log](attempt-a44344b2/retained-crypto-default.log.gz) |
| Default release library | 43 passed | [log](attempt-a44344b2/retained-release-default.log.gz) |
| Lifetime contract controls | 58 passed | [log](attempt-a44344b2/lifetime-controls.log) |
| New dependency register controls | 41 passed | [log](attempt-a44344b2/dependency-controls.log) |
| Native runner refusal controls | 11 passed | [log](attempt-a44344b2/native-runner-controls.log) |
| Existing authority register controls | 18 passed | [log](attempt-a44344b2/authority-controls.log) |
| CI contract / source integrity / PQ source controls | 108 / 43 / 55 passed | [CI](attempt-a44344b2/ci-contract-controls.log), [integrity](attempt-a44344b2/source-integrity-controls.log), [PQ source](attempt-a44344b2/pq-source-controls.log) |
| Whole-chain claim guard | 49 passed | [log](attempt-a44344b2/claim-controls.log) |
| V1 policy / V2 signature and provider structure | 26 / 17 / 15 passed | [policy](attempt-a44344b2/v2-policy.log), [signature](attempt-a44344b2/v2-signature-structure.log), [provider](attempt-a44344b2/v2-provider-structure.log) |
| Whole-workspace, all-target, all-feature Clippy | Passed with `-D warnings` | [log](attempt-a44344b2/workspace-clippy.log) |

The **175 default crypto tests already include the 10 V3 structural tests**.
The numbers above must not be added as a count of independent security properties.
Python parser/source controls are not actual native signature execution.

The same campaign passed locked Cargo metadata for default, all-feature and fuzz
graphs; workspace formatting; source inventory; implementation summary; the
753-blob PQ source corpus; and repository links. The
[repository check](attempt-a44344b2/repository-links.log) observed 3,799 local
links, 1,294 Rust files and 26 workspace packages at the tested source.
**The full protocol lane and full workspace test suite were not executed by this
local campaign.** Existing Host, large-state, network and other original gates
remain separate requirements. Full-workspace Clippy is not full-workspace tests.

## Implemented candidate boundary

The [native V3 contract](../../docs/security/PQ_ROOT_RECOVERY_NATIVE_V3.md)
describes the reusable implementation:

- Every ordinary authorization, rotation, revocation, recovery and policy change
  verifies exactly two ML-DSA-87 and two SLH-DSA-SHA2-256s approvals under a fixed
  three-key-per-family roster. Exact DER/OID binding rejects suite aliases;
  backend errors do not weaken the AND policy.
- Rotation, recovery and policy changes also require six separate successor
  proofs of possession, bound to the full transition and successor roster.
  Semantic operation identity is independent of the chosen quorum/signature bytes.
- Canonical complete statements bind scope, generation, predecessor, sequence,
  nonce, exclusive Unix validity and intent. Nonces and revocations survive
  generations. Expired-policy recovery still requires both current quorums.
- The native SQLite owner replays original signed evidence, persists pending
  state before external CAS, authenticates separately enrolled writer and anchor
  roles, and fences uncertain results. Only explicit, fresh, exact-target
  reconciliation can complete an uncertain pending operation.
- Budget identity and absolute deadlines survive callbacks. Explicit cancellation
  and observed external cancellation latch permanently; clearing an external
  alias cannot restore permission. A signal that is set and cleared entirely
  between observations is not detectable.

These observations use generated research keys and same-process anchor fixtures.
Signed object/callback boundaries do not demonstrate a separate anchor process. They do
not establish independently administered people, devices, backups, recovery
procedures or an independently durable WAN anchor. The fixture deliberately
retains the **accepted counterexample when the owner and all anchor states are
restored together**. Restoring only the owner while an external head remains
advanced is refused. Passing the counterexample test records the unresolved
threat; it does not mean that simultaneous rollback was prevented.

The returned current-intent observation is not an M15 effect-entry or FinalUse
capability. Native provider schemas, actual payment/API/resource adapters,
production release selection and an end-to-end original-budget handoff remain
unwired. V2 provider reconciliation is a separately tested research component.
Root state rollback cannot itself undo an external effect.

## Earlier failures remain evidence

The first frozen campaign used commit
`1f7ff4106f14e5b514d95a9faf2c5eea1233aea5`, tree
`c54c11c505b2b9f5b8d3c8105491ca5d26390122`. It ended **29/35**, with unchanged
complete source. The [first summary](attempt-1f7ff410/summary.json),
[commands](attempt-1f7ff410/commands.json), native subcommand logs and all other
raw output remain retained. Later successes do not change these exit codes.

| First-campaign failure | Recorded cause | Correction before the second campaign |
| --- | --- | --- |
| Authority controls exit 1; register exit 2 | The new one-line crypto module export no longer matched the old curated source pin | Review all 44 source entries; update the one changed export pin and declared revision; retain the seven-route scope and old lock history |
| V3 runner exit 1 | First three Cargo subcommands exited 101 with explicit `No space left on device (os error 28)`; the owner selector still passed 20 tests | Remove only task-owned reconstructible build caches; retain the failure logs; rerun from a new exact source |
| Three V2 native suites exit 5 each | `OPENSSL_DIR` was unset, so native binding refused and ran zero tests | Supply the actual `/usr` prefix alongside the pinned binary and system library/include paths |

The [cache recovery](cache-recovery.json) and
[duplicate worktree recovery](worktree-recovery.json) records identify the
reconstructible data removed. The original harness is
[run_campaign.py](run_campaign.py); the corrected recorded invocation is
[run_campaign_v2.py](run_campaign_v2.py). These are session-path-bound experiment
records. For a portable native V3 invocation, use the repository's
[mandatory runner](../../scripts/ci/run_pq_root_native_v3.py) in an explicitly
configured checkout.

The [development observation index](preliminary/index.json) retains 28 earlier
records separately from committed-source execution. These include the initial
static-link dependency failure, an initial Clippy style failure, a wrong-feature
kernel selector attempt, the private-directory fixture failure, and SQLite's
refusal to open a `/proc/self/fd` path with `SQLITE_OPEN_NOFOLLOW`.
The resulting owner opens a canonical private path with no-follow checks and
requires trusted same-UID administration; it is not a hostile-filesystem VFS
proof. The separate initial large Node library compile observation records
SIGKILL/exit 101 with **cause unestablished**. Only the retained note/excerpt is
available for that early observation; it must not be described as a full raw log
or diagnosed as OOM.

A review also added the irreversible owner cancellation latch. Its
[targeted development regression](cancellation-regression.json) and
[source hashes](cancellation-review-source.json) are retained. The full second
campaign, not that development observation, is the committed-source evidence.
The [authority continuation patch](authority-root-v3-continuation.patch.gz) retains
the separately reviewed integration delta.

## Separate hosted workflow observation

The [hosted snapshot](hosted-workflows-a44344b2.json), observed at
2026-11-09 03:31 UTC on the same `a44344b2` source, records six completed
successes, one completed failure, four in-progress workflows and two pending
workflows. **All hosted gates did not pass.** This is a dated readback, not a
prediction of later workflow outcomes.

[PoN original native campaign run 42554940456](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42554940456)
failed. Its release build succeeded, but all three prescribed original
`public_v3_multiprocess` campaign runs returned 101, each with zero passed and
one failed test. The recorded overall failure is
`ORIGINAL_THREE_RUN_CAMPAIGN_FAILED`. Exact source and binary identity were
retained; report validation and phase startup reported no errors.

In all three reports, `economics_complete=true` and
`finite_experiment_criteria_met=false`. Each baseline, from-zero and late-product
phase reported `finite_phase_criteria_met=false`,
`all_signed_rounds_confirmed_in_window=false` and
`receiver_client_state_equal=false`. The two attack phases in each run also
reported `genuine_budget_depletion_observed=false` with no depletion timestamp.
These are observed failed predicates; the readback does not establish their
underlying cause or attribute them to this root implementation. The original
workload, acceptance conditions and budgets were not relaxed.

The [selected hosted records](hosted-a44344b2/archive-index.json) retain the full
job log, three stdout/stderr pairs, exact result/source records, artifact member
and hash lists, a [failed-predicate projection](hosted-a44344b2/phase-failure-summary.json)
and the [bounded diagnosis](hosted-a44344b2/assessment.json). The complete
64,519,064-byte ZIP and three original approximately 30 MB reports are not embedded
in this repository seal. Their public artifact identity and hashes are retained;
the downloaded ZIP matched its GitHub digest. The finite projection is explicitly
derived and does not claim completeness of the raw reports.

The local 35/35 component campaign does not repair this separate hosted failure.
The PR remains draft/HOLD, and no merge or production activation follows from
this evidence.

## Bounds and open deployment obligations

The [dependency register](../../docs/security/PQ_ROOT_DEPENDENCY_REGISTER_V3.md)
checks a declared snapshot of **31 files, five authority roles and 14 hash-use
groups**. Its frozen digest is
`ebbc43cb8a757abb195b208594a54d18ba0f37300c6585062fb8cf344283248a`.
It records shared SHA-256, SHA-512, SHAKE128 and SHAKE256 obligations. SHA-512
uses through HMAC and MGF1 do not receive separate lifetime budgets.
A frozen finite source map is not authenticated revision provenance, a complete
call graph or a transitive dependency proof.

The [dependency output](attempt-a44344b2/dependency-register.log) and
[unchanged lifetime output](attempt-a44344b2/lifetime-register.log) retain null
bounds for signature, commitment, proof, ledger, transport, recovery, release and
application, and unknown complete lifetime query budgets. Resource refusal caps
are implementation limits, not adversary offline-query bounds. Allocating eight
shares of the target does not instantiate eight security theorems.

Independent custody and recovery, independently surviving fresh state, trusted
clock integration, actual native release/provider sinks, reorganization liability,
concrete quantum multi-user/multi-message reductions, complete key/epoch
populations, shared-hash query accounting and whole-chain event coverage remain
open. An unadvanced anchor after pending CAS remains fenced; retry/discard
availability recovery is not implemented.

```text
status = HOLD
actual_lifetime_failure_bound = null
whole_chain_pq_qualified = false
composition_coverage_proved = false
whole_chain_hash_query_scope_closed = false
native_m15_production_integration_complete = false
production_activation = false
```

## Archive inspection

Files larger than 64 KiB, and raw logs/patches whose original whitespace triggers
the repository diff check, are losslessly compressed with gzip. Each group index
records original names, stored paths, byte lengths and SHA-256 of both forms.
The hashes are evidence-file integrity identifiers, not new cryptographic
qualification assumptions. Run from a checkout:

```bash
python3 evidence/pq-root-native-v3-20261109/verify_archive.py
```

The verifier checks indexed bytes for the three local observation groups and
the selected hosted observations. It cross-checks exact-source records,
command-log hashes, command totals and HOLD
flags for the two frozen campaigns. It does not rerun tests, authenticate an
independent executor, verify all prose or authenticate external custody.

The [initial delivery diff check](delivery-diff-check-initial.log.gz) rejected
original trailing whitespace and blank log endings. Those observations were
losslessly compressed, not normalized. The [delivery formatting record](delivery-formatting-record.json)
retains the affected paths and auxiliary raw/stored hashes.
