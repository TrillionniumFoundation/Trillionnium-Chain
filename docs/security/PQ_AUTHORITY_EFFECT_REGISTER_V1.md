# PQ authority and effect source register V1

**HOLD. Curated source consistency only; incomplete authority coverage.**

The [register](../../config/pon/pq-authority-effects-v1.json) binds seven reviewed
routes to the source baseline
`7005fee55f2ba82d6c7aa3ccf1f60e616750ae2b`. The
[checker](../../scripts/ci/pq_authority_effect_register.py) enforces their exact
effect scopes and source sets, and compares 44 actual regular files with a fixed
reviewed SHA-256 lock. Successful checking reports `source_consistency: PASS`
while `status: HOLD`, `coverage_complete: false`,
`whole_chain_pq_qualified: false`, and `production_activation: false` remain fixed.

This closes a source-recording gap in the earlier
[cryptographic surface inventory](PQ_AUTHORITY_SURFACE_AUDIT_20261031.md): a
classic transfer type is not interchangeable with the native account owner, and
a signature, context comparison, downloaded artifact or certificate observation
must not be recorded as a different downstream permission. No newly established
classical bypass of a PQ owner is claimed.

## The seven bounded routes

Every row has exact `entry_sources`, `authentication_sources`,
`state_or_effect_sources`, `profile_sources`, and `negative_test_sources` sets.
The manifest carries full paths and file digests. The table below describes the
reviewed source observation; the checker does not reconstruct the call graph.

| Route | Source connection and observed effect | Fixed effect scope |
| --- | --- | --- |
| `compat_transfer_type_v1` | `trnm-types::TransferTx::validate_basic` checks a classic Ed25519 address/signature and returns validation. At the named baseline, repository references were confined to the type module, its export and tests; no native Node consumer was found. | `validation-result-only` |
| `native_pnx1_account_transfer` | `pon_wire::Envelope` enters `pon_executor::prepare`; the classical branch verifies the signing digest. `apply_authenticated_application` checks nonce and fees, then tag 1 debits and credits accounts. The Node execution/admission path persists the result, and the selected activation path updates the active state. | `native-account-state-and-node-persistence` |
| `portable_consumption_settlement_v1` | `ConsumptionSettlementStoreV1::execute_committed_execution` reaches bilateral receipt/rollup checks in `engine.rs`, then the portable settlement state and SQLite journal. Provider/consumer signatures are Ed25519. No native Node consumer of this store was found in the reviewed repository. | `portable-settlement-store-only` |
| `research_command_state_v1` | `SignedResearchCommandV1::validate` checks Ed25519. `ResearchProtocolState::apply` checks the chain, role/key authority and command replay before changing research objects. No Node execution or installation consumer was found. | `research-protocol-state-only` |
| `hepta_admission_compare_v1` | `SignedHeptaAdmissionV1::verify_for_context` compares the receiver's expected owner admission, chain and time, and verifies the classical authority. It returns a comparison result. Its separate PQ V2 comparator also requires its own pins; neither comparator consumes a FinalUse grant. | `owner-context-comparison-only` |
| `cell_discovery_v1_fetch_cache` | The explicit discovery CLI selects a V1 or V2 owner. V1 verifies provider records, updates the provider directory, discovers endpoints and invokes content-checked fetching and create-only materialization through the Cell cache. These effects do not confer payment, custody, installation or use permission. | `provider-directory-and-content-cache-only` |
| `reference_release_finality_v2_observer` | The Python certificate reader and `release_finality.rs::verify_certificate` verify classical votes against receiving-owner committee/context pins. The native result is a read-only statement. The separate formal protocol simulator is retained as profile context, not represented as an installation or production-finality consumer. | `read-only-certificate-facts` |

The compatibility type, Hepta comparator and certificate readers have empty
`state_or_effect_sources` sets because these particular interfaces return facts
without a state/effect sink. Their keys remain mandatory. Empty sets cannot be
substituted for the native account, portable settlement, research state or
discovery effect sets. The compatibility type also has no Node profile selector;
the register preserves that absence instead of inventing a consumer.

### Native account and network profiles remain distinct

The native transaction source is
[`pon_wire.rs`](../../trillionnium/crates/trnm-protocol/src/pon_wire.rs), followed
by [`pon_executor.rs`](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs).
`prepare` checks the account profile before choosing the classic or explicit PQ
authentication owner. The selected PQ branch returns its own prepared value;
failure is not a request to fall back to classic decoding. The
[Node store](../../trillionnium/crates/trnm-pon-node/src/store.rs) owns
`admit_work_checked_with_parent`, `persist_admission_execution`,
`activate_with_fault_and_progress` and `resume_intent_with_progress`.

The [network ingress owner](../../trillionnium/crates/trnm-pon-node/src/ingress.rs)
also rejects construction of classical authenticated sessions for a PQ account
profile. A PQ transport owner can serve a classical account ledger, so network
ownership still needs its own check. The register therefore retains
[`public_submit.rs`](../../trillionnium/crates/trnm-pon-node/src/public_submit.rs)
and the
[before-connect/after-reopen recovery refusal source](../../trillionnium/crates/trnm-pon-node/tests/public_submit_recovery.rs).
Their presence is not a fresh observation that these native tests passed.

The portable consumption settlement store is separately scoped. Substituting
`native_budget.rs`, a funding observation, or a storage-service payment adapter
for its bilateral authorization and durable state sources is refused by this
register. Those additional owners still require their own qualification work.

## Fixed source lock and its limits

For each required path, the initial SHA-256 was computed from
`git show 88568e2511fcf166e6824947ac97b06b72104385:<path>` and compared with the
working file before this register was created. Its original reviewed table
digest was `aa8d0fd93a6917b6a4685673c1a286575df026b3cc144750aaef4a95bf77e773`.

The [composed candidate](PQ_COMPOSITION_20261108.md) changes six of those files:
crypto exports, discovery transport, the executor, ingress, Node store and
transaction wire. The seven route descriptions and all 44 required paths were
retained after reviewing those changes. Every source digest was recomputed
from `git show 7005fee55f2ba82d6c7aa3ccf1f60e616750ae2b:<path>` after checking
the regular-file mode and equality with the working bytes. The checker and its
independent literal-revision test now fix that revision and this table digest:

```text
1b7311376795498390aff1eb4958f57355d9751cfefc64b071f36cd467580315
```

The table digest is SHA-256 of UTF-8 JSON containing exactly
`{"source_revision": SOURCE_REVISION, "files": source_files_sha256}`, serialized
with sorted keys and separators `(',', ':')`. This extra reviewed constant
prevents changing a source file and its self-reported manifest hash together
while leaving the checker unchanged. Changing the revision label, omitting a
route or source category, adding an unrelated source, or changing an effect
scope also requires a new reviewed checker/manifest change.

The runtime check intentionally does not depend on historical Git objects, so
it works in shallow source checkouts. **It does not authenticate the origin of
the Git commit or reviewed lock.** `source_revision_binding` is
`fixed-reviewed-file-lock-only` and `provenance_authenticated` remains false.
Reviewing or changing the checker and lock together is outside this local
consistency check; neither self-reported hashes nor a review label are an
independent trust root. A later tree may pass only while all 44 curated files
still equal these exact baseline bytes. Unlisted files and dependency changes
are not checked and do not acquire the baseline's scope.

The checker reuses the bounded strict JSON parser from
[`pq_lifetime_budget.py`](../../scripts/ci/pq_lifetime_budget.py) and the
descriptor-bound
[`read_regular`](../../scripts/ci/pq_source_reader.py). Duplicate JSON keys,
unknown/missing fields, malformed syntax, floats/nonfinite values, invalid
Unicode and over-limit inputs are refused. Source and directory symlinks,
nonregular/oversized files, missing paths and detected per-read changes are
refused. These checked reads are not an immutable tree snapshot or protection
against a privileged concurrent writer.

## Running and interpreting the guard

Run from the repository root:

```bash
python3 -m unittest discover -s scripts/ci -p 'test_pq_authority_effect_register.py' -v
python3 scripts/ci/pq_authority_effect_register.py
```

Exit 0 means the curated register is internally consistent with the actual
locked source bytes. The JSON status still reads `HOLD`. Exit 2 and a JSON
`REFUSE` reason mean the input, source, scope or fixed lock did not match.

The [adversarial controls](../../scripts/ci/test_pq_authority_effect_register.py)
copy the actual pinned source bytes into isolated temporary trees. They remove
each required file, remove mandatory category members, remove both a native
source and its pin, change source bytes with and without rehashing, substitute
another real settlement module, promote restricted effect scopes, alter profile
or revision context, and exercise malformed JSON, symlinks, FIFO and size
limits. They also verify that adding an unreviewed file does not turn partial
coverage into a complete-coverage claim.

The register does not run Rust tests, verify a production binary, enumerate
macros or dynamically loaded callers, discover external repositories, or prove
that an absent source reference cannot exist at runtime. Negative-test paths
identify review material, not successful receipts. External-branch test results
cannot be supplied as acceptance fields in this schema. Actual integration,
fresh authorization, recovery, external effects and whole-chain security remain
separate obligations; `native_tests_executed`, `call_graph_proved` and
`runtime_reachability_proved` all remain false in the checker result.
