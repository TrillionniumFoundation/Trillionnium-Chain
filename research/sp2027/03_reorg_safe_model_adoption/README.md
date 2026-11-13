# SP27-03: actual admission adapter and controlled effect boundary

**Disposition: INTEGRATE into the SP27-03/05 supporting chapter and artifact;
independent submission NO_GO on this evidence.** The joint run exercises an
actual native admission-library adapter and a controlled effect sink. It
supports the stated composition boundaries, without establishing a new
unbounded mechanism or a native Node/FinalUse product path.

This research continuation starts from `docs/chain-sp2027` at
`5b591754b426c6f88bea6d399fafcd77e31255d8`. It accompanies the restored
hepta-papers SP27-03 delivery `f72d0fc5277aedec768913d7f53b7a18b0e5986f` and its
original execution `f7875030d9ef7cc3f1513d3372ae47d7784144ee`. It is an evidence
and reproduction note under the existing
[development plan](../../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
not another product development plan.

## Execution source and evidence delivery

| Identity | Frozen value |
| --- | --- |
| Chain adapter execution source | `1e5667354f6fa17170202416b9d24562e6c72496` |
| Chain execution tree | `584b16d72f0e1030c51d9beb931d9bc4bc4ba746` |
| Papers consumer execution source | `303f3358e8b36f4c6e9453ea5cf3c40e822154e9` |
| Papers execution tree | `cedbad49062a253038b9e86cd6d2f4d2bfc4ea31` |
| Adapter source SHA-256 | `67e35ac1089421d020dc823914ee5e2c410c4bbea0b69d306fd52340ff54a7dc` |
| Adapter ELF SHA-256 | `0d01d50cdfca9883b5830ad10804c4b116dc109b3a3fe9c24c38c5a6018dbd20` |

This delivery is an **evidence-only child** of the Chain execution source.
The adapter's bytes are unchanged. The source checkpoints above, rather than
the later evidence commit, identify the code used for execution. No native
result is reassigned to the evidence child's complete tree, and no native gate
was rerun merely to copy its records. The final evidence commit is obtained by
Git readback; its own hash is intentionally absent from the committed metadata.

The [delivery map](evidence/SOURCE_AND_DELIVERY.json) preserves the copied-file
identities, scope and decision. All original native gate receipts and logs are
retained under [native validation](evidence/native-validation/frozen-1e5667354/BUILD_RECEIPT.json).
Their local execution paths are historical provenance, not new execution
locations. The separate initial compilation logs retain their development
scope and the original build receipt's relative paths.

The [evidence assembly observation](evidence/EVIDENCE_ASSEMBLY_OBSERVATION.json)
also retains the first whitespace-check failure and the intermediate copy's
five ignored log omissions. A normal descendant commit includes those original
logs and applies narrowly scoped raw-output attributes without changing their
bytes; the failure is not reported as an initial pass.

## Executable boundary

The new
[Rust example](../../../trillionnium/crates/trnm-research-protocol/examples/sp27_03_authorization_adapter.rs)
calls the unchanged `SignedHeptaAdmissionV1::sign`,
`SignedHeptaAdmissionV1::from_canonical_bytes` and
`SignedHeptaAdmissionV1::verify_for_context` implementations. It accepts one
bounded JSON request on stdin and returns one JSON response. A rejected
admission is a recorded verdict, not a successful execution authorization.

The example uses public, explicitly named fixture keys for research. It does
not add a production signer or authority. Every response has
`grants_execution_authority=false` and `pq_qualified=false`. This V1 Ed25519
experiment makes no post-quantum claim. It cannot supply a missing production
Hepta owner, ordinary Node caller, FinalUse authority, external provider
reconciliation, or independently surviving freshness.

The companion Python consumer lives in hepta-papers at
`research/sp2027/03_reorg_safe_model_adoption/joint/`. It supplies the expected
admission and signer pins from a separate current **controlled** authority
record. It invokes this actual Rust verifier while holding the SQLite writer
transaction used for the authority, local counter mutation and completion.
That common transaction domain is an assumption, not a property this example
establishes for a remote service.

## Input namespace contract

Agent 05's exact input is `actual_recovery_handoff.json`, schema
`sp27-05.actual-recovery-observation.v1`, SHA-256
`03bb46885541ca3c369394afcc06552ad89179fbaac869fb72d4ac156d798ac2`.
It records prior recovery/forward observations under Chain source
`f2a4394e84df05ba9307688e2e804282ca3b5ebb`. Reading it is not a new native
recovery, model forward, or complete end-to-end run.

The consumer pins all original bytes and joins a request by native operation,
CHB1 descriptor, and request label together. A label alone is insufficient.
Original TCV1/TCV2/CHB1 identities retain their full typed SHA-512 hex strings.
The research mapping into `Digest32` is explicitly domain separated; it does
not increase the strength of an earlier commitment or change its namespace.

`generation=1` comes from the recorded model generation. Authorization
incarnations 41, 42 and 43 are newly supplied research authority states, never
inferred from that generation. The original CHB1 parent is retained in the
descriptor binding; this new first-generation research admission uses no
`parent_artifact_digest`. Its payload is the new canonical consumer intent
record, not the model payload. Its owner-admission digest is a research
snapshot binding, not an emitted production Hepta V3 admission.

The stable logical key is `(scope, logical_operation_id)`. Owner and
incarnation changes do not change this key. The intent digest binds the
operation, requested/observed content, descriptor, source selector and exact
counter command. The separately named effect digest commits the actual
counter mutation record. Original completion owner/incarnation and verifier
provenance remain separate from that business identity.

## Observed joint cases

The exact-source run `confirmation-303f335-1e5667354` recorded the following
outcomes. Its byte-identical [summary](evidence/joint-result-reference/summary.json)
and [interface-consumption receipt](evidence/joint-result-reference/interface-consumption-receipt.json)
are included here. The [upstream manifest index](evidence/joint-result-reference/UPSTREAM_MANIFEST_SHA256.json)
identifies the complete raw run retained by the companion Papers delivery;
this index copy does not assert that every listed database/event file is
duplicated in this Chain directory.

| Schedule | Classification | Committed counter effects |
| --- | --- | ---: |
| Revocation before the first effect, protected boundary | PRESERVED | 0 |
| Cached precheck unsafe control | VIOLATION | 1 |
| Committed effect, lost ACK, then owner transfer, stable operation key | PRESERVED | 1 |
| Incarnation-dependent key unsafe control | VIOLATION | 2 |
| Same content under a fresh authorization and new business operation | PRESERVED | 2 |

These are **3 PRESERVED and 2 VIOLATION**, with the unsafe observations retained.
A separate paired opaque-provider experiment has two indistinguishable client
observations, both **UNKNOWN**. Its researcher-only oracle sees zero versus one
effect; neither oracle value is substituted for the client's result or used to
authorize redispatch. This is one paired experiment, not two additional safe
joint schedules.

The joint run made nine fresh fixture-sign calls and nine fresh verify calls
to the actual Rust library adapter. Reading the two archived Agent 05 request
observations added **zero native recovery runs, zero model forwards and zero
native end-to-end runs**. No live Agent 05 acknowledgment was observed; the
consumer freezes the delivered producer contract without claiming bilateral
approval.

The protected counter, current authority and completion share one SQLite
writer transaction. The lost-ACK child exits after commit and before response;
the original runner parent then reopens the closed database through a new
connection. This is a different process from the effect committer, not a claim
that a newly launched observer had no prior context. The returned completion
keeps the original owner/incarnation and grants no current execution authority.

## Native gate outcomes

The original repository command observer verified the entire committed source
before and after each recorded gate: **27,889 entries, 2,553,900,018 bytes**,
always the Chain execution source and tree listed above. The
[build receipt](evidence/native-validation/frozen-1e5667354/BUILD_RECEIPT.json)
binds the raw receipts, logs, Cargo lock, toolchain and ELF identity.

| Gate | Exact-source result |
| --- | --- |
| Locked offline adapter build | exit 0; existing independent target reused |
| Locked affected-crate Cargo graph | exit 0 |
| Retained `trnm-research-protocol` tests | 35 passed, 0 failed, 1 ignored |
| Affected-crate Clippy, all targets/features, `-D warnings` | exit 0 |
| Workspace formatting check | exit 0 |
| Original source-integrity negative controls | 43 tests passed |

The ignored test is the retained `print_golden_fixture_for_regeneration` helper.
The exact-source build is cached, not a fresh-target build. These records do
not claim that all workspace native tests or all workspace Clippy targets ran.
Passing retained PQ component tests does not change the V1 Ed25519 adapter's
explicitly non-PQ experiment scope.

## Reproduction

Use clean isolated worktrees at the two execution checkpoints above. Run
the repository preflight before builds. The existing workspace lock is used;
no new package or dependency is introduced.

```sh
bash scripts/project-preflight.sh
cargo build --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-research-protocol --example sp27_03_authorization_adapter
cargo test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-research-protocol --lib --tests --all-features
cargo clippy --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-research-protocol --all-targets --all-features -- -D warnings
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
```

In the companion Papers checkout, with a new output directory:

```sh
python3 research/sp2027/03_reorg_safe_model_adoption/joint/run_joint_cases.py \
  --chain-worktree /absolute/path/to/chain-checkout \
  --adapter /absolute/path/to/chain-target/debug/examples/sp27_03_authorization_adapter \
  --out /absolute/path/to/new-joint-run
```

The runner refuses a dirty source unless `--allow-dirty-development` is
explicitly supplied. Development runs remain separate from the committed-source
confirmation. Native inputs, outputs, stderr, process return codes and binary
hashes are retained alongside the event journal and SQLite databases.
The recorded build/test commands used Rust/Cargo 1.95.0 and `--offline` with a
prepared private dependency cache; their exact argv and environment are in the
original receipts. Store new outputs outside the clean source worktrees.

## Claim boundary

The three required cases are revocation before a first effect, effect commit
with lost ACK followed by owner transfer, and lawful reuse of the same content
under a fresh authorization for a new business operation. Explicit unsafe
precheck and incarnation-key controls remain violations. An opaque provider
case retains `UNKNOWN`; a researcher-only oracle does not replace a client
completion response.

Keep the three evidence layers separate: actual native admission-library
calls; a controlled SQLite effect sink; and finite-model/trace checks. No
whole-chain refinement, unbounded proof, arbitrary external exactly-once,
remote attestation, production activation or ordinary FinalUse follows.
Logical-operation creation is trusted; the adapter does not implement a
CapLease-style confirmation/budget ledger against arbitrary fresh-ID
reissuance. The test concerns the observed revocation barrier, not exact
wall-clock expiration at a later physical effect. Completion disclosure
authorization is outside the trusted local-reader experiment.

The record field `valid_at_commit` is the consumer's current authorization
snapshot predicate; it does not assert that a wall-clock expiration boundary
was sampled at SQLite's exact physical commit instant. A saved pretty JSON
request file and the compact canonical JSON actually written to native stdin
also have distinct byte hashes. Native `input_sha256` refers to the latter.

The result supports the combined 03/05 artifact and its boundary analysis.
CTA's reauthorization boundary, RIFL's stable operation/completion principle,
and CapLease's confirmation/budget constraints remain the relevant comparison.
This experiment does not establish an independently new mechanism beyond
their correct, explicitly limited composition; standalone SP27-03 remains
NO_GO while the supporting contribution is INTEGRATE. The
[frozen original-literature recheck](https://github.com/TrillionniumFoundation/hepta-papers/blob/303f3358e8b36f4c6e9453ea5cf3c40e822154e9/research/sp2027/03_reorg_safe_model_adoption/joint/LITERATURE_RECHECK_20261111.md)
records the primary references and the comparison's limits.

The original 28 schedules remain 6 `VIOLATION`, 18 `PRESERVED`, 3 `UNKNOWN`
and 1 `ASSUMPTION_VIOLATED`. Their results are not replaced or pooled with
this continuation. Agent 05's missing original absolute/request clocks stay
null; new local clocks describe only this new consumer campaign.
