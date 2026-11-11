# SP27-03: actual admission adapter and controlled effect boundary

This research continuation starts from `docs/chain-sp2027` at
`5b591754b426c6f88bea6d399fafcd77e31255d8`. It accompanies the restored
hepta-papers SP27-03 delivery `f72d0fc5277aedec768913d7f53b7a18b0e5986f` and its
original execution `f7875030d9ef7cc3f1513d3372ae47d7784144ee`. It is an evidence
and reproduction note under the existing
[development plan](../../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
not another product development plan.

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

## Reproduction

Use a clean, frozen copy of this branch and the companion paper branch. Run
the repository preflight before builds. The existing workspace lock is used;
no new package or dependency is introduced.

```sh
bash scripts/project-preflight.sh
cargo build --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-research-protocol --example sp27_03_authorization_adapter
cargo test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-research-protocol --all-targets
cargo clippy --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-research-protocol --all-targets -- -D warnings
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

The original 28 schedules remain 6 `VIOLATION`, 18 `PRESERVED`, 3 `UNKNOWN`
and 1 `ASSUMPTION_VIOLATED`. Their results are not replaced or pooled with
this continuation. Agent 05's missing original absolute/request clocks stay
null; new local clocks describe only this new consumer campaign.
