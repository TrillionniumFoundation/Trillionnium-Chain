# TRNM Genesis Generation Checklist

Fail-closed checklist for producing, validating, and handing off a genesis artifact that may later be cited in validator bootstrap evidence.

This checklist is intentionally narrow:
- it does **not** declare TRNM public-mainnet ready by itself
- it does make genesis generation/review steps explicit enough that operators can name one artifact, one hash, and one decision scope before bootstrap
- it prefers stop conditions over inferred operator intent

## Scope

Use this when an operator needs to:
- generate a fresh genesis artifact for rehearsal, handoff, or mainnet-candidate review
- validate that one named genesis file is the exact artifact being distributed
- hand the genesis artifact/hash into the validator bootstrap ceremony packet without transcription drift

Primary references:
- `docs/runbooks/validator-bootstrap-rebootstrap.md`
- `docs/release/TRNM_VALIDATOR_RELEASE_HANDOFF.md`
- `scripts/v2/check_validator_config_bundle.py`
- `configs/node1.toml`
- `configs/node2.toml`
- `configs/node3.toml`
- `configs/node4.toml`

## Operator invariants

Before starting, all of the following must be true:
- you are inside the assigned worktree and branch for this lane/ticket
- `git status --short` is empty
- the validator config bundle you expect to bootstrap against is already named
- you can say whether this genesis is for `local-rehearsal`, `operator-handoff`, or `public-mainnet-input`
- you can name the rollback action before distributing any artifact

If any invariant fails, stop before continuing.

## Step 1 — Bind the artifact to an exact worktree and branch

Prefer the shared fail-closed helper instead of copying the current shell state by hand. `--expected-branch-ref` accepts either a short branch name like `lane/assigned-branch` or a full ref like `refs/heads/lane/assigned-branch`; use the exact value recorded in the ticket.

```bash
EXPECTED_WORKTREE_ROOT="/abs/path/from-ticket"
EXPECTED_BRANCH_REF="refs/heads/lane/assigned-branch"

./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF"
```

Record at minimum:
- `verified_worktree=`
- `verified_branch_ref=`
- `verified_head=`
- `genesis_decision_scope=`

Interpretation rule:
- if the worktree/branch cannot be proven from the ticket-assigned values, do not generate a handoff artifact
- if the decision scope is fuzzy, stop until it is stated explicitly

## Step 2 — Generate or select exactly one genesis artifact

Before validation or distribution, record:
- `genesis_artifact_path=` with the exact file/bundle path to distribute
- `genesis_source_note=` naming who produced it and from which workflow/command
- `validator_set_version=` tied to the validator membership under review

Interpretation rule:
- if multiple candidate genesis files exist and the chosen one is not named explicitly, stop
- if operators are referring to "the latest genesis" rather than one concrete path, stop

## Step 3 — Compute and freeze the distributed hash

Run a deterministic content hash on the exact artifact you intend to distribute.

Example:

```bash
shasum -a 256 /abs/path/to/genesis.json
```

Record:
- `genesis_artifact_sha256=` as a full 64-character hex digest
- `hash_computed_from=` with the exact path hashed

Interpretation rule:
- if the digest is truncated, copied from chat, or computed from a different path than the distributed artifact, stop
- if two operators quote different hashes for the same named artifact, stop the ceremony/bootstrap handoff

## Step 4 — Validate the validator config bundle against the intended bootstrap set

Required files:

```bash
ls configs/node1.toml configs/node2.toml configs/node3.toml configs/node4.toml
```

Recommended targeted validation:

```bash
python3 trillionnium-rust/scripts/v2/check_validator_config_bundle.py \
  trillionnium-rust/configs/node1.toml \
  trillionnium-rust/configs/node2.toml \
  trillionnium-rust/configs/node3.toml \
  trillionnium-rust/configs/node4.toml
```

If the artifact is headed into a shared bootstrap ceremony packet, generate the skeleton from the validated bundle instead of free-typing validator entries:

```bash
python3 trillionnium-rust/scripts/v2/check_validator_config_bundle.py \
  --emit-ceremony-packet \
  --genesis-artifact-path /abs/path/to/genesis.json \
  --genesis-artifact-sha256 <64-char-sha256> \
  trillionnium-rust/configs/node1.toml \
  trillionnium-rust/configs/node2.toml \
  trillionnium-rust/configs/node3.toml \
  trillionnium-rust/configs/node4.toml
```

For `public-mainnet-input`, fill the ceremony metadata up front instead of forwarding a packet that still contains template/default values. The packet generator already fails closed here: it rejects the template `ceremony_id`, placeholder path fields, shorthand/truncated genesis hashes, and the default `validator_set_version=v1` when `--ceremony-scope public-mainnet-input` is selected.

Copyable stricter example:

```bash
python3 trillionnium-rust/scripts/v2/check_validator_config_bundle.py \
  --emit-ceremony-packet \
  --ceremony-id mn04-bootstrap-20260331-0621Z \
  --ceremony-scope public-mainnet-input \
  --packet-generated-at 2026-03-31T06:21:00Z \
  --packet-distribution-path /abs/path/to/bootstrap-ceremony.packet.txt \
  --validator-set-version mainnet-candidate-2026-03-31 \
  --startup-order-note 'node1 -> node2 -> node3 -> node4' \
  --rollback-owner primary-operator \
  --genesis-artifact-path /abs/path/to/genesis.json \
  --genesis-artifact-sha256 <64-char-sha256> \
  trillionnium-rust/configs/node1.toml \
  trillionnium-rust/configs/node2.toml \
  trillionnium-rust/configs/node3.toml \
  trillionnium-rust/configs/node4.toml
```

Interpretation rule:
- if the config bundle fails validation, the genesis artifact is not bootstrap-ready for this validator set
- if the ceremony packet names a different hash than the one computed in Step 3, stop

## Step 5 — Distribute one packet, not many interpretations

For any artifact expected to feed validator bootstrap/handoff, preserve one shared packet containing at least:
- `ceremony_id=`
- `ceremony_scope=`
- `genesis_artifact_path=`
- `genesis_artifact_sha256=`
- `validator_set_version=`
- `packet_distribution_path=`
- `rollback_owner=`
- `validator_entry=` per validator
- `validator_entry_hash=` per validator so acknowledgments can bind back to one immutable descriptor instead of a hand-written tuple
- `operator_ack=` lines must reuse the emitted `validator_entry.config_path` verbatim; if the generated packet uses an absolute `config_path=`, do not rewrite it as a relative path in the acknowledgment artifact

Required for `public-mainnet-input` evidence:
- `packet_generated_at=` in UTC
- `packet_distribution_path=` as one explicit absolute path to the generated ceremony packet file every operator reviewed
- `operator_contact=` per validator owner so missing acknowledgments can be chased without ambiguity
- `operator_ack=` per validator owner
- `operator_ack_signature_path=` or `operator_ack_digest=` when durable acknowledgment is required; for each validator/operator, fill at least one of these fields before treating the packet as signed/public-mainnet handoff evidence
- explicit `abort_condition=` lines for mismatched genesis hash, duplicate node identity, or wrong worktree/ref
- a concrete `validator_set_version=` (for example `mainnet-candidate-2026-03-31`) instead of a template/default label

Recommended for non-public rehearsal/handoff packets:
- still include `packet_generated_at=` and `packet_distribution_path=` so later review can tie one exact packet to one bootstrap window and distribution channel

Interpretation rule:
- if operators receive different packet contents for the same `ceremony_id`, stop and normalize to one packet before startup
- if `packet_distribution_path=` names only a folder, ticket, or bundle root without one exact packet file path, treat the handoff as ambiguous and regenerate/re-record the packet path before startup
- if a public-mainnet-input packet still contains placeholders, relative packet/genesis paths, truncated hashes, or the default `validator_set_version=v1`, do not treat it as ceremony-ready

## Rollback

Before distribution, the operator should already know which of these applies:
- discard the newly generated artifact and mark the attempt No-Go
- revert to the previously recorded genesis artifact/hash
- invalidate the shared packet and require a regenerated one with a new `ceremony_id=`

## Minimum handoff fields

When passing genesis readiness to another operator, record:
- worktree path
- branch ref
- HEAD commit
- genesis artifact path
- genesis artifact sha256
- genesis source note
- validator set version
- packet distribution path
- validator entry hash(es) relied upon for operator acknowledgment binding
- commands run
- pass/fail result
- rollback command
- one-line blocker if the artifact is not cleanly reproducible

## Non-go conditions

Treat genesis generation/handoff as **No-Go** if any of the following is true:
- worktree or branch identity is not proven
- the exact artifact path is not named
- the distributed artifact hash is missing, truncated, or inconsistent across operators
- the validator set version cannot be named
- the shared ceremony packet disagrees with the artifact actually hashed
- operator acknowledgment cannot be tied back to a specific `validator_entry=` / `validator_entry_hash=` in the shared packet
- the operator cannot provide a rollback action immediately

This checklist closes part of the genesis-generation documentation gap, but it does **not** by itself close validator rotation, signer ceremony, network formation, or broader public-mainnet release readiness.
