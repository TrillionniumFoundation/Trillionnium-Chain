# TRNM Validator Bootstrap / Re-bootstrap Runbook

Fail-closed operator checklist for bringing up a validator from a clean worktree, or rebuilding the same validator after host/process replacement.

This runbook is intentionally narrow:
- it does **not** declare TRNM public-mainnet ready by itself
- it does provide a reproducible bootstrap / re-bootstrap procedure bound to an exact worktree, branch, and validator config set
- it points operators at `scripts/v2/check_validator_config_bundle.py --emit-ceremony-packet` so the ceremony packet can be generated from the validated config bundle instead of free-typing validator entries
- it prefers explicit stop conditions over "probably fine" operator judgment

## Scope

Use this when an operator needs to:
- bootstrap a validator from a clean checked-out worktree
- re-bootstrap after host rebuild, process loss, or local environment drift
- prove the validator config bundle and worktree identity before handing off to another operator

Primary references:
- `docs/release/TRNM_VALIDATOR_RELEASE_HANDOFF.md`
- `docs/runbooks/genesis-generation-checklist.md`
- `docs/runbooks/local-release-evidence.md`
- `docs/runbooks/validator-rotation-dr.md`
- `scripts/v2/verify_lane_worktree.sh`
- `trillionnium-rust/configs/node1.toml`
- `trillionnium-rust/configs/node2.toml`
- `trillionnium-rust/configs/node3.toml`
- `trillionnium-rust/configs/node4.toml`

## Operator invariants

Before starting, all of the following must be true:
- you are inside the supervisor-assigned worktree
- the checked-out branch matches the lane/ticket branch exactly
- `git status --short` is empty
- the config bundle exists and is internally consistent for the node you intend to run
- the intended genesis artifact/hash is named explicitly before startup or handoff
- no second process is already using the same validator identity or listen ports
- you can name the rollback action before touching the node

If any invariant fails, stop before continuing.

## Step 1 — Bind to the exact worktree and branch

Prefer the shared fail-closed helper instead of trusting the shell prompt.

Use the ticket-assigned **absolute** worktree path directly; do not pass a relative path copied from the current shell. `--expected-branch-ref` accepts either a short branch name like `lane/assigned-branch` or a full ref like `refs/heads/lane/assigned-branch`; use the exact value recorded in the ticket.

```bash
EXPECTED_WORKTREE_ROOT="/abs/path/from-ticket"
EXPECTED_BRANCH_REF="refs/heads/lane/assigned-branch"
EXPECTED_HEAD="<optional-commit-from-ticket-or-handoff>"

./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF" \
  ${EXPECTED_HEAD:+--expected-head "$EXPECTED_HEAD"}
```

Minimum evidence to record:
- `verified_worktree=`
- `verified_branch_ref=`
- `verified_head=`

Interpretation rule:
- if the lane ticket or operator handoff already pins an exact commit, pass it via `EXPECTED_HEAD` so bootstrap/re-bootstrap fails closed on the wrong lane tip
- if `EXPECTED_HEAD` is intentionally unknown, leave it empty rather than inventing a commit from memory

Stop conditions:
- worktree mismatch
- branch mismatch
- detached HEAD
- expected-HEAD mismatch when the ticket/handoff pinned an exact commit
- missing `git worktree` stanza for the current path

## Step 2 — Confirm a clean operator state

Run:

```bash
git status --short
ps -ef | grep -E 'trnm-node|cometbft' | grep -v grep
lsof -iTCP -sTCP:LISTEN | grep -E '26656|26657|26658|26660'
```

Interpretation rule:
- `git status --short` must be empty
- if an unexpected validator process is already active, stop
- if the owner of the current validator identity cannot be named explicitly, stop

## Step 3 — Check the config bundle before bootstrap

Before touching the node, bind the bootstrap to one explicitly named genesis artifact.
Do not proceed on a fuzzy statement like "the latest genesis" or "the same one as yesterday".
Use `docs/runbooks/genesis-generation-checklist.md` first if the artifact/hash has not yet been generated and frozen for operator handoff.

Minimum genesis checklist to record in the ticket / handoff note:
- `genesis_artifact_path=` with the exact file or bundle path the validator is expected to join
- `genesis_artifact_sha256=` (or another explicitly named content hash) copied from the artifact you actually intend to distribute
- `genesis_source_note=` describing who produced or approved this genesis bundle
- `genesis_decision_scope=` stating whether this is local rehearsal-only evidence or a public operator ceremony input

Interpretation rule:
- if the artifact path can be named but the content hash cannot, stop
- if the content hash exists but cannot be tied back to the exact distributed file, stop
- if different operators are using different labels for the same genesis bundle, normalize to one path + one hash before bootstrap

### Multi-validator ceremony packet (minimum fail-closed set)

When the bootstrap is part of a validator ceremony rather than a single-node local sanity pass, capture one shared packet before any validator starts.
Do not allow each operator to freestyle their own note format.

Minimum packet fields:
- `ceremony_id=` unique identifier for this bootstrap ceremony/rehearsal
- `ceremony_scope=` one of `local-rehearsal`, `operator-handoff`, or `public-mainnet-input`
- the packet generator rejects any other `--ceremony-scope` value so a mistyped scope cannot silently drift into handoff evidence
- `genesis_artifact_path=` and `genesis_artifact_sha256=` copied exactly once as the shared ceremony anchor
- `validator_set_version=` identifying the exact validator membership list under review; for packets that may feed `public-mainnet-input`, use a concrete version label (for example `mainnet-candidate-2026-03-31`) instead of the template/default `v1`
- `validator_entry=` repeated once per validator with `validator_name`, `validator_owner`, `node_id`, `config_path`, `p2p_addr`, and `rpc_addr`; for `public-mainnet-input`, prefer absolute `config_path` values so every operator is reviewing the same on-disk file identity rather than a shell-relative path. When using `python3 scripts/v2/check_validator_config_bundle.py --emit-ceremony-packet --ceremony-scope public-mainnet-input ...`, the generated `validator_entry.config_path` values are emitted as absolute paths automatically from the validated bundle.
- `validator_entry_hash=` or equivalent per-validator fingerprint if a generated validator descriptor exists; `python3 scripts/v2/check_validator_config_bundle.py --emit-ceremony-packet ...` now emits this deterministically from the validated `validator_name`/`node_id`/`config_path`/`p2p_addr`/`rpc_addr` tuple so later acknowledgments can bind to one exact descriptor instead of a hand-written placeholder
- `operator_ack=` repeated once per operator/validator owner, confirming they checked the same genesis hash, config path, and the specific `validator_entry=` they own; the acknowledgment must copy the emitted `validator_entry.config_path` verbatim rather than normalizing it by hand, so later review does not have to guess whether `trillionnium-rust/configs/node1.toml` and `/abs/path/.../trillionnium-rust/configs/node1.toml` were intended to name the same reviewed file. When `validator_entry_hash=` is present, require the acknowledgment line/artifact to quote the same hash so later review can bind the acknowledgment to one immutable validator descriptor instead of a loosely matched name/path pair
- `operator_ack_signature_path=` or `operator_ack_digest=` repeated once per operator when the ceremony requires a durable signed/attested acknowledgment artifact instead of chat-only confirmation
- `startup_order_note=` stating whether startup order matters for this rehearsal and who is expected to start first
- `rollback_owner=` naming who can declare the ceremony aborted and which command/process stop is authoritative

Required for `public-mainnet-input` packets:
- `packet_generated_at=` in UTC so later evidence can tie the ceremony packet to the bootstrap window explicitly
- `packet_distribution_path=` naming the exact shared folder, ticket, or immutable artifact bundle every operator reviewed; use one explicit absolute path so operators do not normalize different relative paths by hand
- `operator_contact=` repeated once per operator so a missing acknowledgment can be resolved without ambiguity
- `abort_condition=` repeated for the specific fail-closed triggers that cause the ceremony to stop immediately (for example mismatched genesis hash, duplicate `node_id`, or wrong assigned worktree)

Recommended for non-public rehearsal/handoff packets:
- still include `packet_generated_at=` and `packet_distribution_path=` so later review can tie one exact packet to one bootstrap window and distribution channel

Copyable packet skeleton:

```text
ceremony_id=mn04-bootstrap-YYYYMMDD-HHMMZ
ceremony_scope=operator-handoff
packet_generated_at=2026-03-31T06:21:00Z
packet_distribution_path=/abs/path/or/ticket
validator_set_version=mainnet-candidate-2026-03-31
startup_order_note=node1 -> node2 -> node3 -> node4
rollback_owner=primary-operator
abort_condition=genesis hash mismatch
abort_condition=duplicate node_id
abort_condition=assigned worktree/ref mismatch

genesis_artifact_path=/abs/path/to/genesis.json
genesis_artifact_sha256=<64-char-sha256>

authority_note=all operators must acknowledge the exact packet above before any validator starts

validator_entry=validator_name=node1;validator_owner=alice;node_id=node1;config_path=/abs/path/to/configs/node1.toml;p2p_addr=127.0.0.1:26656;rpc_addr=127.0.0.1:26657
validator_entry_hash=<deterministic-sha256-from-validator_name/node_id/config_path/p2p_addr/rpc_addr>
operator_contact=node1=<chat/email/oncall-for-node1>
operator_ack=alice checked genesis_artifact_sha256=<64-char-sha256>;config_path=/abs/path/to/configs/node1.toml;validator_name=node1;validator_entry_hash=<deterministic-sha256-from-validator_name/node_id/config_path/p2p_addr/rpc_addr>
operator_ack_signature_path=/abs/path/to/alice-ack.txt

validator_entry=validator_name=node2;validator_owner=bob;node_id=node2;config_path=/abs/path/to/configs/node2.toml;p2p_addr=127.0.0.1:27656;rpc_addr=127.0.0.1:27657
validator_entry_hash=<deterministic-sha256-from-validator_name/node_id/config_path/p2p_addr/rpc_addr>
operator_contact=node2=<chat/email/oncall-for-node2>
operator_ack=bob checked genesis_artifact_sha256=<64-char-sha256>;config_path=/abs/path/to/configs/node2.toml;validator_name=node2;validator_entry_hash=<deterministic-sha256-from-validator_name/node_id/config_path/p2p_addr/rpc_addr>
operator_ack_digest=<optional-sha256-of-bob-ack>
```

Interpretation rule:
- `operator_contact=` should identify one concrete durable contact route per validator/operator (for example `node1=alice-oncall@...` or a ticket/chat handle scoped to that validator) rather than a shared generic team alias copied into every entry
- chat-only `operator_ack=` is acceptable for local rehearsal, but if the packet is later quoted in a mainnet readiness review, preserve either `operator_ack_signature_path=` or `operator_ack_digest=` for each operator whose approval is being relied upon
- if the packet claims a durable acknowledgment exists but cannot name the path or digest, treat that acknowledgment as missing instead of implicitly trusted

Fail-closed rule:
- if two validators claim the same `node_id`, stop
- if two validators point at different genesis hashes for the same `ceremony_id`, stop
- if a `public-mainnet-input` packet uses a relative `genesis_artifact_path=` or `packet_distribution_path=`, stop and regenerate it with explicit absolute paths
- if an operator cannot map their running process back to one `validator_entry=`, stop
- if the packet names a validator but does not name the owning operator, treat the ceremony as incomplete

Required files:

```bash
ls trillionnium-rust/configs/node1.toml trillionnium-rust/configs/node2.toml trillionnium-rust/configs/node3.toml trillionnium-rust/configs/node4.toml
```

Recommended targeted validation:

```bash
python3 scripts/v2/check_validator_config_bundle.py \
  trillionnium-rust/configs/node1.toml \
  trillionnium-rust/configs/node2.toml \
  trillionnium-rust/configs/node3.toml \
  trillionnium-rust/configs/node4.toml
python3 scripts/v2/check_validator_config_bundle.py \
  --emit-ceremony-packet \
  --genesis-artifact-path /abs/path/to/genesis.json \
  --genesis-artifact-sha256 <64-char-sha256> \
  trillionnium-rust/configs/node1.toml \
  trillionnium-rust/configs/node2.toml \
  trillionnium-rust/configs/node3.toml \
  trillionnium-rust/configs/node4.toml
cargo check -p trnm-node -q
```

The `--emit-ceremony-packet` mode is meant to reduce operator transcription drift: it reuses the validated `node_id` / `config_path` / `p2p_addr` / `rpc_addr` tuple from the actual config bundle instead of retyping each `validator_entry=` by hand. For `--ceremony-scope public-mainnet-input`, it also resolves each emitted `config_path` to an absolute path so the packet can be reviewed without shell-relative ambiguity.

For any packet expected to feed a signed/public-mainnet readiness review, prefer generating the skeleton with the ceremony metadata filled in up front instead of forwarding a packet that still contains placeholder fields. The packet generator now fails closed if `--ceremony-id` is left as a `<placeholder>` value under `--ceremony-scope public-mainnet-input`:

```bash
python3 scripts/v2/check_validator_config_bundle.py \
  --emit-ceremony-packet \
  --ceremony-id mn04-bootstrap-20260331-0621Z \
  --ceremony-scope public-mainnet-input \
  --packet-generated-at 2026-03-31T06:21:00Z \
  --packet-distribution-path /abs/path/or/ticket \
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

Fail-closed rule for generated packets:
- if `packet_generated_at=` or `packet_distribution_path=` is still a placeholder when the packet is shared for operator acknowledgment, do not treat the packet as ceremony-ready
- if `ceremony_scope=public-mainnet-input`, require operators to replace the per-validator `<owner-for-<validator>>` / `<chat/email/oncall-for-<validator>>` placeholders plus any `<optional-ack-path>` / `<optional-sha256-of-ack>` placeholders before startup instead of relying on a later cleanup pass
- if `ceremony_scope=public-mainnet-input`, do not treat a generated packet as signed/public-mainnet handoff evidence until every `validator_entry=` has a named owner/contact and every `operator_ack` / `operator_ack_signature_path` / `operator_ack_digest` line has been filled with the real acknowledgment artifact or digest for that validator; when `validator_entry_hash=` is emitted, each acknowledgment must quote the same hash verbatim, and each acknowledgment must also reuse the emitted absolute `config_path=` verbatim instead of rewriting it as a shell-relative path
- if `ceremony_scope=public-mainnet-input`, require `genesis_artifact_path=` and `packet_distribution_path=` to be explicit absolute paths rather than relative paths copied from a local shell
- if `ceremony_scope=public-mainnet-input`, require `genesis_artifact_sha256=` to be a real 64-character hex SHA-256 digest instead of a shorthand label or truncated checksum

### Signed handoff evidence bundle (public-mainnet-input)

For any packet that will be cited outside a local rehearsal, archive one small evidence bundle alongside the packet instead of relying on chat history:
- the exact generated ceremony packet file referenced by `packet_distribution_path=`
- the exact genesis artifact digest record used by the packet (`genesis_artifact_path=` + `genesis_artifact_sha256=`)
- one acknowledgment artifact per validator owner, where each artifact names the same `ceremony_id=`, `validator_name=`, `config_path=`, and `genesis_artifact_sha256=` that appear in the shared packet
- if `validator_entry_hash=` is used, require each operator acknowledgment artifact to quote the same hash so later review can tie the acknowledgment back to one immutable validator descriptor

Minimum review rule:
- if an operator acknowledgment cannot be matched back to the packet by `ceremony_id=` plus either `validator_name=` or `validator_entry_hash=`, treat the acknowledgment as unusable for signed/public-mainnet handoff evidence

What this proves:
- the named validator config bundle has no duplicate node identity or reused listen addresses
- the validator config loader still compiles
- operator-facing config validation logic is present before you attempt runtime startup
- the bootstrap evidence can name which genesis artifact/hash this config bundle is expected to join

If only shell automation changed, also syntax-check the touched script before using it:

```bash
bash -n scripts/<touched-script>.sh
```

If the config bundle check fails, treat the bootstrap as blocked until the duplicate node/address assignment is resolved explicitly.

## Step 4 — Bootstrap the validator in the smallest credible way

For a local bootstrap sanity pass, start with the known config entrypoint instead of ad-hoc flags:

```bash
cargo run -q -p trnm-node -- \
  --config trillionnium-rust/configs/node1.toml \
  --block-ms 5 \
  --max-blocks 6 \
  --demo-tasks 8 \
  --demo-keys 3 \
  --parallel-workers 4
```

Interpretation rule:
- use the exact config file you intend to hand off or compare against
- if the bootstrap attempt requires unexplained one-off flags, record them explicitly or treat the run as non-reproducible
- if the node only boots in a dirty worktree or with unstaged config edits, treat the bootstrap as failed

## Step 5 — Re-bootstrap after rebuild or drift

Use re-bootstrap when the host was rebuilt, the process state is ambiguous, or prior artifacts cannot be trusted.

Minimum sequence:
1. re-run Step 1 and Step 2
2. re-check the expected config file set
3. re-run the targeted validation command(s)
4. perform the smallest bootstrap sanity start again
5. record whether this is a fresh bootstrap or a re-bootstrap in the handoff note

Mandatory note in the evidence:
- why the re-bootstrap was required
- which validator identity/worktree now owns the process
- what exact rollback command returns the operator to the last known-good state

### Rebuild / disaster-recovery evidence minimum

When the re-bootstrap follows host rebuild, disk replacement, or other disaster-recovery work, capture one minimal evidence packet before calling the validator recovered:
- `dr_trigger=` short description of the failure or rebuild trigger
- `rebuild_scope=` what was replaced or rebuilt (host / disk / process-only / config-only)
- `config_bundle_sha256=` one checksum covering the config bundle actually used for the recovered bootstrap
- `genesis_artifact_path=` and `genesis_artifact_sha256=` copied from the validated bootstrap packet, not retyped from memory
- `validator_identity_check=` naming the validator entry or node ID that was recovered
- `preflight_command=` and `preflight_result=` for the exact validation command rerun after rebuild
- `bootstrap_command=` and `bootstrap_result=` for the smallest sanity start used to prove the node can come back
- `rollback_command=` that returns the operator to the previously known-good artifact/worktree if the rebuilt node is rejected
- `captured_at_utc=` recorded in UTC for later handoff or audit comparison

Fail closed on DR evidence too:
- if the recovered node cannot be tied to the same validator identity/config bundle/genesis hash tuple, do not mark the rebuild as successful
- if the rebuild changed any config values intentionally, record that delta explicitly in the handoff note instead of implying a like-for-like recovery
- if `config_bundle_sha256=` was not captured from the bundle that actually booted, treat the DR packet as incomplete

## Step 6 — Validator replacement / rotation preflight minimum

Use this when one validator is being replaced, the signing/ownership context is rotating, or the validator membership packet changes between rehearsals.
This is still a manual fail-closed procedure, not replacement automation.

Minimum packet delta before any replacement node starts:
- `replacement_reason=` why the old validator/process is being replaced
- `replaced_validator_name=` and `replaced_node_id=` for the validator leaving service
- `replacement_validator_name=` and `replacement_node_id=` for the validator entering service
- `old_config_path=` and `new_config_path=` naming the exact before/after config files under review
- `validator_set_version_before=` and `validator_set_version_after=` so operators can tell whether this is a same-membership rebuild or an actual validator-set change
- `genesis_artifact_sha256=` copied from the shared ceremony packet so the replacement cannot silently drift onto a different chain view
- `operator_ack=` from both the outgoing owner (or incident commander if the old owner is unavailable) and the incoming owner, each naming the same `replacement_validator_name=` / `replacement_node_id=` pair
- `cutover_owner=` naming who is authorized to declare the old validator stopped and the replacement allowed to start
- `cutover_window_utc=` naming the intended UTC cutover window instead of relying on chat-relative timing

Minimum command sequence:
1. re-run the config bundle validation against the exact post-rotation config set
2. verify the outgoing validator process is stopped or quarantined before starting the replacement
3. run the smallest bootstrap sanity start for the replacement validator using the reviewed `new_config_path=`
4. record the rollback command that restores the previous validator packet/worktree if the replacement is rejected

Minimum evidence to keep with the packet:
- `old_validator_stop_command=` and `old_validator_stop_result=`
- `replacement_preflight_command=` and `replacement_preflight_result=`
- `replacement_bootstrap_command=` and `replacement_bootstrap_result=`
- `rollback_command=` pointing back to the last known-good validator packet/worktree
- `captured_at_utc=` recorded after the replacement sanity check finishes

Fail-closed rule:
- if the outgoing validator might still be signing, do not start the replacement
- if operators cannot name the before/after validator-set version labels, treat the rotation as evidence-incomplete
- if the replacement packet changes both validator identity and genesis hash in the same step, stop and split the operation into separate reviewed changes
- if the replacement bootstrap succeeds only with undocumented one-off flags or unstaged edits, reject the cutover as non-reproducible

## Rollback

Before starting, the operator should already know which of these applies:
- stop the just-started validator process
- return to the previously recorded clean commit/worktree
- discard the attempted handoff and mark the bootstrap as No-Go

Typical rollback command shape:

```bash
pkill -f 'trnm-node|cometbft'
```

Use a more precise process selector if multiple rehearsals may exist on the same host.

## Minimum handoff fields

When passing bootstrap status to another validator/operator, record:
- worktree path
- branch ref
- HEAD commit
- genesis artifact/hash expected by this bootstrap
- config file used for bootstrap
- commands run
- pass/fail result
- rollback command
- whether the run was bootstrap or re-bootstrap
- one-line blocker if the run is not cleanly reproducible

If the bootstrap is being cited in a rehearsal/handoff packet rather than a local-only sanity pass, also resolve the generated evidence paths with the assigned lane values instead of quoting "latest artifact" from shell memory:

```bash
./scripts/v2/extract_release_handoff_fields.sh \
  --expected-worktree-root /abs/path/from-ticket \
  --expected-branch-ref refs/heads/lane/assigned-branch
```

Preserve the resulting `summary_path=`, `manifest_path=`, `git_worktree_path=`, `git_worktree_branch_ref=`, `git_worktree_branch_ref_match=`, `truth_source=`, `historical_evidence_only=`, `evidence_scope=`, `rollback_command=`, and `replay_command=` fields next to any PASS/GO language.

Fail-closed rule:
- if either artifact path cannot be resolved, do not cite the bootstrap as handoff-ready evidence
- if `git_worktree_branch_ref_match` is not `true`, stop instead of treating the bootstrap as "close enough"

## Non-go conditions

Treat the bootstrap as **No-Go** if any of the following is true:
- worktree or branch identity is not proven
- the expected genesis artifact/hash cannot be named unambiguously
- config files exist but were not actually the ones used at runtime
- a second validator process may still own the signing context
- bootstrap required unstaged edits or undocumented manual steps
- the operator cannot provide a rollback command immediately

This runbook closes the documentation gap for validator bootstrap / re-bootstrap procedure, but it does **not** close broader mainnet requirements such as genesis ceremony, validator rotation, disaster recovery automation, or public-network handoff evidence.
