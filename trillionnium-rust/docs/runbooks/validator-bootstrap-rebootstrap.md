# TRNM Validator Bootstrap / Re-bootstrap Runbook

Fail-closed operator checklist for bringing up a validator from a clean worktree, or rebuilding the same validator after host/process replacement.

This runbook is intentionally narrow:
- it does **not** declare TRNM public-mainnet ready by itself
- it does provide a reproducible bootstrap / re-bootstrap procedure bound to an exact worktree, branch, and validator config set
- it prefers explicit stop conditions over "probably fine" operator judgment

## Scope

Use this when an operator needs to:
- bootstrap a validator from a clean checked-out worktree
- re-bootstrap after host rebuild, process loss, or local environment drift
- prove the validator config bundle and worktree identity before handing off to another operator

Primary references:
- `docs/release/TRNM_VALIDATOR_RELEASE_HANDOFF.md`
- `docs/runbooks/local-release-evidence.md`
- `scripts/v2/verify_lane_worktree.sh`
- `configs/node1.toml`
- `configs/node2.toml`
- `configs/node3.toml`
- `configs/node4.toml`

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

Prefer the shared fail-closed helper instead of trusting the shell prompt:

```bash
EXPECTED_WORKTREE_ROOT="/abs/path/from-ticket"
EXPECTED_BRANCH_REF="refs/heads/lane/assigned-branch"

./scripts/v2/verify_lane_worktree.sh \
  --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
  --expected-branch-ref "$EXPECTED_BRANCH_REF"
```

Minimum evidence to record:
- `verified_worktree=`
- `verified_branch_ref=`
- `verified_head=`

Stop conditions:
- worktree mismatch
- branch mismatch
- detached HEAD
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
- `genesis_artifact_path=` and `genesis_artifact_sha256=` copied exactly once as the shared ceremony anchor
- `validator_set_version=` identifying the exact validator membership list under review
- `validator_entry=` repeated once per validator with `validator_name`, `node_id`, `config_path`, `p2p_addr`, and `rpc_addr`
- `validator_entry_hash=` or equivalent per-validator fingerprint if a generated validator descriptor exists
- `operator_ack=` repeated once per operator/validator owner, confirming they checked the same genesis hash and config path
- `startup_order_note=` stating whether startup order matters for this rehearsal and who is expected to start first
- `rollback_owner=` naming who can declare the ceremony aborted and which command/process stop is authoritative

Fail-closed rule:
- if two validators claim the same `node_id`, stop
- if two validators point at different genesis hashes for the same `ceremony_id`, stop
- if an operator cannot map their running process back to one `validator_entry=`, stop
- if the packet names a validator but does not name the owning operator, treat the ceremony as incomplete

Required files:

```bash
ls configs/node1.toml configs/node2.toml configs/node3.toml configs/node4.toml
```

Recommended targeted validation:

```bash
python3 scripts/v2/check_validator_config_bundle.py \
  configs/node1.toml \
  configs/node2.toml \
  configs/node3.toml \
  configs/node4.toml
cargo check -p trnm-node -q
```

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
  --config configs/node1.toml \
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

## Non-go conditions

Treat the bootstrap as **No-Go** if any of the following is true:
- worktree or branch identity is not proven
- the expected genesis artifact/hash cannot be named unambiguously
- config files exist but were not actually the ones used at runtime
- a second validator process may still own the signing context
- bootstrap required unstaged edits or undocumented manual steps
- the operator cannot provide a rollback command immediately

This runbook closes the documentation gap for validator bootstrap / re-bootstrap procedure, but it does **not** close broader mainnet requirements such as genesis ceremony, validator rotation, disaster recovery automation, or public-network handoff evidence.
