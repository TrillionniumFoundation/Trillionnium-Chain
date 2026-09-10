# TRNM Native PoCO Validator Release Handoff

Status: operator handoff contract for native validator releases

## Purpose

This document defines the minimum evidence required to transfer a native TRNM validator release between developers, release owners, operators, and incident responders. It does not declare the network release-ready.

## Required identity fields

Every handoff packet must contain:

```text
repository_url=
branch=
commit_sha=
worktree_status=clean|dirty
release_candidate=
generated_at_utc=
chain_id=
validator_set_id=
node_id=
validator_id=
```

## Binary and configuration evidence

```text
node_binary_path=
node_binary_sha256=
validator_binary_path=
validator_binary_sha256=
cli_binary_path=
cli_binary_sha256=
genesis_path=
genesis_sha256=
node_config_sha256=
validator_config_sha256=
policy_config_sha256=
```

Confirm the native processes with:

```bash
ps -ef | grep -E 'trnm-chain-node|trnm-chain-validator' | grep -v grep
```

Do not capture private keys, seed phrases, signer tokens, or unredacted secret-store paths.

## Minimum release evidence

The handoff must reference passing evidence for:

1. `cargo test --workspace --locked`;
2. native quorum and unique finality per height;
3. signed proposal and vote verification;
4. vote replay and equivocation rejection;
5. deterministic execution and state-root agreement;
6. crash/restart and durable recovery boundaries;
7. round change, offline validator, and partition healing;
8. validator join, removal, replacement, and key rotation;
9. PoCO escrow, consumption, challenge, resolve, expiry, refund, and slashing invariants;
10. rollback, replay, backup, and rebuild drills;
11. metrics, alerts, logs, and incident correlation fields.

## Artifact manifest

```text
summary_path=
summary_sha256=
manifest_path=
manifest_sha256=
raw_logs_root=
rollback_command=
replay_command=
known_failures=
open_blockers=
```

All paths must resolve inside the handed-off artifact root or an explicitly authenticated archive.

## Fail-closed rules

The handoff is invalid when:

- branch, commit, or worktree identity is missing;
- binary hashes do not match the tested artifacts;
- validators disagree on finalized block or state root;
- replay/rollback commands are absent or untested;
- the signer or key-custody boundary is unknown;
- a passing result relies only on simulator output;
- evidence files are missing, mutable, or unhashed.

## Decision block

```text
operator_decision=GO|CONDITIONAL_GO|NO-GO
release_owner=
validator_signoffs=
security_signoff=
limitations=
accepted_risks=
completed_at_utc=
```

Public release remains **NO-GO** until the repository release truth source explicitly closes the selected Day-1 blockers.
