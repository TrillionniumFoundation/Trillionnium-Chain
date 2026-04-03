# Web4 Release Closeout Bundle (2026-03-04)

> 历史证据说明：本文仅记录 **2026-03-04 当次 Web4 closeout**；它不是当前仓库的 release truth-source。
> 当前是否 release-ready，请看仓库根 `RELEASE_READINESS.md`；当前仓库入口请看 `README.md`。

## Fixed SHAs
- Branch: `merge/web4-integration-2026-03-02`
- Head SHA: `c7a7dd51a79604655fc88b3af5f4b6e7f3d4e0ba`
- RPC hardening patch SHA: `c7a7dd51a79604655fc88b3af5f4b6e7f3d4e0ba`
- Baseline frontend A/B reference SHAs in history:
  - `9dc71e72e3b39c55ff8e7c7652e87db4f06b62b0` (A attempt, later reverted by `d478b447ae89a901a91dfb2bae5d8f3b3b04592a`)
  - `a24b68b4be87a9d7bcc54d30eb08eeca5a499346` (B semantic mapping hardening)

## Patch status summary
| Patch | Scope | Status | Notes |
|---|---|---|---|
| A | frontend time semantics | Open | Current `adapters.ts` still has `new Date(0)` fallback + conditional `updatedAt`. |
| B | frontend semantic mapping hardening | Partial | `name/owner` already explicit synthetic/unknown, but full per-step green run in this serial execution failed due unrelated workspace test lock contention; change was rolled back per protocol. |
| C | rpc parser hardening | Closed | Hardened `split_whitespace` paths to `split_ascii_whitespace`, controls treated as separators, plus regression test. |
| D | release closeout bundle | Closed | This evidence bundle generated; no actual merge to `main` executed. |

## Gate/test evidence
### Patch C execution (green)
1) Targeted test
- `cargo test -p trnm-rpc normalize_actor_or_signer_treats_controls_as_separators_not_concatenation`
- Result: PASS

2) Workspace tests
- `cargo test --workspace`
- Result: PASS

3) Aggregate release gate
- `./scripts/v2/web4_release_aggregate_gate.sh`
- Result: PASS

4) Frontend checks
- Not required (Patch C touched rpc only).

## Rollback protocol records
- Patch B rollback command executed:
  - `git restore web4-frontend/lib/api-contract/adapters.ts web4-frontend/tests/unit/api-contract-adapters.test.ts`
- Root-cause tag: `RC-WORKSPACE-LOCK-CONTENTION`
  - Failure signature: trnm-rpc integration test intermittent lock contention (`Blocking waiting for file lock on artifact directory`) during `cargo test --workspace` run in Patch B gate sequence.

## Main dry-run conflict list (no real merge)
Dry-run method:
```bash
BASE=$(git merge-base HEAD origin/main)
git merge-tree "$BASE" HEAD origin/main > /tmp/main-merge-tree.txt
grep -n "^<<<<<<<" /tmp/main-merge-tree.txt
```
Result:
- No conflict markers found (`0` conflict hunks in merge-tree output).

## Rollback commands
- Revert Patch C commit:
  - `git revert c7a7dd51a79604655fc88b3af5f4b6e7f3d4e0ba`
- Hard reset to pre-patch state (destructive, local only):
  - `git reset --hard c7a7dd51a79604655fc88b3af5f4b6e7f3d4e0ba^`
- Restore working tree without changing history:
  - `git restore trillionnium-rust/crates/trnm-rpc/src/main.rs`

## Remaining unclosed items + next minimal action
1) Patch A still open (`new Date(0)` fallback exists).
   - Next minimal action:
     - Replace epoch fallback with fail-closed when `version` missing, update/ensure adapter unit test, rerun mandated sequence, commit with `fix(frontend): ...`.
2) Patch B needs clean green rerun evidence in this serial run context.
   - Next minimal action:
     - Re-apply semantic mapping hardening patch (if not already in base state), rerun required sequence after ensuring no concurrent cargo lock holders, commit only when all green.
