# Release Note — 2026-02-19

## Scope
Stability hardening for local chain + worker e2e flow, focused on startup reliability, worker claim behavior, and smoke-test determinism.

## Included in commit
- `75a8948` — `fix(worker): harden job claim flow and stabilize e2e smoke`

## What changed

### 1) Chain startup resilience
- Fixed local node startup precondition by ensuring non-empty minimum gas price config (`0stake`).
- Recovered from `cs.wal` path failure and restored stable block production.

### 2) Worker robustness (`worker/listener.py`)
- Added worker-home awareness (`--home`) for chain CLI calls to avoid environment drift.
- Added startup idempotent registration guard (`workload register-worker`) to prevent first-claim failures.
- Improved tx behavior:
  - retries on `account sequence mismatch`
  - benign classification for expected races (`already registered`, `not in CREATED state`, etc.)
- Added in-flight job tracking to reduce duplicate claim/execute attempts.
- Reduced log noise for expected "already registered" cases.

### 3) Smoke test stability (`scripts/e2e_smoke.sh`)
- Fixed worker cleanup to reliably kill prior worker instances (`pkill -f "main.py start"`).
- Added workload worker registration pre-check and register-on-missing step.
- Keeps deterministic 6-step smoke flow and commit-count validation.

## Validation

### End-to-end smoke
- `scripts/e2e_smoke.sh 1` passed repeatedly.
- Observed successful result commits:
  - Job 6 committed
  - Job 7 committed

### Runtime behavior after fix
- Chain process stable and producing blocks.
- Worker performs claim → execute → complete flow successfully.
- Remaining benign race logs are reduced and non-fatal.

## Known non-blocking noise
- Python environment warning:
  - `urllib3 v2 only supports OpenSSL 1.1.1+ ... LibreSSL 2.8.3`
- This does not block current smoke/e2e flow but is worth cleanup in a later environment pass.

## Recommended next actions
1. Add CI smoke variant that asserts no duplicate worker process before submit.
2. Add optional compute-job status query guard to skip already-running/completed jobs before claim.
3. Normalize Python runtime/OpenSSL to remove urllib3 warning in logs.
