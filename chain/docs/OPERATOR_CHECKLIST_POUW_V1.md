# Operator Checklist — PoUW V1 (Pre-Testnet / Pre-Release)

Use this checklist before deploying PoUW V1 to shared environments.

## A. Code & Build

- [ ] `go test ./... -count=1` passes
- [ ] `make smoke-pouw-e2e` passes
- [ ] `./tools/smoke_pouw_cli_flow.sh` passes
- [ ] `make check-pouw-cmds` returns `[ok] command hooks found`
- [ ] `chaind tx workload --help` shows `submit-result/challenge-result/resolve-challenge`
- [ ] `chaind query workload --help` shows `list-challenge/show-challenge`

## B. Protocol & State Semantics

- [ ] `submit-result` moves task to RESULT_SUBMITTED
- [ ] `challenge-result` moves task to CHALLENGED and stores challenge object
- [ ] `resolve-challenge(true)` slashes worker and refunds challenger deposit
- [ ] `resolve-challenge(false)` applies challenger penalty+refund and completes task
- [ ] EndBlock auto-finalizes RESULT_SUBMITTED tasks after challenge window expiry
- [ ] Logic does not rely on `challenge_id != 0` to detect challenged state

## C. Economics Parameters (initial baseline)

- [ ] `workload_denom = utrnm`
- [ ] `challenge_window_blocks = 100`
- [ ] `challenge_deposit = 1000000`
- [ ] `challenger_slash_percent = 10`
- [ ] `worker_slash_percent_on_bad_result = 20`

## D. Security / Authority

- [ ] `resolve-challenge` authority is explicitly controlled (gov/module authority)
- [ ] non-authority resolve attempts fail in committed tx result
- [ ] slash percent constraints are enforced by module logic

## E. Migration & Ops

- [ ] Release notes reviewed: `docs/RELEASE_NOTES_POUW_V1.md`
- [ ] Migration guide reviewed: `docs/MIGRATION_POUW_V1.md`
- [ ] Team notified that `update-task` is deprecated for production settlement flow
- [ ] Rollback plan documented (binary/version/config)

## F. Observability

- [ ] Event stream includes submit/challenge/resolve/deprecation events
- [ ] Failed tx raw logs are captured in scripts/CI
- [ ] Node start flags include valid minimum gas price for local smoke

---

## Recommended Go/No-Go Gate

Ship to testnet only when:

1. All A/B/C/D items checked
2. At least one full CLI smoke run recorded with logs
3. At least one independent replay by another operator
