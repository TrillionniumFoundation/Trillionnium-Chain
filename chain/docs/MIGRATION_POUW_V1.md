# Migration Guide: PoUW V1

## Who should read this

- Operators upgrading from pre-PoUW challenge flow
- Integrators using `update-task` to complete tasks
- Automation users running workload tx/query CLI flows

---

## Breaking/Behavioral Changes

### 1) Settlement path changed

Old:
- `create-task` -> `update-task(status=2)`

New recommended:
- `create-task` -> `submit-result` -> optional `challenge-result` -> `resolve-challenge` or auto-finalize

### 2) Challenge lifecycle is first-class

Task result is no longer assumed final immediately after submission.
Finalization happens after:
- challenge resolution, or
- challenge-window timeout (auto finalize)

### 3) `update-task` is deprecated

`update-task` still exists for compatibility, but should not be used by production worker flows.

---

## Parameter Baseline (recommended starting profile)

- `workload_denom`: `utrnm`
- `challenge_window_blocks`: `100`
- `challenge_deposit`: `1000000`
- `challenger_slash_percent`: `10`
- `worker_slash_percent_on_bad_result`: `20`

### Tuning notes

- Increase `challenge_window_blocks` if re-execution/verifier latency is high.
- Increase `challenge_deposit` if spam challenges appear.
- Increase `challenger_slash_percent` to further discourage low-quality challenges.
- Keep `worker_slash_percent_on_bad_result` below governance risk tolerance.

---

## CLI Migration Cheatsheet

### Submit result

```bash
chaind tx workload submit-result <task-id> <result-hash> <result-uri> --from <worker> ...
```

### Challenge result

```bash
chaind tx workload challenge-result <task-id> <reason> <evidence-uri> --from <challenger> ...
```

### Resolve challenge (authority)

```bash
chaind tx workload resolve-challenge <task-id> <challenge-succeeded> <final-result-hash> <memo> --from <authority> ...
```

### Query challenges

```bash
chaind query workload list-challenge
chaind query workload show-challenge <id>
```

---

## Validation Checklist

- Run keeper e2e regression bundle:

```bash
make smoke-pouw-e2e
```

- Run CLI smoke scenario:

```bash
./tools/smoke_pouw_cli_flow.sh
```

- Run full test suite:

```bash
go test ./... -count=1
```
