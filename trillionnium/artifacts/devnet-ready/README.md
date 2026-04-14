# Devnet-ready artifacts (2026-03-24)

本目录用于 stage-1 internal devnet-ready 证据，不代表 full RC-ready。

## Contents

- `testlists/`
  - `trnm-state.tests.list`
  - `trnm-rpc.tests.list`
  - `trnm-node.tests.list`
  - `trnm-pouw.tests.list`
  - `trnm-worker-agent.tests.list`
  - `trnm-cli.tests.list`
- `../../run/bft4-smoke-20260324-163130.txt`
- `../../run/bft4-node{1,2,3,4}-20260324-163130.log`

## Refresh commands

```bash
cd trillionnium
for c in trnm-state trnm-rpc trnm-node trnm-pouw trnm-worker-agent trnm-cli; do
  cargo test -p "$c" -- --list > "artifacts/devnet-ready/testlists/${c}.tests.list"
done
./scripts/check_bft_4node_smoke.sh
```

## Notes

- BL09 retirement-prep note: retained `trnm-pouw.tests.list` and the matching refresh command are migration-era compatibility and provenance / audit evidence only. They do not mean PoUW remains the default payout authority or that the default work-unit payout path is still authorized once PoCO settlement is primary.
- `-- --list` 固定测试面，不等于全量通过。
- BFT smoke 是当前 stage-1 最小正向 bring-up 证据。
- full RC evidence 仍应通过 `scripts/run_local_release_evidence.sh` 与 `scripts/release_rc.sh` 生成。
