# Worker-Agent MVP (PoUW)

`trnm-worker-agent` 是 AI worker 接入 PoUW 的最小骨架，包含：
- `pull-task`：拉取任务（本地状态模拟）
- `execute`：执行任务并产出 `result_hash` / `salt`
- `commit-reveal`：生成 commit/reveal 上链命令模板
- `run-once`：一键完成 pull+execute+commit/reveal 模板输出（JSON）

## Quick run
```bash
cd trillionnium-rust
cargo run -q -p trnm-worker-agent -- pull-task --state worker-state.json
cargo run -q -p trnm-worker-agent -- execute --task-id 1001 --worker worker1 --payload "hello"
cargo run -q -p trnm-worker-agent -- commit-reveal --task-id 1001 --worker worker1 --result-hash <hash> --salt-hex <salt>

# one-shot JSON output (recommended)
cargo run -q -p trnm-worker-agent -- run-once --state /tmp/worker-state.json --worker worker1 --payload "hello"

# optional submit mode (append submission records)
cargo run -q -p trnm-worker-agent -- run-once --state /tmp/worker-state.json --worker worker1 --payload "hello" --submit --submit-log /tmp/trnm-submits.jsonl
```

E2E smoke:
```bash
./scripts/v2/worker_agent_e2e_demo.sh
```

Submission relay dry-run:
```bash
cargo run -q -p trnm-worker-agent -- flush-submissions --submit-log /tmp/trnm-worker-agent-submits.jsonl --adapter-cmd "./scripts/worker_tx_adapter.sh"
```

Submission relay execute (local adapter, with retry + ack dedupe):
```bash
cargo run -q -p trnm-worker-agent -- flush-submissions --submit-log /tmp/trnm-worker-agent-submits.jsonl --execute --adapter-cmd "./scripts/worker_tx_adapter.sh" --max-retries 3 --backoff-ms 200 --ack-log /tmp/trnm-worker-agent-acks.jsonl
```

Adapter modes:
- `TRNM_TX_ADAPTER_MODE=mock`（默认，本地 receipt）
- `TRNM_TX_ADAPTER_MODE=command`（调用外部 tx cli）
- `TRNM_TX_CLI=<your_cli>`（例如先用 `echo` 演练）

示例：
```bash
TRNM_TX_ADAPTER_MODE=command TRNM_TX_CLI=echo ./scripts/v2/worker_agent_full_loop.sh
```

RPC verification:
```bash
./scripts/v2/worker_agent_verify_with_rpc.sh 42
```

Full loop (run-once -> submit -> relay execute -> rpc verify):
```bash
./scripts/v2/worker_agent_full_loop.sh
```
