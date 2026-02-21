# Worker-Agent MVP (PoUW)

`trnm-worker-agent` 是 AI worker 接入 PoUW 的最小骨架，包含：
- `pull-task`：拉取任务（本地状态模拟）
- `execute`：执行任务并产出 `result_hash` / `salt`
- `commit-reveal`：生成 commit/reveal 上链命令模板

## Quick run
```bash
cd trillionnium-rust
cargo run -q -p trnm-worker-agent -- pull-task --state worker-state.json
cargo run -q -p trnm-worker-agent -- execute --task-id 1001 --worker worker1 --payload "hello"
cargo run -q -p trnm-worker-agent -- commit-reveal --task-id 1001 --worker worker1 --result-hash <hash> --salt-hex <salt>
```
