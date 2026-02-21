# Developer Onboarding v1 (C2)

## Quick Start
1. Install Rust toolchain (`cargo --version`).
2. Enter repo and run:
   ```bash
   cd trillionnium-rust
   cargo test --workspace --quiet
   ```
3. Run RPC examples:
   ```bash
   cargo run -q -p trnm-rpc -- query-task 42
   cargo run -q -p trnm-rpc -- query-proposal 9001
   cargo run -q -p trnm-rpc -- query-events 42
   ```

## Expected Fields
- Task query: `task_id,status,worker,bounty,result_hash_hex,version`
- Proposal query: `proposal_id,title,proposer,status,version`
- Event query: `event_type,task_id,from_status,to_status,actor,tx_id,block_height,state_root,ts_unix_ms`

## Troubleshooting
- If `cargo` missing: add `/opt/homebrew/opt/rustup/bin` to `PATH`.
- If tests fail: run `cargo test -p trnm-rpc` first for schema smoke.
