# Rust Verifier PoC（旁路验证器）

更新日期：2026-02-19  
目标：在不改链主状态机前提下，用 Rust 实现 commitment 校验旁路。

## 范围

- 输入：`task_id`, `result_hash`, `reveal_salt`, `worker_address`, `committed_hash`
- 逻辑：按现有规则复算
  - `sha256("{task_id}|{result_hash}|{reveal_salt}|{worker_address}")`
- 输出：`matched=true/false` verdict json

## 目录

- `rust/verifier/`：Rust 二进制工程（`trnm-verifier`）
- `rust/verifier/fixtures/`：match/mismatch 样例
- `scripts/run_rust_verifier_poc.sh`：本地一键运行入口
- `.github/workflows/rust-verifier-poc.yml`：CI build/test/fixture check

## 本地运行

```bash
# 需先安装 Rust/cargo
./scripts/run_rust_verifier_poc.sh
```

默认输入：`rust/verifier/fixtures`  
默认输出：`data/rust-verifier-local`

## 命令示例

```bash
cd rust/verifier
cargo run -- verify --input fixtures/match.json --output ../../data/rust-verifier-local/match.verdict.json
cargo run -- batch --input-dir fixtures --output-dir ../../data/rust-verifier-local
```

## 接入现状（已落地）

- 场景脚本已输出结构化标记：`[VERIFIER_INPUT] {...}`（C/F/G）
- 导出脚本：`scripts/export_verifier_inputs.sh`

```bash
# 1) 先跑 P1 套件
./scripts/p1_negative_suite.sh

# 2) 导出 verifier 输入
./scripts/export_verifier_inputs.sh

# 3) 执行 Rust 批量复验
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
INPUT_DIR=data/verifier-input/<ts> OUT_DIR=data/rust-verifier-local/<ts> ./scripts/run_rust_verifier_poc.sh
```

## 下一步接入建议

1. 在 `p1_negative_suite.sh` 增加可选开关（如 `WITH_RUST_VERIFY=1`）自动串起导出+复验
2. 在 summary.json 增加 verifier 汇总字段（matched_total / mismatch_total）
3. 在 CI 增加“链下重验一致性”检查（旁路，不阻断链执行）
