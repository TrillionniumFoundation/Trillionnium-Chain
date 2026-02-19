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

## 最新运行样本（2026-02-19 晚间）

- 触发来源：`sharp-cr` 完成后导出输入
- 输入目录：`data/verifier-input/20260219-185212`
- 输出目录：`data/rust-verifier-local/20260219-185212`
- 批量执行结果：`processed=3`
- 对齐统计：`matched=3`, `mismatch=0`
- 样本文件：`scenario_C.json`, `scenario_F.json`, `scenario_G.json`

字段级 diff（input vs rust output）结论：
- 共同字段（如 `task_id` / `trace_id` / `committed_hash`）无值差异
- 输入侧独有：`result_hash`, `reveal_salt`, `worker_address`
- 输出侧独有：`expected_hash`, `matched`, `reason`

## 接入现状（更新）

1. ✅ `p1_negative_suite.sh` 已支持 `WITH_RUST_VERIFY=1`（导出+复验自动串联）
2. ✅ `summary.json` 已包含 Rust 复验字段：
   - `with_rust_verify`
   - `rust_verify_rc`
   - `rust_verify_export_dir`
   - `rust_verify_output_dir`
   - `rust_verify_matched`
   - `rust_verify_mismatch`
3. ✅ CI 已包含 Rust verifier PoC workflow（build/test/fixture verification）

## 下一步收敛建议

1. 在 CI 增加“P1 负向套件 + Rust sidecar”联动作业（旁路不阻断主执行）
2. 增加失败样本归档模板（自动保存 mismatch 输入/输出对）
3. 固化统一 evidence 索引（将 `summary.json` 与 `rust-verifier-local/<ts>` 建立可追溯映射）
