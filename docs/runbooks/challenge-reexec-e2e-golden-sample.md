# Challenge Re-exec 单入口复跑（Golden Sample 规范）

本文定义 `scripts/challenge_reexec_e2e.sh` 的输出目录规范，并给出可复跑示例。

## 1) 单入口脚本

```bash
scripts/challenge_reexec_e2e.sh [run_id] [task_id] [match|mismatch] [reexec_hash] [orig_hash]
```

- 默认 `run_id`：`YYYYmmdd-HHMMSS`
- 也可通过环境变量覆盖：`RUN_ID/TASK_ID/OUTCOME/REEXEC_HASH/ORIG_HASH/OUT_DIR`

执行链路：

1. `challenge_reexec_bundle.sh`（产出 decision + template + summary）
2. `challenge_reexec_resolve_template.sh`（独立生成 template）
3. verify（最小断言）
4. `challenge_reexec_template_smoke.sh`（能力冒烟）

---

## 2) Golden Sample 目录规范

默认目录：`data/reexec-e2e/<run_id>/`

```text
data/reexec-e2e/<run_id>/
├── README.md
├── bundle/
│   ├── decision.json
│   ├── resolve-template.txt
│   └── summary.md
├── template/
│   └── resolve-template.txt
├── verify/
│   ├── smoke.log
│   └── warn.txt            # 可选：当 bundle/template 不一致时出现
└── smoke/
    ├── decision.json
    ├── resolve-template.txt
    └── summary.md
```

说明：
- `bundle/` 是主产物（用于归档/提交）
- `template/` 是独立重建产物（用于一致性比对）
- `verify/` 保留验证日志
- `smoke/` 是沿用现有脚本的回归冒烟产物

---

## 3) 示例（mismatch）

```bash
scripts/challenge_reexec_e2e.sh 20260222-1300 task-demo-001 mismatch 0xreexecabc 0xorigin
```

成功时标准输出会打印 run root，例如：

```text
data/reexec-e2e/20260222-1300
```

可重点检查：

- `bundle/decision.json` 中 `challenge_succeeded=true`
- `bundle/resolve-template.txt` 中 `resolve-challenge`
- `verify/smoke.log` 包含 `[OK] challenge reexec bundle smoke`

---

## 4) 兼容性

- 不改动既有脚本：
  - `scripts/challenge_reexec_bundle.sh`
  - `scripts/challenge_reexec_resolve_template.sh`
  - `scripts/challenge_reexec_template_smoke.sh`
- 单入口仅做编排与最小验证。