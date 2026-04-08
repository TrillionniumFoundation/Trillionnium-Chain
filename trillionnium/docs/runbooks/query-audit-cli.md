# Query-Audit CLI（运维最小使用说明）

适用对象：需要从 `run/message-gateway/requests.jsonl` 导出企业审计记录，并按 `task_id` 或 `provenance_fingerprint` 快速检索的运维同学。

## 1) 导出审计数据（JSONL + 索引）

```bash
cd trillionnium
cargo run -q -p trnm-worker-agent -- \
  export-audit \
  --ingress-file run/message-gateway/requests.jsonl \
  --output-file run/audit-export.jsonl
```

执行后会生成两个文件：

- `run/audit-export.jsonl`：审计记录（逐行 JSON）
- `run/audit-export.index.json`：查询索引（由 CLI 自动生成）

> `query-audit` 依赖 `*.index.json` 和 `*.jsonl` 同时存在。

## 2) 按 task_id 查询

```bash
cd trillionnium
cargo run -q -p trnm-worker-agent -- \
  query-audit \
  --output-file run/audit-export.jsonl \
  --task-id 7002
```

返回为 JSON，核心字段：

- `task_id`：查询任务 ID（字符串）
- `hit_indexes`：命中下标数组（长度即命中条数）
- `records`：命中记录列表

## 3) 按 provenance_fingerprint 查询（最小入口）

```bash
cd trillionnium
cargo run -q -p trnm-worker-agent -- \
  query-audit \
  --output-file run/audit-export.jsonl \
  --provenance-fingerprint <FINGERPRINT>
```

返回为 JSON，核心字段：

- `provenance_fingerprint`：查询指纹
- `hit_indexes`：命中下标数组
- `records`：命中记录列表

> `query-audit` 必须二选一：`--task-id` 或 `--provenance-fingerprint`。

## 4) 直接给值班同学的最短命令

```bash
cd trillionnium && \
cargo run -q -p trnm-worker-agent -- export-audit --ingress-file run/message-gateway/requests.jsonl --output-file run/audit-export.jsonl && \
cargo run -q -p trnm-worker-agent -- query-audit --output-file run/audit-export.jsonl --task-id <TASK_ID>
```

将 `<TASK_ID>` 替换为实际值即可。

## 5) 一键 smoke 校验

```bash
cd trillionnium
bash scripts/check_query_audit_smoke.sh
```

通过时会输出 `[OK] query-audit smoke passed ...`。
