# Validation Modes（dev / beta / prod）

目的：统一“验证口径”，避免本地放宽逻辑误入生产门禁。

## 模式定义

- `dev`：本地快速迭代，允许宽松校验，强调开发效率。
- `beta`：预发验证，尽量贴近生产，仅保留少量可控放宽。
- `prod`：生产严格口径，不允许宽松分支。

通过环境变量控制：

```bash
MVP_MODE=dev|beta|prod
```

默认：`prod`

---

## 当前口径映射

### 1) check_event_fields.sh
- 变量：`ALLOW_MISSING_RESOLVE_EVENT`
- `dev/beta`：默认可为 `1`
- `prod`：必须 `0`

### 2) check_event_replay_smoke.sh
- 变量：`ALLOW_PARTIAL_EVENT_REPLAY`
- `dev/beta`：默认可为 `1`
- `prod`：必须 `0`

### 3) release_rc.sh
- 作为本地 RC 入口，允许在 `dev/beta` 继承宽松配置。
- `prod` 发布前必须显式：

```bash
MVP_MODE=prod \
ALLOW_MISSING_RESOLVE_EVENT=0 \
ALLOW_PARTIAL_EVENT_REPLAY=0 \
./scripts/release_rc.sh
```

---

## 建议执行规范

### 本地开发
```bash
MVP_MODE=dev ./scripts/release_rc.sh
```

### 预发验收
```bash
MVP_MODE=beta ./scripts/release_rc.sh
```

### 生产前门禁（必须）
```bash
MVP_MODE=prod ./scripts/release_rc.sh
```

并确认日志中不存在“resolve skipped / partial replay”类提示。

---

## CI 要求

- merge-gates / nightly 默认应按 `prod` 口径运行。
- 如需临时放宽，必须在 PR 中显式说明范围、时限与回退计划。
