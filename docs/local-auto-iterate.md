# Local Auto-Iterate Workflow (macOS)

这个方案用于在本地持续执行“低风险、小步、可验证”的自动迭代，并内置：

- 暂停/停止开关
- 连续失败熔断（默认 2 次）
- 网络抖动下 push 自动重试
- 自动向 PR（默认 #17）追加轮次评论
- 锁文件避免并发运行

## Scripts

- `scripts/auto_iterate_daemon.sh`：守护循环（主入口）
- `scripts/auto_iterate_round.sh`：执行单轮任务（从 tasks 列表轮转）
- `scripts/auto_iterate.tasks`：任务清单（每行一个命令）

## Quick Start

1. 编辑 `scripts/auto_iterate.tasks`，加入可执行任务命令（每条任务自行完成“改动 + 验证 + commit”）。
2. 在仓库根目录启动：

```bash
bash ./scripts/auto_iterate_daemon.sh
```

3. 观察日志：

```bash
tail -f ./run/auto-iterate/daemon.log
```

## Pause / Resume / Stop

在仓库根目录：

```bash
# 暂停（保留进程）
touch .auto-iterate.pause

# 恢复
rm -f .auto-iterate.pause

# 停止（下一个循环退出）
touch .auto-iterate.stop
```

## 常用环境变量

- `SLEEP_SECONDS`：轮次间隔（默认 30）
- `MAX_CONSEC_FAIL`：连续失败熔断阈值（默认 2）
- `PUSH_RETRIES`：push 重试次数（默认 6）
- `AUTO_PR_COMMENT`：是否自动 PR 评论（默认 1）
- `PR_NUMBER`：目标 PR 编号（默认 17）
- `ROUND_SCRIPT`：单轮执行脚本路径

示例：

```bash
SLEEP_SECONDS=60 MAX_CONSEC_FAIL=3 PUSH_RETRIES=10 bash ./scripts/auto_iterate_daemon.sh
```

## launchd（可选）

可用 `launchd` 常驻运行，建议将工作目录设为仓库根目录，并把 stdout/stderr 指向 `run/auto-iterate/`。

> 注意：任务内容由 `scripts/auto_iterate.tasks` 决定；守护器只负责调度、熔断、重试，不替你生成改动逻辑。
