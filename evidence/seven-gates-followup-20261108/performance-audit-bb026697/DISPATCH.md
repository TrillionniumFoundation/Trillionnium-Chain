# F0 已注册 dispatch 入口的只读复核

复核时间：**2026-11-08T18:20:41.690372Z**。通过 HeptaRuntime desktop 的绝对路径 `/usr/bin/gh` 执行 GET，身份为 **ProfHepta**。**本审计没有 dispatch。**

## 已证实的请求前置条件

- F0 注册 ID：**399731485**；path：`.github/workflows/pon-fixed-host-root-f0.yml`；state：**active**。
- 仓库 workflows 总数 388；分页 1–4（100/100/100/88）已读，F0 只有一项，位于第 2 页；direct workflow GET 返回相同 ID/path/state。
- branch `fix/chain-seven-gates-followup-20261108-3a20` 的真实 Git ref 指向 **bb026697a972521009bc133ae6ed2b653e18e931**。
- 该 SHA 的远端 YAML blob 为 `733184b54aba30ab56c5a076bcfefdea31e1e2b1`，17,173 bytes，SHA256 为 `89e5058056006cee4d24dcfe1afa52e991bd40959bfa19463878b0a7ad168093`，与审查的本地 bb 文件逐字节相符。
- `workflow_dispatch:` 为无 inputs 的空声明；**没有 required/default inputs**，没有 expected_head/resource/timeout/test-selector 参数。
- `GET actions/workflows/399731485/runs?head_sha=bb026697a972521009bc133ae6ed2b653e18e931&per_page=100` 返回 **total_count=0**。此查询没有 event/status 过滤，因此当时同 head 的 queued、in_progress、completed dispatch 或 PR run 都不存在。
- `GET actions/workflows/399731485/runs?event=workflow_dispatch&per_page=5` 亦返回 **total_count=0**：没有可借用的历史 manual dispatch 成功记录。

**main 文件读取 404 仍是原观察，但它不证明 workflow 未注册。** 以本次 direct metadata 和完整 workflows 集合的真实注册证据补齐初轮“手动入口未验证”。这里验证的是注册项、源声明、身份、ref 和去重前置条件，不是声称服务器已经接受一次尚未发送的 dispatch。

## 可执行的一次性命令

由 root 按现有授权通过 HeptaRuntime ProfHepta 执行：

```bash
/usr/bin/gh workflow run 399731485 \
  --repo TrillionniumFoundation/Trillionnium-Chain \
  --ref fix/chain-seven-gates-followup-20261108-3a20
```

对应唯一请求体：

```json
{"ref":"fix/chain-seven-gates-followup-20261108-3a20"}
```

**不传 `-f/-F` inputs，不改变 main、guard、源码、资源或测试选择。** 发送前仍应确认 ref 未前移；此 workflow 没有独立 expected_head input，dispatch 时 checkout 的是事件 `github.sha`。请求后须记录新 run ID，并核验 `workflow_id=399731485`、`event=workflow_dispatch`、`head_sha=bb026697a972521009bc133ae6ed2b653e18e931`。若返回状态 Unknown，先 GET 对账，不盲重发。

## 副作用与仍保留的 HOLD

精确 bb workflow 只有 `contents: read`，没有 environment/deployment、仓库 push、release、生产激活、secret 配置修改或真钱支付步骤。checkout 禁止 persist-credentials；标准 Actions checkout 和 artifact 上传仍使用平台自身凭证机制，不能说完全不使用凭证。

实际动作包括 hosted runner 安装 Rust 1.95.0/锁定依赖、fmt/strict Clippy/build/7 controls、一对 baseline+ROOT 的原生 phase、固定 runtime slice 与精确 ownership 服务的 provisioning/清理、以及上传成功/失败/部分证据保留 30 天。它消耗 CI 与 artifact 资源。job 上限 100 分钟，controller 600 秒，native selector 540 秒，各 phase service 300 秒。

全部原始四秒、depth6、quarter-core 限制不变；42 包暴露仍是 6 个确认槽，不是 42 笔业务交易。F0 的 finite 结果仍不关闭完整 qualified goodput、全业务尾延迟、独立 WAN、整链 PQ 或生产资格。

原始 GET 输出与精简结论分别保存于 `f0-metadata-first-get.json`、`f0-registry-history-get.json`、`dispatch-verification.json`；它们不包含 dispatch 执行回执。

