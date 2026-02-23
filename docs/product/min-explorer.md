# P1-4 #2 Minimal Explorer（本地）

提供一个本地可运行的最小区块浏览器（轻量 Python HTTP 服务）：

- 地址页：`/address/<address>`（`balance` / `nonce` / recent tx）
- 交易页：`/tx/<tx_hash>`（`status` / `error`）
- 区块页：`/block/<height>`（`height` / `state_root`）

实现文件：`scripts/min_explorer.py`

---

## 1) 启动

在仓库根目录执行：

```bash
python3 scripts/min_explorer.py --host 127.0.0.1 --port 8090
```

启动后访问：

- 主页：<http://127.0.0.1:8090>
- 地址页：<http://127.0.0.1:8090/address/trnm1...>
- 交易页：<http://127.0.0.1:8090/tx/0x...>
- 区块页：<http://127.0.0.1:8090/block/1>

---

## 2) 数据来源

Explorer 读取本地运行产物，不直接依赖远程服务：

- 账户状态：`run/rpc/accounts.json`
- 交易生命周期：`run/rpc/txs.json`
- 区块日志（提取 `height/state_root`）：
  - `run/parallel-sanity.log`
  - `run/node1.log`
  - `run/node2.log`
  - `run/node3.log`

> 若页面提示 not found，通常是对应数据文件尚未生成。

---

## 3) 先准备示例数据（可选）

如果你还没有 `run/rpc/*.json`，可先跑一次产品层 smoke：

```bash
./scripts/v2/product_layer_smoke.sh
```

然后再打开 explorer。

---

## 4) 说明

- 该 Explorer 目标是 **最小可用验证**（P1-4 #2），用于本地联调和验收。
- 当前不包含高级功能（分页、搜索索引、实时订阅、复杂统计）。
- 页面是轻量 server-side 渲染，零第三方依赖（Python 标准库）。
