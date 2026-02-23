# TRNM SDK 示例（JavaScript，10 分钟接入）

目标流程：**create wallet -> faucet -> sendTx -> getTx**

> 适用对象：对接 Trillionnium 产品层最小 API（`balance / nonce / faucetRequest / sendTx / getTx`）的前端或 Bot 开发者。

## 1) 前置条件

- Node.js >= 18（需内置 `fetch`）
- 已有可访问的 RPC 网关地址（默认 `http://127.0.0.1:8545`）
- RPC 支持方法：
  - `balance(address)`
  - `nonce(address)`
  - `sendTx(from,to,amount,fee,denom,nonce,signature)`
  - `getTx(txHash)`
  - faucet：优先 `faucetRequest(address,amount)`，兼容尝试 `faucet(address,amount)`

## 2) 安装依赖

```bash
cd examples/sdk-js
npm install
```

## 3) 运行示例

```bash
# 默认连本地 8545
npm start

# 或自定义参数
RPC_URL="http://127.0.0.1:8545" \
DENOM="utrnm" \
FAUCET_AMOUNT="1000000" \
TRANSFER_AMOUNT="1000" \
POLL_MS="800" \
POLL_MAX="20" \
POLL_TIMEOUT_MS="16000" \
npm start
```

## 4) 你会看到什么

- `[1/4] wallets created`：脚本内存中生成 Alice/Bob 钱包（ed25519）
- `[2/4] faucet ok`：给 Alice 申请测试币
- `[3/4] sendTx accepted`：签名并提交转账
- `[4/4] getTx final (terminal)`：轮询交易终态（严格要求 `committed/fail`，不允许 `pending`）

成功后会输出：

```text
DONE: create wallet -> faucet -> sendTx -> getTx
```

---

## 关键实现说明

- 地址 derivation 与 Rust 对齐：`trnm1 + sha256(pubkey)[:20]`
- 签名消息与 Rust 对齐：
  - `trnm-transfer-v1|from=...|to=...|amount=...|fee=...|nonce=...`
- 签名格式与 Rust 对齐：
  - `ed25519:<pubkey_hex>:<signature_hex>`

---

## 常见问题

1. **faucet 报 method not found**
   - 检查网关是否开启 faucet；或确认方法名（`faucetRequest` / `faucet`）。

2. **sendTx 报 invalid signature**
   - 确认消息模板、nonce、from 地址与私钥派生公钥一致。

3. **getTx 一直 pending / 超时失败**
   - 提升 `POLL_MAX` 或 `POLL_TIMEOUT_MS`，并检查后端是否有异步执行/落账延迟。
   - quickstart 会在超时时明确报错：`expect committed/fail, got pending`。
