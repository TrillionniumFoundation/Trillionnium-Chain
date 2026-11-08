# C1b 真实取消的独立费用读回

原始 C1b 操作不变。本次仅在已保留、SHA-256 固定的历史 SQLite **副本**上进行只读查询；没有连接原数据库，没有签名、Node 调用、派发、退款提交或 provider 付款。

## 已闭合的小项

| 项目 | Reserve | Cancel |
| --- | ---: | ---: |
| 实际 PNX1 tag | 2 | 3 |
| 实际签名 wire 字节 | 239 | 191 |
| 精确 C1b 配置的 base fee | 180 | 100 |
| byte fee units | 1 | 1 |
| 独立计算费用 | **419** | **291** |
| 实际账户净变化 | −1,419 | +709 |

先从原始 wire 解出网络、owner、nonce、expiry、fee limit、tag 和 payload，再从原执行源码 `0f18f93f2d35b62c6ca6d63faf4f336d55cbf4bf` 的 ledger/devnet 配置计算费用。最后才与 canonical 状态变更对照。因此 291 和 419 现在有独立依据，不再仅是余额差额。

本金退款为 **1,000**；取消区块净增加 **709**；Reserve 加 Cancel 的净变化 **−710**。两个 nonce 分别是 1、2；同一 task ID 从其原始字段和域独立重算匹配。

两份 Ed25519 签名均对原域摘要重新验证。分别改变签名和 payload 的四个反例均被拒绝。实际 PNP2 交易向量、完整 wire、固定 header/trace block ID 与原 canonical packet 绑定；账号 witness 字节也匹配 header commitment。没有重新验证 W1 或账号 multiproof，没有重新执行 native M06。

## 原件

- [result.json](result.json)：完整上下文、源码/原件哈希、独立解码及实际余额对照。
- [readback.py](readback.py)：实际执行的只读收集/验证脚本。
- [reserve-wire.bin](reserve-wire.bin)、[cancel-wire.bin](cancel-wire.bin)：原始签名 wire。
- [reserve-packet.bin](reserve-packet.bin)、[cancel-packet.bin](cancel-packet.bin)：对应原 canonical packet。
- [ledger-v1.json](ledger-v1.json)、[devnet-v1.json](devnet-v1.json)：从精确 C1b git object 读取的费用配置。

此结果不改变旧 [funding-readback](../../pon-w1-fresh-runtime-20261107/owner-cancellation-C1b/funding-readback.json)，其保留时尚未独立解码费用的描述仍为当时事实。本次补充结果没有授权释放 M12 cap；GPU/完整历史资源未知、provider 未付款等边界继续保留。
