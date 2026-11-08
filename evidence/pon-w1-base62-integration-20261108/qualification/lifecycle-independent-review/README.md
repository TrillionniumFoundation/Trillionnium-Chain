# C6 自然超时、原 Cancel 重组与独立冷恢复窄审

本审阅只读已终态的 C6 原件，没有重新打开 Node、提交交易或运行实验。主入口与独立 cold 的原 durable job 均为 exit 0、完整 durable output，各实际执行 1 个精确 Rust 入口；它们与普通资格方法分开计数。完整结果见 [summary.json](summary.json)，31 份原件的字节哈希见 [input-artifact-index.json](input-artifact-index.json)。

## 独立核实的顺序与绑定

原 deadline 为 `1199343004629858` ns，自选择时刻起严格 120 秒。真实 r0vm 已在 `1199255881430349` ns 被观察到；prove-batch-0000 日志记下 segment 0 与 1 开始实际 proving。目标在 `1199343395352233` ns 以 `original-deadline`、exit -9、sticky_cancel=false 终态，晚于 deadline 0.390722375 秒。随后实际 parent 观察 helper 退出、M12 记录 Unknown Failure，最后才记录 owner 请求；后续观察和清理没有改写证明的原 deadline。

按精确源中的两个 domain 独立重算得到：

- Runtime evidence：`545bfc5d2537aee23a885d24373a121913d8c841a14001e508a0c2e6a0bdbf24`。
- Typed Failure evidence：`f38a93aeecc62d5d46944fe9d44dc48bda90dd368086fadb368da6529b81e880`。

它们绑定原 request、operation/job、配置/source commitment、controller 实际退出观察时刻、timeout reason 与 None resource tag，并与原 Failure 精确一致。Hot 与独立 cold 的 target readback 对象完全相同。

## 资金、重组与 Unknown 资源

原 Unknown Failure 的 consumed=null、cancellation_at_failure=null，不授权本金退款或 provider 付款。后续明确 owner 请求才进入普通 NativeTask Cancel。Fork 去掉该 Cancel 时，资金行回到 Reserved / 1000；cold reopen 保持这个状态。恢复原 ancestry 后，before/restored/final/cold 均为同一个原 Cancel 观察，原 wire、packet、operation 与 inclusion 完全一致；没有重签、重派或新增 native Cancel 交易。

此处退款是本独立研究 fixture 的 gross principal 1000，原件明确不主张净账户增量。Owner 的分支余额差为 709，最终 owner 余额恢复及 provider 余额不变依赖精确 C6 成功状态机断言；本审阅未重放账户。M12 begin=Done 只闭合派发，Unknown 的完整原 resource cap 仍保留：CPU 960000000000 ns、GPU 240000000000 ns、内存上界 8589934592 bytes、receipt cap 16777216 bytes。GPU、实际峰值内存与所有历史后代 wait/reap 仍未知。

M12 cancellation 为 accepted-observed；journal_event_new=null、new_event_proven=false，不能额外主张事件新生证明。实际 target cancel 请求数为 0，因为原 deadline 已令目标终态。

## 与 C5 的身份边界

本次 generation operation 为 `8058cfa81675504da3f0593b8df7c51cb0b1f3fd6db1daa4d3f83172a6d4eacc`，statement 为 `52a53b4c6264f99141cda3d84ee5793dbd9a21778693848435809fbcd3fd4ca6`；它们不同于 C5，使用新的研究 Node 目录，实际外部 driver 要求 out/target/Node 目录在原 launch 前不存在。

固定 seed、genesis 与 NativeTask fixture 会生成与 C5 相同的 NativeCancel ID、191 字节 wire、49953 字节 packet 及 inclusion。这些相同字节不意味着复用旧 Node/M12 operation，也不代表全球新链资金；不能把 C5 与 C6 相加为 2000 单位退款。

## 未建立的资格

这是 1 次真实昂贵生成尝试、0 份新增完整证明、0 次正向 provider 付款。完整资源结算、中奖 W1 Node admission、WAN 和协议／密码学安全均未建立。用于研究资金与 Cancel 的维护块不是该 standalone winning W1 的 admission；原 winner 仍明确 parent_eligibility_checked=false、node_admission=false。成功退出的生命周期测试不能替代这些边界。

