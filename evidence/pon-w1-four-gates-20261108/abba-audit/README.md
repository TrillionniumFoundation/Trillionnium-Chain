# 原 80 行共同资源 ABBA 的严格独立审计

[实际结果](result.json) 由 `scripts/audit_w1_deployment_comparison.py` 对两份原始 `result.json` 的独立 SHA256 pin、intent、80 个 raw row、stage、stdout 与最终 cancellation 状态重新检查形成。原始实验未重跑，新增完整 proof 数为 0。

| 实际统计口径 | 原 proof 1 | 原 proof 2 |
| --- | ---: | ---: |
| 通过的 verification 行 | 40 | 40 |
| 完整 ABBA block | 10 | 10 |
| 原边际中位数的 proof/native 比 | 13.0634904873 | 13.4308277868 |
| 每 block 两组均值之比，再取中位数 | 12.0628448679 | 13.7398970544 |
| 每 block proof−native 均值差的中位数（ms） | 31.26346375 | 32.00626050 |

两种比值统计不同，不能互换。全部 20 个 block 中 proof 验证更慢；本记录不推断随机化因果效应、总体尾分布或生成方案性能。载荷比仍为原记录的 5.191573。

独立固定的两个 report SHA256 分别为 `1c20ddb6496e9576ad84d77f9af1e9220a3ef50fe257d0593d6a651103b4f8bc` 与 `d1a0d767680d1304231088911461b0b42dd7a19a8f6a3f3f282ed073c1c29a3d`。原件在 [上一轮成本记录](../../pon-w1-fresh-runtime-20261107/cost-common-rayon2/readback.json) 所引用的 raw 包中。本目录不改写上一轮记录。

审计没有取得原 controller 的新增独立退出见证，也没有完整历史进程、GPU、资源付费、业务预算、Node admission 或部署 qualification；这些机器字段均保持 false / null。新审计的 20 项负控制及全部 80 个实际行已通过。
