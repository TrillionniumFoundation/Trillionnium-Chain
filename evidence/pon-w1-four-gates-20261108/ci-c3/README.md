# C3 原始 CI 失败读回

本目录只读回已执行的精确 C3 `abab79dac0cb89eb2753d3f579119ac135650eb5` / tree `194808f4a0db5d642aa746beb251ca9e9532cebb`。本次新增原生 campaign = 0，新增 proof = 0。没有改变原窗口、压力、工作负载或业务判据。

## 结果

| 原执行 | 保留结果 |
| --- | --- |
| protocol-contract 的原 4 秒 confirmation | 5 个命名原生测试进程全部成功，但业务 validator 的压力阶段 0/1 确认，末次 History replay 为 `PUBLIC_REQUEST_DEADLINE`；manifest 仍失败 `CONFIRMATION_TARGET`。 |
| fresh-service 中的原始 retained-packet selector | 原生进程退出 0；压力 0/1 确认，最后 History 调用保留原 `IO: Resource temporarily unavailable (os error 11)`，不改标为 typed deadline。 |
| fresh-service 的 fresh-challenge selector | 原生进程退出 101；压力 0/1 确认，末次 replay 为 `PUBLIC_REQUEST_DEADLINE`。 |
| 三次完整 separate-process campaign | 每次确实完成 baseline / from-zero / late-product 三段；全部 9 段原有限业务判据为 false。每次基线只在原 30 秒内确认预定 3 轮中的 1 轮；两类压力段均为 0/3。 |

三次 campaign 均使用原 `authenticated-v1`、1,024 个实际签名 seed transfers、4 个 seed blocks、21 个 business blocks；攻击进程 readiness 为 0 / 24 / 24。阶段 actor 报告均成功且未因 cap/kill 终止，没有 phase startup error；这组业务失败不能沿用旧实验的 Host 父级启动失败解释。

留存的客户端导入观测进一步定位到：三次基线中 7 个已完成 packet commit span 的 wall 合计分别为 11.207397464、11.296986941、11.297084321 秒。各自 History 调用 wall 合计为 0.094359487、0.083584097、0.157937378 秒。这里分别只在同一种 span 内求和；admission、commit、history_import、Host 等区间包含关系不能相加。线程 CPU 不是所有 worker 或完整进程树 CPU。这些观测定位后续工作，不建立因果加速或总体尾延迟结论。

## 原件及可复算性

- [summary.json](summary.json)：逐 phase 原窗口、预定/观察/已确认轮数、错误、接收状态，以及独立列出的完成阶段统计。
- [raw.tar.gz](raw.tar.gz)：从三份完整 ZIP 精确保留的 41 个白名单原件，包括主 report、phase readback、manifest、source/resource records 及日志；没有数据库或二进制载荷。
- [raw-manifest.json](raw-manifest.json)：每件原始字节大小和 SHA-256。
- [readback.py](readback.py)：先核对三份完整 ZIP 的预固定 SHA-256，再提取和计算；不运行 verifier、Node 或 campaign。
- [retrieval-history.json](retrieval-history.json)：保留第一次 240 秒下载超时及独立新路径成功读回。传输重试没有重跑实验。

| GitHub artifact | ZIP 字节 | SHA-256 |
| --- | ---: | --- |
| [protocol 13598537139](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42433029659/artifacts/13598537139) | 5,997,415 | `8c7fa04540912d6e5514893da14e369c729131e8bc3700a66d79d6f4a6aea538` |
| [fresh 13598253920](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42433029674/artifacts/13598253920) | 5,617,790 | `4067ef4aede73de57f49370c87ef2653246a738848c02d2bfb00f23839f68e69` |
| [campaign 13598547220](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42433029746/artifacts/13598547220) | 70,256,249 | `ef0d55c5b0a5ed2b57d5bb848cc7e5a7437849c52b84d14e00279c253daed668` |

原件包 SHA-256 为 `4983a445568178aaf21379147773f959156a6aafc796b79ed52a647f75719e32`；summary 为 `9b4c25277e7d36ee3f8af9c3858db134dbf5f934ee9a4edd9450f8d12e6aec54`。

本目录不是新提交的源码资格，也没有 WAN、独立 operator、work hardness、生产或付款资格。
