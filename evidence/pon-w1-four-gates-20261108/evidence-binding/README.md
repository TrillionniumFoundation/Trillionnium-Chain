# 实际保留记录的证据绑定缺口及修复

原 C3 `abab79dac0cb89eb2753d3f579119ac135650eb5` 的成本 reader 接受了一个确定性反例：在原 ABBA 行的隔离副本中，把 verifier stdout 的 `inner_verification_ns` 从 33,114,440 改为 1，保留 observer 的原 `stdout_sha256`。原 reader 仍接受新数值。这个反例没有执行新 verifier 或生成新证明；它证明的是证据接收缺少字节绑定。

[原复现及第一版验证记录](adversarial-gate-validation.json) 保留原与改写 stdout 的 SHA256。该历史记录的 9 项测试计数、局部依赖缺失及尚未执行真实 receiver 的状态不改写；最终源码另增加控制并在完整树实际运行。

## 修复边界

- 实际解析的 stdout 字节必须与 observer 固定的 digest 一致，拒绝缺失或畸形 commitment。
- JSON 必须为 UTF-8、无重复 key，拒绝非有限数、布尔冒充整数、未知行类型、不一致的退出/超时/计时状态。
- regular-file 检查与读取使用同一 fd；`O_NONBLOCK` 防止 FIFO 阻塞。既有普通文件 symlink 语义保留。
- 只有通过验证、时间和输入 pin 的行才能提交 journal identity；被拒绝的行不能污染后续接收身份。
- 每一行及最终输出前后重新核对固定输入；最后一行、验证后的 stdout 和发布后的输入改变均撤销 operation acceptance。

独立审计器另复现了原始行 `index=0` 改成 `false` 仍与固定 report 通过 Python 普通相等判断的缺口。新审计以递归类型严格相等、独立 report SHA、闭合时的全部 pin 及 cancellation 路径重读拒绝该副本。[审计复现记录](adversarial-gate-v2-audit-manifest.json) 保留原报告未改变这一条件。

## 已实际执行的整合控制

完整整合树已执行：12 项证据绑定、20 项审计负控制、10 项 CI W1 接线负控制，以及 11 项真实 receiver 控制，均通过。真实 receiver 使用 C3 已资格的 verifier ELF 和原有完整 v2 receipt，四项新增篡改控制实际经过 verifier；不计为新 proof。

CI 接在现有 `repository-truth` 的 W1 command block，固定要求 151 项常规控制执行、0 skip。既有透明配置 workflow 的真实 receiver 门改为 11 项。删除、重复、注释、吞错、移到其他 lane 或减少计数均由负控制覆盖。[接线源码哈希及提交前记录](adversarial-gate-ci-hookup-manifest.json) 的 pending 字段仅描述该记录形成时的局部状态；最终精确提交资格由独立后续 attestation 记录。

该修复提高成本和接收证据的完整性，没有建立新的 zkVM 密码学安全证明、链 admission 或完整资源结算资格。
