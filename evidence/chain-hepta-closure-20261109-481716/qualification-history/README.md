# 原 qualification 绑定保留

M4 六份文件按改写 M5 前的原字节保留。candidate/profile→plan→packet→review 的摘要链在重绑前重新核验。它们固定 M4，不替代新 M5。

原 execution-status.json 是当时迭代中的报告组装快照：顶层 observed_at 为14:45，后补的 hosted checks 自身时间为15:04。它不是同一时刻联合观察，也不是最终 native 结果。新根 execution-status.json 对该状态更正，并明确每个 checks/source/native 的身份与时间；M4 完整原始失败结果见 native/M4 原件。

## M5 retained snapshot

The six files in `M5/` retain the exact earlier M5 profile/plan/packet/review/hash chain and the execution-status snapshot recorded at 15:57 UTC, when native collection was still pending. Its pending fields are historical, not the final M5 native outcome. The final canonical M5 observation is retained separately in `../validation/native-M5/`: 2449 passed, one failed, 41 ignored. M6 bindings are regenerated from the new source; no M5 result is relabeled as M6.
