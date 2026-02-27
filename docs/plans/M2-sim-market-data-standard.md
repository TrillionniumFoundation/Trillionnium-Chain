# M2 仿真行情标准格式清单（Data Contract）

## 目标
同一份行情输入，得到可重复回放结果。

## 标准字段（建议）
- `ts` (ISO8601 / epoch_ms，固定一种)
- `symbol`
- `open, high, low, close`
- `volume`
- `turnover`（可选但建议）
- `source`
- `tz`

> 约束：一个项目内只允许一种主格式（jsonl 或 csv），禁止混用为主输入。

## 必做项
- [ ] 固化 schema 文件（如 `schemas/sim_market_v1.json`）
- [ ] 统一时间粒度和交易日历
- [ ] 明确缺失值策略（drop/forward-fill/zero 禁止隐式）
- [ ] 明确复权策略（前复权/后复权/不复权）
- [ ] 数据指纹：生成 `dataset_id` + `sha256`
- [ ] 回放入口必须记录：`dataset_id + schema_version`

## 验收标准
- [ ] schema 校验 100% 通过
- [ ] 无乱序/重复时间戳
- [ ] 同 dataset_id 重跑结果一致

## 建议门禁命令
```bash
./scripts/v2/validate_sim_market_schema.sh data/sim/*.jsonl
./scripts/v2/check_sim_market_integrity.sh data/sim/*.jsonl
```
