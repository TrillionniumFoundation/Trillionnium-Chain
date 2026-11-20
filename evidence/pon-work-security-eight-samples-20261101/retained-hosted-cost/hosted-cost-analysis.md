# Hosted W1 成本原始记录：独立复核

**12 个 artifacts、16 个 native 捕获均完成独立记录复核。V2 四条 lane 的八样本固定网格成立，全部安全/资源/上线资格仍为 false。**

Head `3bbc0288d6b7b6ed7f2bf0ee70d99b3b14236129`；prospective merge `ea43b65fdd91b741b8f9e577061710dd2aebbb2e`；两者 tree `f52299288ca23426e5186f37fb3a58788e40dbee`。

本报告直接读取冻结 JSONL，未导入项目 reader，未重新执行 native。整数成本先由 cohort/search/verifier 记录求和，再逐项对照原 reader。保留的 archive、成员大小/CRC、manifest SHA-256、ELF、source 前后与锁图均检查。完整 W1 transcript 和 AB product 没有在本脚本内再次计算。

## V2：完整固定策略

CPU 包括一次实际 setup、全部失败与成功 attempts、trial retention 和 proof hashing；不含另记公共材料生成、后续输出/销毁或 native verifier。`Δ` 为 dispatcher / generic − 1。

| Lane | Artifact | Generic CPU 秒 | Dispatcher CPU 秒 | Dispatcher Δ | Shard 比值区间 generic/dispatch |
| --- | --- | ---: | ---: | ---: | ---: |
| prospective-merge / x64 | 13093301643 | 41.001259184 | 41.750666641 | +1.827767% | 0.902516–1.503594 |
| prospective-merge / arm64 | 13093891287 | 69.350255952 | 72.191903184 | +4.097530% | 0.894032–1.120780 |
| head / arm64 | 13093926141 | 69.321174848 | 72.161178712 | +4.096878% | 0.893970–1.118517 |
| head / x64 | 13094025188 | 41.082052430 | 41.726853924 | +1.569545% | 0.943064–1.480990 |

每个 V2 lane：30 shards；每 shard 实际 8 samples；480 setups/cohorts；11,680 complete searches；195,832 paid attempts；5,840 完整 candidate 记录；93,440 native verifier calls。全部 search 找到 first hit，所有失败尝试计入成本。legal 均为 Accepted，product-last 均为 Product。

四条 V2 lane 共同使用同一组 **5,120 搜索流 / 86,318 attempted challenge 身份**。策略、horizon 前缀、head/merge、x64/ARM 的相同流已逐项匹配；四次执行不能写成四倍独立流或新增 chainwork。

### 按材料类保留全部结果

下表仍是每类全部 target/horizon/sample 的完整聚合，百分比不能跨 lane 拼接成事后最优策略。

| Lane | 材料类 | Generic CPU 秒 | Dispatcher CPU 秒 | Dispatcher Δ |
| --- | --- | ---: | ---: | ---: |
| prospective-merge / x64 | full-rank-field | 8.201583722 | 8.697688687 | +6.048892% |
| prospective-merge / x64 | zero | 8.104483637 | 8.603296783 | +6.154780% |
| prospective-merge / x64 | continuity-maintenance-v1 | 8.273009349 | 7.352976621 | -11.120896% |
| prospective-merge / x64 | one-zero-left-rank-one | 8.228604266 | 8.548483217 | +3.887402% |
| prospective-merge / x64 | one-zero-right-rank-one | 8.193578210 | 8.548221333 | +4.328306% |
| prospective-merge / arm64 | full-rank-field | 13.850085400 | 15.010018112 | +8.374914% |
| prospective-merge / arm64 | zero | 13.713137760 | 15.330185760 | +11.791962% |
| prospective-merge / arm64 | continuity-maintenance-v1 | 13.990237592 | 13.684237336 | -2.187241% |
| prospective-merge / arm64 | one-zero-left-rank-one | 13.913568936 | 14.091992168 | +1.282369% |
| prospective-merge / arm64 | one-zero-right-rank-one | 13.883226264 | 14.075469808 | +1.384718% |
| head / arm64 | full-rank-field | 13.846779384 | 15.003110552 | +8.350903% |
| head / arm64 | zero | 13.710326648 | 15.328044104 | +11.799263% |
| head / arm64 | continuity-maintenance-v1 | 13.985869072 | 13.677042160 | -2.208135% |
| head / arm64 | one-zero-left-rank-one | 13.899486992 | 14.083790432 | +1.325973% |
| head / arm64 | one-zero-right-rank-one | 13.878712752 | 14.069191464 | +1.372452% |
| head / x64 | full-rank-field | 8.225833527 | 8.700390688 | +5.769107% |
| head / x64 | zero | 8.140414578 | 8.533942851 | +4.834253% |
| head / x64 | continuity-maintenance-v1 | 8.265169881 | 7.352166044 | -11.046401% |
| head / x64 | one-zero-left-rank-one | 8.203129842 | 8.608628951 | +4.943224% |
| head / x64 | one-zero-right-rank-one | 8.247504602 | 8.531725390 | +3.446143% |

## V1 历史两样本 lane

V1 保持原两样本语义，样本政策仍未满足；下列计数与成本来自其自身版本的挑战域，未重标为 V2。

| Lane | Artifact | 完整 attempts | Verifier calls | Generic CPU 秒 | Dispatcher CPU 秒 | Dispatcher Δ |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| head / x64 | 13093416862 | 50,034 | 23,360 | 10.479927495 | 10.603538586 | +1.179503% |
| prospective-merge / arm64 | 13093421854 | 50,034 | 23,360 | 17.723816464 | 18.398611680 | +3.807279% |
| head / arm64 | 13093480950 | 50,034 | 23,360 | 17.722648504 | 18.399973784 | +3.821806% |
| prospective-merge / x64 | 13093776046 | 50,034 | 23,360 | 10.496243288 | 10.632923140 | +1.302179% |

## False-trace：完整拒绝成本

每条捕获为九类 × 八个实际 setup × 每 setup 四次搜索。比值分母是全部 attacker cohort CPU，含 setup 与全部 misses；分子为同捕获完整 production verifier 的拒绝 CPU。四路径与五路径捕获分别保留，不合并成一个不同计时窗口。

| Lane | Artifact / 路径组 | Attacker CPU 秒 | Production 拒绝 CPU 秒 | 完整比值 | 九类比值范围 |
| --- | --- | ---: | ---: | ---: | ---: |
| head / arm64 | 13093136677 / 4 paths | 0.009399456 | 0.198225712 | 21.089062 | 18.603627–24.337477 |
| head / arm64 | 13093136677 / 5 paths | 0.009923824 | 0.197660000 | 19.917725 | 19.202075–22.628599 |
| head / x64 | 13093396655 / 4 paths | 0.004961609 | 0.113546188 | 22.884953 | 19.267705–30.030372 |
| head / x64 | 13093396655 / 5 paths | 0.005848001 | 0.113597193 | 19.424961 | 17.922473–26.240776 |
| prospective-merge / x64 | 13093436001 / 4 paths | 0.005001261 | 0.113341276 | 22.662540 | 18.814664–30.790295 |
| prospective-merge / x64 | 13093436001 / 5 paths | 0.005762731 | 0.114107705 | 19.800977 | 18.048050–26.193433 |
| prospective-merge / arm64 | 13093880577 / 4 paths | 0.008735520 | 0.198071400 | 22.674254 | 20.727079–24.855811 |
| prospective-merge / arm64 | 13093880577 / 5 paths | 0.009271168 | 0.197991256 | 21.355589 | 20.402270–23.837019 |

全部 false-trace native 结果为 Transcript 拒绝；零 valid-proof acquisition。各路径、各类整数分子分母及完整 record counts 保存在 JSON。八份捕获的 deterministic search identities 相同，不能当作八倍独立挑战。此比值仅是本次 hosted 原语拒绝观察，不是公网 fanout/队列/存储/签名/业务确认放大系数，也不与历史不同分母/源码/主机观察作因果比较。

## 身份、锁图与资格边界

Cargo.lock SHA-256：`fbe64b5b4662405980becd75c81c9ef699a78b56449d71ed33185531db851c69`。12 个 metadata 图各有 174 selected packages，均在 179-package lock 中；逐边核对后，忽略文件系统定位元数据的 normalized resolved graph 全部一致：`ce5299637fe83da9f213feab2ba7d75954ae51a9940fde1b0ac4d40e7544719a`。

x64 retained ELF machine 为 62，ARM64 为 183；每条 lane 的 measured-before/after 与 retained-before/after binary pin 均匹配实际文件。source 前后同一 tree，6,856 tracked entries / 792,504,967 bytes。所有 identity/build/native commands 均 exit 0、无 timeout，原 30/900/300 秒 caps 不变。

`hardness_accepted`、`work_profile_qualified`、`resource_fairness_qualified`、`public_service_measured`、`independent_hardware_qualified`、`public_network_ready`、`production_activation` 在全部 manifest/reader/raw campaign 中均为 false。reader 的 `native_execution_authenticated` / `w1_transcript_replayed` 等边界保持原值；run success 不替代成本安全证明。

这是 hosted x64 与 ARM 上的固定原始记录复核。跨主机绝对 CPU 不构成受控因果性能比较，也不证明最快合法策略、GPU/ASIC/量子成本、模型增益、公开网络业务确认或生产激活。完整结构策略中的正负结果全部保留。

## 复现

使用 Python 3.11 或更新版本，在保留的原 artifacts 与最终源码上运行：

```sh
python3 analyze-hosted-cost.py --root /tmp/trnm-pon-hosted-3bbc/cost-artifacts --source /tmp/trnm-pon-security-final
```

脚本只读取原 artifact 子目录、ZIP 与 receipt，仅写同级 `hosted-cost-analysis.json` 和 `hosted-cost-analysis.md`。它不会运行 native/Cargo、不会修改 raw 或原 manifest。
