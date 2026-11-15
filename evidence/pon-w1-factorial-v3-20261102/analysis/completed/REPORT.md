# V3 local factorial cost observations

Measured source: `2b250859e7c07088e6c3c01f75006372c684de61`. Native execution result: **PASS**. Qualification: **HOLD**.

Scope: one local provisioned 8-CPU / 8-GiB environment; not original public Host. This does not certify original public-Host budgets or independent hardware.

Actual retained grid: 30/30 shards, 8 sample IDs per shard.
Actual paid setups/searches/attempts: 960 / 23,360 / 389,788.
Exhausted searches: 0; indexed searches after horizon/cell deduplication: 5,120.
Native verifier outcomes: `{'legal': {'Accepted': 93440}, 'product-last': {'Product': 93440}}`. Semantic alerts: 0; capture errors: 0.

## Aggregate measured CPU

| Fixed cell | Producer CPU (s) | Setup within producer (s) | Separate evidence CPU (s) | Producer + measured evidence (s) | Paid attempts | PNW1 bytes materialized |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| eager-transposed | 46.269653755 | 0.064712296 | 0.324588542 | 46.594242297 | 97,447 | 4,793,223,036 |
| lazy-transposed | 46.051049294 | 0.064791210 | 0.335482491 | 46.386531785 | 97,447 | 287,257,920 |
| eager-full-limb | 34.886637389 | 0.064100805 | 0.331081284 | 35.217718673 | 97,447 | 4,793,223,036 |
| lazy-full-limb | 35.389193100 | 0.064104630 | 0.324660051 | 35.713853151 | 97,447 | 287,257,920 |

Common material generation, paid once in each actual shard: 0.021745635 CPU seconds, separately retained.

Adding measured evidence is not an end-to-end service or mining cost; the unmeasured/excluded stages remain explicit.

## Matched per-shard effects

Percent change is candidate minus baseline, divided by baseline; negative is lower measured CPU. No values are confidence or security guarantees.

### Producer only

| Material | Target index | Reuse | Lazy vs eager: Transposed | Lazy vs eager: FullLimb | FullLimb vs Transposed: eager | FullLimb vs Transposed: lazy | Interaction (CPU ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| full-rank-field | 0 | 1 | +0.1532% | -4.7797% | -16.1719% | -20.3008% | -0.381175 |
| full-rank-field | 0 | 8 | -6.5066% | -3.6056% | -23.9591% | -21.5996% | +2.520225 |
| full-rank-field | 0 | 64 | +1.7084% | -2.0793% | -23.8980% | -26.7321% | -16.381832 |
| full-rank-field | 1 | 1 | +8.3899% | -0.9045% | -18.7200% | -25.6897% | -8.815834 |
| full-rank-field | 1 | 8 | -5.0047% | -3.1764% | -23.4660% | -21.9930% | +24.638258 |
| full-rank-field | 1 | 64 | +0.1998% | +5.4343% | -23.8648% | -19.8874% | +265.998870 |
| zero | 0 | 1 | -1.4963% | +10.1666% | -32.0091% | -23.9589% | +1.072249 |
| zero | 0 | 8 | -2.0731% | +0.5599% | -20.1576% | -18.0109% | +1.197567 |
| zero | 0 | 64 | +26.1946% | +105.0876% | -25.5266% | +21.0319% | +272.028904 |
| zero | 1 | 1 | -0.9590% | -0.0250% | -22.5050% | -21.7743% | +0.958483 |
| zero | 1 | 8 | +11.1579% | -7.7600% | -19.6366% | -33.3136% | -135.519593 |
| zero | 1 | 64 | -5.5306% | -0.1808% | -25.8275% | -21.6271% | +405.104964 |
| continuity-maintenance-v1 | 0 | 1 | -10.6870% | +9.6067% | -23.6977% | -6.3603% | +2.041826 |
| continuity-maintenance-v1 | 0 | 8 | -2.0895% | +4.4830% | -21.1578% | -15.8653% | +3.390290 |
| continuity-maintenance-v1 | 0 | 64 | -14.4450% | -9.5233% | -24.3525% | -20.0008% | +36.029148 |
| continuity-maintenance-v1 | 1 | 1 | +6.6214% | +0.1490% | -25.4462% | -29.9719% | -7.016090 |
| continuity-maintenance-v1 | 1 | 8 | +7.3599% | -3.5350% | -22.2537% | -30.1434% | -80.031241 |
| continuity-maintenance-v1 | 1 | 64 | +0.7471% | -4.5765% | -21.9797% | -26.1025% | -333.935962 |
| one-zero-left-rank-one | 0 | 1 | +7.2367% | -6.4452% | -20.6781% | -30.7985% | -1.553851 |
| one-zero-left-rank-one | 0 | 8 | -5.5157% | +2.5540% | -33.0000% | -27.2777% | +6.448933 |
| one-zero-left-rank-one | 0 | 64 | -16.5861% | -7.5144% | -19.0510% | -10.2473% | +54.913284 |
| one-zero-left-rank-one | 1 | 1 | +6.9088% | -7.2068% | -18.9886% | -29.6849% | -16.360952 |
| one-zero-left-rank-one | 1 | 8 | +2.9852% | +3.4385% | -24.5470% | -24.2149% | -4.071633 |
| one-zero-left-rank-one | 1 | 64 | +0.7238% | +1.8783% | -24.5520% | -23.6872% | +54.929303 |
| one-zero-right-rank-one | 0 | 1 | -3.8536% | -5.6579% | -15.9050% | -17.4831% | -0.072137 |
| one-zero-right-rank-one | 0 | 8 | +17.6987% | -4.7164% | -18.1368% | -33.7273% | -11.990848 |
| one-zero-right-rank-one | 0 | 64 | +2.3065% | -1.0810% | -26.0799% | -28.5275% | -17.455907 |
| one-zero-right-rank-one | 1 | 1 | +3.1188% | -5.2886% | -25.4231% | -31.5035% | -7.223488 |
| one-zero-right-rank-one | 1 | 8 | +0.1312% | -6.6028% | -19.5668% | -24.9762% | -54.644543 |
| one-zero-right-rank-one | 1 | 64 | -1.0329% | +3.3831% | -28.4666% | -25.2747% | +285.342954 |

### Producer plus measured evidence

| Material | Target index | Reuse | Lazy vs eager: Transposed | Lazy vs eager: FullLimb | FullLimb vs Transposed: eager | FullLimb vs Transposed: lazy | Interaction (CPU ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| full-rank-field | 0 | 1 | -0.0278% | -4.6269% | -15.9145% | -19.7827% | -0.363939 |
| full-rank-field | 0 | 8 | -6.4190% | -6.9730% | -20.5703% | -21.0405% | +0.608796 |
| full-rank-field | 0 | 64 | +1.5353% | -1.9879% | -23.1964% | -25.8615% | -15.788900 |
| full-rank-field | 1 | 1 | +8.3893% | -0.9313% | -18.5674% | -25.5699% | -8.882663 |
| full-rank-field | 1 | 8 | -5.0051% | -3.2088% | -23.3175% | -21.8674% | +24.481120 |
| full-rank-field | 1 | 64 | +0.2091% | +5.4139% | -23.7354% | -19.7742% | +266.189670 |
| zero | 0 | 1 | -1.4741% | +9.8113% | -31.2374% | -23.3612% | +1.069234 |
| zero | 0 | 8 | -2.0795% | +0.3317% | -19.2410% | -17.2524% | +1.161061 |
| zero | 0 | 64 | +25.1676% | +100.4703% | -24.7833% | +20.4682% | +272.431515 |
| zero | 1 | 1 | -0.9509% | +0.0194% | -22.3780% | -21.6176% | +0.990421 |
| zero | 1 | 8 | +11.0678% | -7.7746% | -19.5214% | -33.1745% | -135.741308 |
| zero | 1 | 64 | -5.4892% | -0.2099% | -25.6801% | -21.5287% | +402.345590 |
| continuity-maintenance-v1 | 0 | 1 | -10.2507% | +9.7153% | -23.1594% | -6.0652% | +2.052422 |
| continuity-maintenance-v1 | 0 | 8 | -2.1008% | +4.5707% | -20.5801% | -15.1679% | +3.583528 |
| continuity-maintenance-v1 | 0 | 64 | -13.9892% | -9.2302% | -23.4671% | -19.2326% | +35.649180 |
| continuity-maintenance-v1 | 1 | 1 | +6.5443% | +0.1146% | -25.3067% | -29.8144% | -7.002112 |
| continuity-maintenance-v1 | 1 | 8 | +7.3052% | -3.5125% | -22.1301% | -29.9804% | -79.985967 |
| continuity-maintenance-v1 | 1 | 64 | +0.7601% | -4.5969% | -21.8341% | -25.9898% | -338.486839 |
| one-zero-left-rank-one | 0 | 1 | +8.2711% | -7.2104% | -19.4676% | -30.9828% | -1.809472 |
| one-zero-left-rank-one | 0 | 8 | -5.4343% | +6.2731% | -32.4398% | -24.0757% | +8.873475 |
| one-zero-left-rank-one | 0 | 64 | -16.0397% | -7.2997% | -18.4089% | -9.9156% | +54.445132 |
| one-zero-left-rank-one | 1 | 1 | +6.8487% | -7.2488% | -18.9108% | -29.6096% | -16.421762 |
| one-zero-left-rank-one | 1 | 8 | +2.9513% | +3.5127% | -24.4573% | -24.0453% | -3.117995 |
| one-zero-left-rank-one | 1 | 64 | +0.6925% | +1.8891% | -24.4310% | -23.5329% | +58.548358 |
| one-zero-right-rank-one | 0 | 1 | -4.1129% | -5.4832% | -15.7682% | -16.9719% | -0.041732 |
| one-zero-right-rank-one | 0 | 8 | +17.0264% | -4.2082% | -17.6698% | -32.6087% | -11.831733 |
| one-zero-right-rank-one | 0 | 64 | +2.1375% | -1.0159% | -25.5283% | -27.8276% | -16.806704 |
| one-zero-right-rank-one | 1 | 1 | +3.1177% | -5.2694% | -25.3098% | -31.3847% | -7.252415 |
| one-zero-right-rank-one | 1 | 8 | +0.1125% | -6.6124% | -19.4980% | -24.9056% | -54.876671 |
| one-zero-right-rank-one | 1 | 64 | -0.8710% | +3.3168% | -28.2768% | -25.2468% | +269.825700 |

## Limitations and timing variation

- This is one local native source/binary run; provisioning is not independent physical hardware attestation.
- Inclusive producer cohort CPU includes one actual setup, all complete attempts/tickets, successful proof serialization, eager losing-proof destruction, binary-trial retention and timer/container overhead up to cohort completion.
- Producer-plus-measured-evidence adds a separate non-overlapping interval for complete attempt digests and attempt-record JSON Value construction only; it is a measured subtotal, not total mining cost.
- Outer search/candidate/mutation/verifier record construction, additional proof hashes, JSON serialization/write, later retained-object destruction, verification, transfer and business settlement remain outside that subtotal.
- The separately recorded common material cost is not silently added once per winner or duplicated across cells.
- Repeated strategy and horizon observations are not independent challenges or credited chainwork.
- Negative native calls here are Product-last, not a new measurement of false-trace rejection economics.
- No claim about the cheapest legal algorithm, physical energy, quantum cost, original public Host service or production qualification follows.
- Timing flags are descriptive; no observation or failure denominator is removed.

Descriptive timing flags: 61 cell/shard observations; see analysis.json. They do not invalidate or remove samples.

All exact totals, eight-sample paired producer effects, original record counts and reader identities are retained in analysis.json and the accompanying CSVs.
