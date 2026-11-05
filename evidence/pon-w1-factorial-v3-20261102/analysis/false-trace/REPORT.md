# Separate FullLimb false-trace local observations

Source `2b250859e7c07088e6c3c01f75006372c684de61`, native capture **PASS**, qualification **HOLD**.

Actual: 72 setups, 288 searches, 573 paid hash attempts, 288 candidates, 1440 verifier calls. Exhausted searches: 0. Semantic alerts: 0.

Complete measured attacker-cohort CPU: 0.005807667 seconds. V3 legal costs are not used.

| Receiver path | Receiver rejection CPU (s) | Whole-campaign receiver / attacker | Per-class range |
| --- | ---: | ---: | ---: |
| production | 0.120374555 | 20.726835 | 18.339781–27.212225 |
| reference | 0.160877536 | 27.700888 | 24.162897–34.841339 |
| limb | 0.125098185 | 21.540179 | 18.566104–28.262953 |
| column-limb-experimental | 0.142632702 | 24.559380 | 21.001330–36.704616 |
| full-limb-experimental | 0.119886695 | 20.642832 | 18.276114–26.779724 |

Every retained native outcome is `Transcript` refusal. The unchanged `<=1` local rejection-economics condition remains unsatisfied.

| Material | Paid hash attempts | Attacker cohort CPU (ms) | Default receiver CPU (ms) | Default receiver / attacker |
| --- | ---: | ---: | ---: | ---: |
| periodic-dense-fixture | 70 | 0.603175 | 14.869461 | 24.651985 |
| full-rank-field | 65 | 0.464436 | 12.638337 | 27.212225 |
| zero | 69 | 0.609444 | 13.299827 | 21.822886 |
| identity | 59 | 0.799735 | 15.555542 | 19.450871 |
| rank-one | 71 | 0.848697 | 15.583660 | 18.361865 |
| sparse-diagonal | 47 | 0.677694 | 12.787466 | 18.869085 |
| continuity-maintenance-v1 | 68 | 0.659207 | 13.686907 | 20.762685 |
| one-zero-left-rank-one | 72 | 0.549234 | 11.022020 | 20.067986 |
| one-zero-right-rank-one | 52 | 0.596045 | 10.931335 | 18.339781 |

## Scope

- Denominator is this campaign actual prefix setup plus all four independent false-trace searches per setup, all misses, trial retention and winning clone within its declared timing scope.
- Public material generation, JSON/output, receiver verification and later retained-buffer destruction are not silently included in attacker cohort CPU.
- These are finite measured primitive ratios, not a cheapest-attacker lower bound or public-network amplification coefficient.
- Production and explicit FullLimb share an arithmetic kernel; their separately measured timings remain separate.
- No V3 legal producer or evidence timing is used in this denominator.
- All original failure/qualification boundaries remain; local native capture PASS is not economic or service acceptance.
