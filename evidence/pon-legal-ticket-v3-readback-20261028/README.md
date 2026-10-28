# Read-only validation of actual legal-ticket V3 admission costs

[Run 40609636499](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40609636499)
completed the published V3 first-admission and cold-readback campaign at source
`9e73f62c5e5f026fff979840891301d9a8c56d52`, tree
`7ef7a5daca79fc67ecb242d89e381ac31ef606f6`. The earlier failed `409cc73` run is
not reclassified. This followup downloaded existing successful artifacts,
checked capture/source/binary/raw-output hashes and reran only the existing
pure Python evidence reader. No native benchmark or native binary was executed
locally. The recomputed summaries equal the hosted summaries exactly on both
architectures; [independent-readback.json](independent-readback.json) records
the exact observations and denominators.

Each architecture measured eight fresh stores and 508 first-native-admission
calls across repeated cohorts, but only 127 unique fixture packet IDs. Both
architectures use the same 127 IDs; these are not 1,016 distinct tickets. Every
cohort has 64 bounded searches with at most eight attempts per search. Per
strategy and reuse condition, two rounds produced 127 admissions from 273
attempts. Setup, exhausted searches, failed attempts, first admission and
ordinary close/reopen/readback costs are retained. Standalone verifier costs
are not added again to phases that already include them.

| Matrix setup reuse | Architecture | General CPU ms / first admission | Split-limb CPU ms / first admission | Split / general |
| --- | --- | ---: | ---: | ---: |
| false | x86-64 | 9.296824882 | 8.916305134 | 0.959069924 |
| true | x86-64 | 8.850126795 | 8.757291315 | 0.989510266 |
| false | AArch64 | 13.625213480 | 13.229019780 | 0.970922019 |
| true | AArch64 | 13.170763213 | 13.189641827 | 1.001433373 |

These are observed exclusive measured phase totals, including matrix setup
when present, divided by actual first admissions. Global settings setup is
recorded separately. The observed split-limb saving is 4.093% and 1.049% on
x86-64, 2.908% without matrix reuse on AArch64, and a 0.143% cost increase with
reuse on AArch64. The result establishes no architecture-independent advantage,
global minimum, hardness lower bound, quantum bound or production qualification.

Both hosts expose four shared vCPUs. No exclusive-host contention control,
hardware attestation, GPU/ASIC/FPGA, energy measurement or hardware batching
was supplied. The legal maintenance fixture covers two strategies; broader
primitive benchmarks do not become admitted-ticket measurements by inference.
There is no explicit activation call or active-chain reward measurement.
Cold recovery means ordinary process store close/reopen and byte readback,
not OS-cache eviction or a physical power failure. Existing approval limits
on separate adversarial benchmark execution were not bypassed by this readback.

Compressed raw stdout, capture records, source records, raw host/compiler
logs and both independent summaries are retained here. Original artifact ZIPs
remain locally available, with byte ranges and hashes in the
[artifact publication plan](../pon-w1-complete-a54-20261028/artifact-chunks.json).
