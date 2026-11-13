# Original release native Host checkpoint attribution — 2026-11-10

**Status: HOLD_NO_GO. No production performance, safety or admission gate passed.**

This is a small, deliberately static, **derived** nine-phase cost record from the unchanged
[source-head original three-run native campaign](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42773664165).
It preserves the original three complete attempts, each with baseline/from-zero/late-product
30-second phases, the same **0/24/24** hostile actors, 1,024 signed seed transfers, 21
business blocks, the original quarter-CPU/2-GiB/zero-swap/256-PID fixed Host and
depth-plus-work confirmation criteria. All nine original phase predicates are **false**;
all three Cargo invocations returned **101**. These facts are not overwritten by this reader.

## Identity and exact reproduction

- Source-head code and original native binary source: `81f00ca62d9ce53483d56d2f2ec12fb871a0b3ae`.
- GitHub Actions original artifact: [13743836733](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42773664165/artifacts/13743836733).
- ZIP byte size: `83,146,334`. ZIP SHA-256: `f004b1cf52aca7f84b2eb24c75d6a43fd5dd95a7c0ff86cbb97a31afd0c575d5`.
- Fixed original `run-1-raw/report.json` SHA-256: `fbeaa1575691e1874e4cbbc1d65ee40ecc872f786dde8b8e3d7145a0f1fba5dd`.
- Fixed original `run-2-raw/report.json` SHA-256: `da1eb0e5f44469fec02ab792209de7dc4222b419a0e17520174eecbed95db5ac`.
- Fixed original `run-3-raw/report.json` SHA-256: `35ae50399bbf1cbbb96272e27c0404c87ac6fbfca5011203b4c8342270e5161e`.
- Diagnostic script at this evidence cut has Git blob SHA-1 `5bba58c5028649d8168a8bb99cc34fed28ded632`.
- Structured summary `host-phase-summary.json` has Git blob SHA-1 `c8b9135a57bbbb09b355d864c963deb89f4e9bcc` and raw SHA-256 `0b980a386e8c7dcd9691ee01b9bbceb844dae6fd3de8e4f978653519c54a4fc2`.

To reproduce: download the *original* ZIP; verify its whole-byte SHA-256; read
`run-{1,2,3}-raw/report.json` directly (without extracting untrusted ZIP path names);
verify each exact report SHA-256, and place those three JSON files into matching
local directories. Then invoke:

```bash
python3 -m unittest discover -s scripts/ci -p test_inspect_native_campaign_failure.py -v
python3 scripts/ci/inspect_native_campaign_failure.py \
  --root /path/to/three-original-runs \
  --output /path/to/fresh-diagnostic.json
```

Compare `runs[*].phases[*].history_checkpoint_host_observations`,
`history_import_thread_cpu_ns`, `native_packet_stage_observations`, and original
report SHA-256 against `host-phase-summary.json`. The summary's nine fixed rows
are ordered by run 1–3, then baseline/from-zero/late-product; missing commit
timings stay `null`. Do **not** use `finite_experiment_criteria_met` or a derived
figure to claim a new native result: the recorded 0/3 is unchanged.

## Observed cost and safety boundary

| Original phase family | Fresh Host checkpoint calls per phase | Host checkpoint calling-thread CPU | Fraction of complete History import calling-thread CPU |
| --- | ---: | ---: | ---: |
| baseline | 99,282–100,995 | 4.73–4.82 s | 84.65%–84.99% |
| from-zero | 48,612–49,402 | 2.57–2.61 s | 85.13%–85.34% |
| late-product | 46,955–48,754 | 2.51–2.60 s | 84.77%–85.22% |

These CPU spans are **nested**, not independent costs or an achievable speedup
if checks were removed. The adjacent `admission`, `admission_prepare` and
`commit` spans also nest. The original
`host_kernel_parent::KernelBudget::verify` performs a fresh boot read,
root-owned inode check, **current calling-thread** membership check and five
fresh limit reads. Caching a prior Host verdict, reusing a stale cgroup
descriptor, sampling instead of checking on every required boundary, or
relaxing a deadline does **not** qualify as an equivalent performance fix.
The previously observed SQLite commit API time is not a substitute for the
full admission/commit enclosing cost.

## Next admission proof, not supplied by this record

An actual optimization must state its threat model, retain original
kernel-change/replacement, cancellation and resource-refusal controls,
execute the exact original 4-second/16-hostile service and three 30-second
0/24/24 campaigns in a fixed source-head and independent prospective-merge
lane, report all attempted denominators and original raw costs, and preserve
the full native W1/State/root/History verifier. Anything weaker remains
research-only. **No main merge, production activation or claimed saturated TPS.**
