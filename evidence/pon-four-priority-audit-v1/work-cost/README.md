# Fresh same-target work cost observation

Measured source: `3c63c8368187de895e1dc0df8bbc105c6f39f842`; tree `54d2f12c0d783f827d43bc626489f58ab75d7c31`.
Both executions used this clean committed source before and after, with unchanged
source inputs and binary hashes. Native collection UTC: 2026-10-02T02:11:02.328504+00:00.
Paired collection UTC: 2026-10-02T02:11:51.672789+00:00 to 2026-10-02T02:11:52.813955+00:00.
Rust: rustc 1.95.0 (59807616e 2026-04-14); Cargo: cargo 1.95.0 (f2d3ce0bd 2026-03-21); filesystem: overlayfs.
All collection was serial on one controlled cloud host, without intentionally
concurrent local measurement. This is same-operator CPU evidence, not independent review.
No socket/network campaign, public ingress, GPU/VRAM, or honest-service measurement ran.

## Executed observations

- Existing `scripts/pon_work_cost_report.py --run --out OUT`: build/run exit 0;
  32 original/forged-cost observations, eight per dense/zero/rank-one/sparse class.
- Existing `pon_prepared_cost`: release build/run exit 0; 64 paired observations,
  four classes × two explicit targets × eight samples; all raw rows retained.
- Common target used by diagnostic: `7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` (development target).
  The narrower prepared benchmark target is retained but not mixed into diagnosis.
- Existing collector `--verify OUT`: exit 0, source applicability verified without
  rerunning the experiment. Additional paired artifact/source/binary verification passed.
- Diagnostic `--input OUT/native-work.json --prepared OUT/paired/prepared-cost.json
  --expected-target 7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff --require-local-acceptance`:
  expected exit 2 (`not-accepted`), retained as `diagnostic.exit` and `diagnostic.json`.

## Observed diagnosis (one-winner setup charged)

| Class | Cheapest supplied producer | Winner/verifier | Marginal reject/forge | Mean forge ns | Mean rejection ns |
|---|---|---:|---:|---:|---:|
| dense | prepared | 1.8266 | 281.0028 | 1530.88 | 430180.12 |
| rank-one | prepared | 2.0100 | 328.4535 | 1334.50 | 438321.25 |
| sparse | prepared | 1.3377 | 301.4292 | 1465.88 | 441857.50 |
| zero | prepared | 1.3500 | 301.1951 | 1451.25 | 437109.38 |

Every class fails the proposed <=1 marginal invalid rejection/construction diagnostic.
At modeled 64-winner setup amortization, sparse and zero also fall below the proposed
>=1 winner/verification screening ratio (0.9699 and 0.9623). Amortization horizons above
one are arithmetic scenarios using measured setup/search costs, not newly executed
multi-winner reuse. All underlying losing attempts and slower paired rows remain in raw
outputs; these bounded successful searches do not measure exhausted search campaigns.

Honest service remains `unmeasured`. No missing traffic ledger is converted to a pass.
The diagnostic report's `fresh_measurement:false` means the summarizer itself did not
execute experiments; the separately retained native/paired execution receipts establish
that THESE input bytes were newly collected on the source above. It also deliberately
leaves `source_applicability_verified:false`; separate verification receipts supply that
check, without inflating the diagnostic into authenticated external acceptance.

The thresholds are proposed local diagnostics, not preregistered scientific/deployment
acceptance. Fastest supplied valid implementation is not a lower bound on adversarial
algorithms/hardware. Conservative prefix setup and marginal forgery are separate; actual
CPU time must not be inferred from process latency. External security review, independent
operators, a registered hostile arrival/mix plan and public honest-service evidence remain
unqualified. All production, public-network and hardness acceptance flags stay false.

## Packet layout and preservation

`manifest.json` is the original collector's unchanged artifact manifest. `paired/manifest.json`
binds the separately collected paired artifacts. `packet-manifest.json` binds this complete
packet, including the exact outside-repository paired collection driver and command logs.
It does not replace either original manifest. All failed diagnostics and every raw sample
are retained. Execution records include exact commands, environment, source hashes and
binary hashes; the paired driver has machine-local paths intentionally retained as executed.
Copy this directory as a new evidence package only after review; do not overwrite historical
observations. No repository source or activation setting was changed by this collection.
