# Actual legal CPU batch V4: independent readback

The completed [V4 run 40619573406](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40619573406) measured the two existing legal producers at 1, 2 and 4 actual CPU worker threads. Both native architecture jobs succeeded at exact commit `7e3543f8817d019975ae578b56b4997eb92bc422`, tree `c238630a84d2e950894e0a2b9b4256d48455e836`. This evidence reads that completed run; it executes no solver, native admission, work relation or new adversarial experiment. The separate original campaign run `40619573513` failed and is not represented as a V4 success.

## Effective-ticket denominator and retained bytes

Each architecture has 12 fresh-store cohorts, 768 searches, 1,638 complete producer attempts, 876 missed attempts, 6 exhausted searches and 762 actual first-admission calls followed by ordinary cold packet readback. Across the paired strategies, worker counts, rounds and both architectures there are only **127 distinct fixture packet IDs**. All repeated copies of each ID have identical bytes. The 1,524 combined calls are independent store admissions of the same fixed fixture set, not 1,524 distinct newly mined network tickets or rewards.

Each strategy/worker pair uses two counterbalanced rounds: 128 searches, 273 attempts, 146 missed attempts, one exhausted search and **127 admitted fixture packets**. Every per-ticket number below divides its complete recorded numerator by 127. Failed attempts and the one shared producer preparation are charged. The separately acquired native template is charged in the all-phase scope and is not credited as another admitted ticket.

Both ZIPs were read entirely in memory: 780 members per architecture, including an actual native ELF and 762 original packet files totaling 37,725,096 bytes per architecture. Every member passed its ZIP CRC and SHA-256 readback. A second positive-byte read derived each packet ID, challenge and original ticket hash from its actual header and proof tail, matched the recorded whole-proof SHA, exact parent/task/target/nonce and original target predicate, and checked the 49,508-byte no-transaction packet grammar. This hash/byte readback is not a repeat of full native matrix/work/state verification; the successful hosted Node admission performed that operation. Missed-attempt full proof bytes are not retained, only their original recorded proof hashes and cost observations.

## Measured total cost per actual first admission

The total below is the sum of 14 nonoverlapping cohort phases, including template acquisition, one shared preparation, all attempts, encoding, archive writes with file fsync, first native admission, close, ordinary cold reopen and byte readback. The recurring subtotal includes preparation, generation, encoding and native admission. The archive phase remains separate in the raw phase records. Native admission includes the original full verification and SQLite work and is not charged again as a standalone verifier.

| Architecture | Strategy | Workers | All-phase CPU ms | All-phase wall ms | Recurring CPU ms | Recurring wall ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| x86_64 | prepared-general | 1 | 8.663303520 | 11.494020488 | 8.132868606 | 9.028759087 |
| x86_64 | prepared-general | 2 | 8.535451858 | 9.003882866 | 8.011883701 | 8.025603969 |
| x86_64 | prepared-general | 4 | 8.987837173 | 11.465082819 | 8.464843157 | 9.643558079 |
| x86_64 | maintenance-split-limb | 1 | 8.610680575 | 12.107841866 | 8.076086575 | 9.599100512 |
| x86_64 | maintenance-split-limb | 2 | 8.583115717 | 12.016102835 | 8.030514535 | 9.670802992 |
| x86_64 | maintenance-split-limb | 4 | 8.966779102 | 10.335425646 | 8.437625543 | 8.133248220 |
| aarch64 | prepared-general | 1 | 13.886288630 | 14.953966898 | 13.088447496 | 13.764112244 |
| aarch64 | prepared-general | 2 | 13.820620031 | 13.633487661 | 13.029716031 | 12.525606417 |
| aarch64 | prepared-general | 4 | 13.867739213 | 13.246628937 | 13.073831874 | 12.102661260 |
| aarch64 | maintenance-split-limb | 1 | 13.799267843 | 14.470106890 | 13.004747150 | 13.375896268 |
| aarch64 | maintenance-split-limb | 2 | 13.824920000 | 13.676746945 | 13.029624063 | 12.535060346 |
| aarch64 | maintenance-split-limb | 4 | 13.851331087 | 13.687791764 | 13.050382614 | 12.106790480 |

The smallest observed all-phase CPU cost on x86-64 is general / 2 workers, **8.535451858 ms**; on ARM it is split-limb / 1 worker, **13.799267843 ms**. The smallest observed all-phase wall cost is general / 2 workers on x86-64 (**9.003882866 ms**) and general / 4 workers on ARM (**13.246628937 ms**). These are minima among these six measured configurations for each runner, not a globally cheapest solver or a statistical significance finding.

For example, x86-64 general / 2 workers uses **1,084,002,386 process CPU ns / 127 admissions / 10^6 = 8.535451858267717 ms per admission**. Its wall numerator is **1,143,493,124 ns**, with the same denominator. [comparison-numerators.csv](comparison-numerators.csv) retains all 48 exact strategy/worker/scope numerators, denominators and computed costs.

| Architecture | Strategy | Workers | All-phase CPU numerator ns | All-phase wall numerator ns | Calls |
| --- | --- | ---: | ---: | ---: | ---: |
| x86_64 | prepared-general | 1 | 1100239547 | 1459740602 | 127 |
| x86_64 | prepared-general | 2 | 1084002386 | 1143493124 | 127 |
| x86_64 | prepared-general | 4 | 1141455321 | 1456065518 | 127 |
| x86_64 | maintenance-split-limb | 1 | 1093556433 | 1537695917 | 127 |
| x86_64 | maintenance-split-limb | 2 | 1090055696 | 1526045060 | 127 |
| x86_64 | maintenance-split-limb | 4 | 1138780946 | 1312599057 | 127 |
| aarch64 | prepared-general | 1 | 1763558656 | 1899153796 | 127 |
| aarch64 | prepared-general | 2 | 1755218744 | 1731452933 | 127 |
| aarch64 | prepared-general | 4 | 1761202880 | 1682321875 | 127 |
| aarch64 | maintenance-split-limb | 1 | 1752507016 | 1837703575 | 127 |
| aarch64 | maintenance-split-limb | 2 | 1755764840 | 1736946862 | 127 |
| aarch64 | maintenance-split-limb | 4 | 1759119048 | 1738349554 | 127 |

## What batching and the split producer actually changed

| Architecture | Strategy | Workers | Generation CPU ms / admission | Generation wall ms / admission | Generation wall speedup vs 1 | Total CPU ratio vs 1 | Total wall speedup vs 1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| x86_64 | prepared-general | 1 | 0.972820811 | 0.972854260 | 1.0000 | 1.000000 | 1.0000 |
| x86_64 | prepared-general | 2 | 0.964286843 | 0.516529732 | 1.8834 | 0.985242 | 1.2766 |
| x86_64 | prepared-general | 4 | 1.428410772 | 0.466322378 | 2.0862 | 1.037461 | 1.0025 |
| x86_64 | maintenance-split-limb | 1 | 0.937532236 | 0.937241858 | 1.0000 | 1.000000 | 1.0000 |
| x86_64 | maintenance-split-limb | 2 | 0.941189906 | 0.499116134 | 1.8778 | 0.996799 | 1.0076 |
| x86_64 | maintenance-split-limb | 4 | 1.360996992 | 0.384349772 | 2.4385 | 1.041355 | 1.1715 |
| aarch64 | prepared-general | 1 | 1.886405291 | 1.886444819 | 1.0000 | 1.000000 | 1.0000 |
| aarch64 | prepared-general | 2 | 1.877483969 | 0.999392913 | 1.8876 | 0.995271 | 1.0969 |
| aarch64 | prepared-general | 4 | 1.883394394 | 0.543403087 | 3.4715 | 0.998664 | 1.1289 |
| aarch64 | maintenance-split-limb | 1 | 1.828771780 | 1.828993559 | 1.0000 | 1.000000 | 1.0000 |
| aarch64 | maintenance-split-limb | 2 | 1.830591874 | 0.970851205 | 1.8839 | 1.001859 | 1.0580 |
| aarch64 | maintenance-split-limb | 4 | 1.833004031 | 0.527525882 | 3.4671 | 1.003773 | 1.0572 |

Four workers reduce the generation wall span about 2.09–2.44× on x86-64 and 3.47× on ARM. The complete admitted-ticket cost changes much less. On x86-64, four-worker generation process CPU increases about 45–47%, and the complete 14-phase CPU cost increases about 3.75–4.14% against the corresponding one-worker strategy. Native admission is serialized after all workers join and accounts for about 81.19% of all-phase process CPU on x86-64 and 80.77% on ARM.

| Architecture | Workers | Split vs general all-phase CPU change |
| --- | ---: | ---: |
| x86_64 | 1 | -0.607424% |
| x86_64 | 2 | +0.558422% |
| x86_64 | 4 | -0.234295% |
| aarch64 | 1 | -0.626667% |
| aarch64 | 2 | +0.031113% |
| aarch64 | 4 | -0.118319% |

Negative values mean lower observed CPU cost for split-limb; positive values mean higher cost. The small changes alternate in sign. Two counterbalanced rounds on shared runners cannot establish a stable hardware-independent advantage, confidence interval or global minimum.

## Complete observed accounting and limits

| Architecture | Sum 14-phase CPU ns | Sum 14-phase wall ns | Whole native process CPU ns | Capture elapsed ns | Max RSS KiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| x86_64 | 6648090329 | 8435639278 | 6715042000 | 8533785248 | 86732 |
| aarch64 | 10547371184 | 10625928595 | 10687184000 | 10779638625 | 37160 |

The complete native-process capture includes initial settings/archive-directory setup, JSON serialization and temporary-store cleanup outside the per-cohort clocks. Compiler installation, native build, Clippy, repository/source checks and artifact upload are outside that native capture and remain in the retained job logs. Each thread batch has one process-clock interval; overlapping per-trial wall observations are diagnostic and never added as CPU cost. Thread identity and interval overlap prove recorded distinct threads, not simultaneous physical-core execution.

Both hosted jobs report four available CPU IDs. Hardware authentication, exclusive-host control, GPU/ASIC/SIMD batching, energy, WAN performance, physical power-loss recovery, active-chain rewards and global optimality remain unmeasured. The two strategies use this existing maintenance fixture, fixed parent and original target; broader matrix/task families are outside this run. V4 retains the existing native PNW1 work packet and does not measure the 15.86 MB RISC Zero Composite proof or the new transparent Succinct certificate.

V3 remains separate: its endpoint experiment includes fresh/reused preparation at serial generation, while V4 always shares one prepared producer, adds packet archive I/O and uses a whole-batch clock. Their all-phase numbers are not an isolated algorithm comparison. The original 240-second driver and 250-second capture limits remain unchanged; these are finite completed observations.

## Reproducibility and publication status

Extract `selected-readback.zip` into an isolated directory and run `python3 independent_readback.py` there. This rechecks the exact original reader against the retained raw JSONL, all exclusive integer sums, source/capture/ELF-hash binding and archived packet member hashes. The source reader and exact driver/lock/config excerpts are included in that bundle. `packet_binding_readback.py` accepts a refreshed read-only download URL and the fixed artifact metadata to repeat the positive packet-byte/hash checks. Neither command executes the native solver or creates an admitted packet.

[original-archive-parts.json](original-archive-parts.json) gives both original ZIP IDs, byte counts, whole SHA-256 values and eight ordered 4 MiB part hashes/Git identities for durable publication. The original compressed ZIPs and actual native ELF bytes were fully read in memory but are **not saved locally or included in this selected evidence bundle**. The selected bundle is not the complete original artifact. Durable publication of those two originals is still pending; no stronger retention claim is made here.

The original read-only sandbox socket failures and an expired temporary download URL returning HTTP 403 are retained. Refreshed URLs retrieved the exact same artifact SHA. No new solver or failed adversarial experiment was rerun.

- [Original V4 source PR](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/531)
- [Actual successful run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40619573406)
- [Native driver at tested source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/7e3543f8817d019975ae578b56b4997eb92bc422/trillionnium/crates/trnm-pon-node/examples/pon_legal_ticket_batch_v4.rs)
- [Original exact-source reader](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/7e3543f8817d019975ae578b56b4997eb92bc422/scripts/ci/check_legal_ticket_batch_v4.py)
