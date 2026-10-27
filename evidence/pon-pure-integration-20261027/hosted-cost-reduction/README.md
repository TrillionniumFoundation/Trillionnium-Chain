# Complete reduction of the hosted cost campaign

This is a later read-only reduction of the complete d961 campaign, not a new workload run. The [manifest](manifest.json) binds the source scripts, original artifact and every output. The retained raw stream has SHA256 `f48e6d83edfa4d1c25f7112380875297447031ec5103b70dcc327706d9083a98`.

[All fixed cohorts](fixed-cohorts.json) and [the matching CSV](fixed-cohorts.csv) retain all 1,728 offered groups: 800 supported and 928 unsupported, each covering the original two rounds. They retain all 605,024 attempts, 80,836 winning calls and 50,764 exhausted searches. Winning calls are not unique newly mined blocks. Setup and every failed attempt remain in the CPU denominator.

## Every supported strategy at the largest fixed horizon

The following table includes all strategies at horizon 256. Each ratio compares exactly matched material, target and preparation/reuse policy against `prepared-general`; values above one mean less observed CPU. Minima, medians and maxima are descriptive across the listed paired groups, not confidence intervals or hardware-independent speedups. Different rows support different materials; row medians cannot rank all-task implementations.

| Strategy | Paired groups | Minimum ratio | Median ratio | Maximum ratio |
| --- | ---: | ---: | ---: | ---: |
| blocked-one-zero-rank-one | 8 | 1.056048 | 1.098443 | 1.350663 |
| blocked-zero | 4 | 1.125613 | 1.178315 | 1.479824 |
| blocked-zero-integer-paired | 4 | 0.849032 | 0.886748 | 1.115640 |
| maintenance-integer-paired | 4 | 0.740622 | 0.769916 | 0.940837 |
| maintenance-periodic | 4 | 1.000325 | 1.036093 | 1.251871 |
| maintenance-prefix | 4 | 0.559201 | 0.582317 | 0.716018 |
| maintenance-split-limb | 4 | 1.039703 | 1.076936 | 1.298195 |
| paired-field-products | 36 | 0.701183 | 0.737301 | 0.820142 |
| prepared-general | 36 | 1.000000 | 1.000000 | 1.000000 |
| structured | 24 | 0.790340 | 1.006885 | 1.301419 |
| tiled-classical | 36 | 0.926268 | 0.940906 | 0.980265 |
| tiled-strassen-one-level | 36 | 0.642775 | 0.648442 | 0.658601 |

The [unrounded summary](largest-horizon-all-strategies.json) is derived from the complete JSON, not a fastest sample. For example, the zero-specific blocked strategy has a 1.178315 median ratio across four matched groups at this horizon; the one-level Strassen strategy has a 0.648442 median across 36 groups. These observations show that structured shortcuts and optimization costs must be measured. They prove neither a universal shortcut nor a minimum physical cost.

The campaign repeats seeded challenge streams across nested horizons and kernels, runs two rounds on a hosted machine with uncontrolled external contention, and does not cover GPU/ASIC designs, unlimited preprocessing, unbounded campaigns or all future task distributions. Zero-winner groups retain null per-win cost rather than a successful-looking zero. Unsupported strategies are kept in the complete outputs rather than silently falling back. Both plain outputs and lossless gzip copies are retained and hash-bound. No hardness or production-qualification flag is promoted.
