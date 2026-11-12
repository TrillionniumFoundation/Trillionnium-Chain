# Observed balanced strata campaign: descriptive result

The frozen strict reader and unchanged SP27-06 analyzer both consumed the actual original batch successfully. All 13 planned phases completed: five healthy controls/sentinels and eight pressure controls. Every business operation confirmed strictly before its original four-second deadline, and every pressure phase met native control integrity. Native and analysis qualification are `COLLECTED_CONTROL_SERIES`; no first-divergence or reader rejection was recorded. The causal mechanism remains **UNKNOWN**.

## All thirteen observed endpoints

Times below are milliseconds from each phase's original traffic epoch; the latency column subtracts the actual recorded business release. The phases have separate epochs and are not one wall-clock timeline.

| Index | Phase | Confirmation endpoint (ms) | Release-to-confirmation latency (ms) | Native gate |
| ---: | --- | ---: | ---: | --- |
| 0 | health-000 | 2673.502700 | 2673.388307 | true |
| 1 | health-001 | 2617.861904 | 2617.770967 | true |
| 2 | health-002 | 2857.806807 | 2857.738835 | true |
| 3 | control-000-transport | 2861.468990 | 2860.321090 | true |
| 4 | control-001-early-reject | 2798.110260 | 2797.580952 | true |
| 5 | control-002-late-reject | 2901.255562 | 2900.736710 | true |
| 6 | control-003-valid-expensive | 3020.800036 | 3020.161353 | true |
| 7 | health-003 | 2616.533703 | 2616.450238 | true |
| 8 | control-004-valid-expensive | 3081.921311 | 3081.237746 | true |
| 9 | control-005-late-reject | 2900.983219 | 2900.409144 | true |
| 10 | control-006-early-reject | 2794.677509 | 2794.092137 | true |
| 11 | control-007-transport | 2721.622917 | 2721.037915 | true |
| 12 | health-004 | 2700.994493 | 2700.915975 | true |

## Two observed phases per arm

Each phase offered 16 single-attempt requests. All 16 matching bodies were actually checked and reached the intended native stage. Every canonical Submit body was 99,043 bytes (1,584,688 bytes per phase; physical network bytes are not inferred). Transport and early-reject had 16 explicitly unstarted Work spans per phase. Late and valid each had 16 actual native full replays per phase with no cached rejection returned. Missing pre-work CPU fields remain null in the machine-readable output.

| Arm | Business confirmations | First endpoint (ms) | Second endpoint (ms) | Second minus first (ms) | Mean release-to-confirmation latency (ms) |
| --- | ---: | ---: | ---: | ---: | ---: |
| transport | 2/2 | 2861.468990 | 2721.622917 | -139.846073 | 2790.679503 |
| early-reject | 2/2 | 2798.110260 | 2794.677509 | -3.432751 | 2795.836544 |
| late-reject | 2/2 | 2901.255562 | 2900.983219 | -0.272343 | 2900.572927 |
| valid-expensive | 2/2 | 3020.800036 | 3081.921311 | 61.121275 | 3050.699550 |

## Contrasts aligned by execution half

These are descriptive subtractions, not causal estimates or significance tests. The first half used T/E/L/V and the second V/L/E/T, with a healthy midpoint sentinel. Both raw endpoint differences and release-adjusted latency differences are retained in `STATISTICS.json`. The table reports release-to-confirmation latency differences.

| Contrast | First half difference (ms) | Second half difference (ms) | Arithmetic mean (ms) |
| --- | ---: | ---: | ---: |
| late-reject minus early-reject | 103.155758 | 106.317007 | 104.736383 |
| valid-expensive minus late-reject | 119.424643 | 180.828602 | 150.126622 |
| early-reject minus transport | -62.740138 | 73.054222 | 5.157042 |

## Actual arrival timing and partial native costs

Equal request counts and body lengths did not produce identical arrival profiles. The paid-queue column is the sum of 16 per-request waits, not one critical-path delay. CPU columns are the recorded calling-thread scope, exclude scoped worker CPU, and have nested intervals; full-work CPU must not be added to dispatch CPU or treated as complete verification cost.

| Control phase | Observer accepts min–max (ms) | Paid queue wait sum (ms) | Full-work calling-thread CPU (ms) | Dispatch calling-thread CPU (ms) |
| --- | ---: | ---: | ---: | ---: |
| control-000-transport | 101.695669–158.348983 | 414.420502 | NOT_RECORDED | 4.547451 |
| control-001-early-reject | 101.588853–102.811106 | 64.757214 | NOT_RECORDED | 6.413068 |
| control-002-late-reject | 101.835539–105.388955 | 201.787795 | 20.501315 | 27.360106 |
| control-003-valid-expensive | 102.415528–104.763587 | 1137.849692 | 21.549623 | 71.435123 |
| control-004-valid-expensive | 158.180227–160.571961 | 1209.631479 | 22.145594 | 72.793202 |
| control-005-late-reject | 102.183078–103.374824 | 353.541680 | 18.343025 | 25.039663 |
| control-006-early-reject | 102.260626–103.453124 | 98.962136 | NOT_RECORDED | 6.398776 |
| control-007-transport | 101.383057–102.560371 | 166.449846 | NOT_RECORDED | 4.214599 |

The JSON retains all actual call times, lateness distributions, stage counts, service peak counters, recorded deadline/cancellation metrics and independent replay results. No cancellation cause or queue depth is inferred. The native process lasted 54.134029355 s with 9.483126 s of whole-child CPU; this is an outer measured total, not the sum of the nested phase counters. Complete strata-input acquisition recorded 0.732009246 s wall and 0.174794390 s process CPU, including negative construction and valid producer paths; it is not a pure prover measurement.

## Interpretation boundary

This bounded schedule did not reproduce the prior sustained-pressure pair's failed confirmation. It does not refute that retained original observation or establish resistance to another load, duration or schedule. Two observations per arm from one host/campaign do not identify a general causal effect. The valid arm includes admission, execution, fork choice and storage, and actual arrival timing differed between phases. No extra native runs were added to obtain a preferred outcome, and no other health batch or historical corpus was pooled. The original Agent 06 author and coordinator acknowledgments remain `NOT_OBSERVED`.

Primary evidence: `../strata_analysis_v1/CONSUMER_RECEIPT.json`, SHA-256 `51e0e351a93f3fe70fef3e809c0e2204a1eb7dcfbe5c5fd9d7c3e03f8e66c8f1`. The companion statistics receipt binds the exact consumed input files, this summarizer and its outputs.
