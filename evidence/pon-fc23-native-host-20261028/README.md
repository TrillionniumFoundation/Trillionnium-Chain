# Actual fixed-Host preparation and failed confirmation gates

These are original observations of Chain head
`fc23fa6de10380dd9ce9cae6cddd1db4d87551ce` and its actual prospective merge
`9ae4fd76ede88a1cff56ca2e1afe28ed39668ff0`. Both use tree
`d6257737accc27f887c910b36e695c0ecc49a078`. The later integration candidate does
not inherit their qualification. The original four service gates remain failed.

The original [baseline run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40610405423)
contains protocol-head, x64, arm64 and protocol-merge jobs
`122560294754`, `122560294560`, `122560294738`, and `122560294795`.
All complete job logs and all four original diagnostic ZIPs are retained here.
They include the actual native executables, original databases, complete request
and resource observations, source guards, and every failed readback result.
Their SHA-256 values are checked by [readback.py](readback.py); its deterministic
[summary](fc23-ci-readback-summary.json) does not rerun or reclassify the work.

| Lane | Preparation wall seconds | Original inner build seconds | Original named native tests | No-attack confirmation | Pressure confirmation |
| --- | ---: | ---: | ---: | --- | --- |
| protocol-head | 113.319 | 0.294 | 5 / 5 | 1 / 1 in 0.988 s | 0 / 1 |
| x64 | 146.063 | 0.397 | 5 / 5 | 1 / 1 in 1.281 s | 0 / 1 |
| arm64 | 153.027 | 0.304 | 5 / 5 | 1 / 1 in 1.094 s | 0 / 1 |
| protocol-merge | 156.704 | 0.401 | 5 / 5 | 1 / 1 in 1.282 s | 0 / 1 |

Every lane observed unchanged source and identical executable SHA-256 across
preparation and original execution. The original build ran again inside the
unchanged 25% CPU / 2 GiB / zero-swap Host. Both actual Host checks had no errors.
The former 900-second compilation timeout was resolved without changing that
deadline. The five tests assert protocol, ownership and accounting invariants;
the separate original reader correctly rejects `CONFIRMATION_TARGET` when the
four-second service outcome fails. A zero libtest exit is not service acceptance.

## Complete four-lane request denominator

| Original calls | Attempts | Timely successes | After the four-second window |
| --- | ---: | ---: | ---: |
| No-attack Head | 300 | 300 | 0 |
| No-attack signed Submit | 28 | 28 | 0 |
| No-attack History | 28 | 28 | 0 |
| Pressure Head | 81 | 79 | 2 |
| Pressure signed Submit | 28 | 28 | 0 |
| Pressure History | 20 | 19 | 1 |
| Malicious calls | 979 | 0 | 64 |

Of the 979 malicious calls, 915 were refused and 64 returned errors. None was
accepted. Nevertheless all four pressure confirmations failed. In three lanes
the independent native page execution reached `PUBLIC_REQUEST_DEADLINE`; in the
merge lane the fourth History request started at about 3.954 seconds and returned
EAGAIN at 4.045 seconds. Network response success alone is not complete replay
or State convergence. Every original raw call remains in its diagnostic ZIP.

Paid mutation CPU was respectively 0.505130073, 0.526140447, 0.530522976 and
0.536137517 seconds. Every final credit remained close to 2 CPU seconds, with
zero CPU-budget refusals. This workload did **not** demonstrate genuine credit
exhaustion. The sender threads, honest caller, independent History verifier and
service in this particular from-zero fixture all shared the same 25% Host.
The separately revised multiprocess campaign is a different experiment and
cannot retroactively qualify these failures. Deadlines, CPU credit, request
denominators and reader predicates have not been relaxed.

## Retained macOS cleanup failure

The original [cleanup run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40610405430),
job `122560294239`, executed 84 tests: 83 passed, one failed, none skipped.
`test_actual_timeout_preserves_failure_row_logs_and_reaping` expected `OUTERR`
and observed an empty log. Its original archive and job log are retained.

The existing process owner starts the absolute 0.2-second deadline before
`Popen` and retains bounded prefixes observed before that deadline. It kills
and reaps only the group it owns; it does not promise a post-kill pipe drain.
The [small original-owner controls](fc23-cleanup-timeout-controls.json) used real
processes and the unchanged deadline. Immediate output was retained before a
0.201711-second timeout; output delayed by 0.3 seconds yielded an empty prefix
and a 0.201028-second timeout. Both children were reaped. These controls show
that empty output is possible under the contract, but do not identify the
macOS failure's cause. The original log cannot distinguish output not yet
written from output written but not yet read. This failure remains a failure;
no retries, added wait, extended deadline or diagnostic-based success override
was introduced.

The existing source and full proof/security/model/WAN gates remain independent.
No artifact here grants production activation or whole-chain PQ acceptance.
