# W1 response reservation r17: retained preliminary observations

These records bind the exact preliminary candidate
`33fdb7a2721ee8e4ff42a7ab0a7b57a90ba254d2`, tree
`484bcf680f416748827d8972de6a6161a1d0a3f7`. They do not qualify the subsequent
combined source. The [manifest](manifest.json) lists original and retained
SHA-256 values; every non-JSON log is retained losslessly as gzip.

## Observed native result

The original Rust 1.95.0 test profile, locked dependency graph, all node features,
two build jobs and a fresh private OpenSSL 3.5.9 provider produced the actual
449,431,976-byte test binary with SHA-256
`2b63ca12a98d54fab9f195bb3ddb702a4adc75230c5b017f015d64cea0414193`.
Compilation succeeded in 673.47 seconds. These are selected component tests,
not a full-workspace run or original Host observation.

| Selected module | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| Response signing TCP and owner boundaries | 5 | 1 | 0 |
| Authenticated caller boundaries | 3 | 0 | 0 |
| Classical authentication CPU controls | 21 | 0 | 0 |
| PQ identity controls | 13 | 0 | 0 |
| Total selected executions | 42 | 1 | 0 |

The cancellation test failed at the strict terminal-phase assertion:
the observed value was None, while Some("work") was required. Submit with a
verified signed ACK under competing authentication passed. The raw failed test
and all passing controls remain in [the native summary](retained/native-component-attempt-1/summary.json).

Inspection found that repeated live diagnostic snapshots can contend with
the observer's deliberately nonblocking diagnostic writes. The subsequent
test correction waits for existing owner-published atomic closure, then takes
one snapshot. It keeps the exact work-phase/EOF/no-measurement-failure assertions,
the pending worker reservation checks, all original deadlines, and the actual
signature gate. This record does not claim that corrected test has passed.

## Source controls and preparation failures

Complete actual tracked source verification passed before and after this
preliminary run. Source inventory, repository/Markdown contracts, CI source
guards, CI source-integrity controls, PQ source/negative controls and current
policy/phase readers passed where recorded in
[the source-control summary](retained/final-source-controls-attempt-1/summary.json).
Two negative suites, test_repository.py and test_applicability.py, reached this
local driver's 180-second per-command limit. Their partial stdout/stderr and
exit 124 are retained; neither suite is counted as passed.

The first provider download failed with curl exit 92. The separate HTTP/1.1
archive-download runtime job reached its 600-second outer limit. The later
provider attempt reused only an exact source archive with the original
SHA-256 pin, then freshly built and passed real ML-DSA-65 sign, verify and
wrong-message rejection. It did not reuse provider validity from another run.
Preparation is not native PQ or whole-chain cryptographic acceptance.

## Concurrent source and qualification boundary

PR 780 initially published this preliminary candidate into the existing
integration branch. That base advanced from 96e1eede to d26e047d; the original
PR readback recorded the resulting conflict. The subsequent reconciliation
preserves both source lines, their original failure records and the normal
HeptaRuntime ProfHepta publication route. It also places the newly fallible
default rejection-cache allocation before a previously unbound Node acquires
its first CPU domain.

The resource namespace remains r17. Exact mathematical-refusal caching creates
no valid work, no extra authorization and no new budget. New proof bytes still
use the native verifier. Original fixed Host parameters remain 0.25 CPU,
2 GiB, zero swap and 256 PIDs; the original 4-second / 16-hostile gate, three
complete 0/24/24 campaigns, full 4,105-block History, capacity/churn and independent
WAN remain separate acceptance requirements. No original Host, anonymous
fairness, accepted-work cost floor, economic break-even or production activation
is granted by these observations.
