# Executed PoN design-delivery evidence

Implementation commit: `8b87fee77ddee6a9778e8bebe880ba2627b05d5d`.
Implementation tree: `2068d839a45655e80653d4580a81023a064a7255`.
Public task input commit: `e7b36311fe5306bf63b7f88985801307e9e47d8c`.
Both full native regression and the complete scientific campaign ran on that clean,
unchanged implementation. Later evidence/publication changes do not alter those inputs;
`check_pon_evidence.py` checks every bound source and report digest.

## Results and exact scope

| Delivery | Executed result | Boundary |
|---|---|---|
| Detailed design | 18 modules,36 typed procedures; exact fields/commits/errors/limits | documented/executable, not all native product integrations |
| Native regression | 1794 tests pass;15 doc tests;ignored fixture helper separately passes;Clippy/fmt pass | tmpfs logical suite, not physical power-loss evidence |
| Source/contract rejects | 50 repository negative tests | not a natural-language proof or an independent audit |
| PoN arithmetic | 28 reference tests | explicitly abstract model, not used as the work verifier |
| Executable ledger | 18 tests with eight actual process-crash cuts | disk SQLite/full work/Ed25519; no native ordinary-node claim |
| Independent-language parity | seven suites,12 native command tags and work/root vectors | separately coded Python/Rust by the same author, not external acceptance |
| Model/reward/free use | real optimized parameters,28 work-verified blocks,finite100000 test-unit pool,replay rejected,consumer pays0 | same operator; source-routing model, not LLM or normal Hepta product entry |
| Network | three real localhost processes with full work/state verification,64 signed transfers,attack/reorg cases | controlled loopback and logical chain clock, not WAN/public-chain TPS |

[Summary](summary.json), [complete campaign](campaign.json), [native qualification](native-qualification.json),
[environment](environment.json), [manifest](manifest.json) and the raw log subdirectories
retain exact commands, exits, inputs and observations. Reports include no private tasks,
provider credentials, deployed keys or service changes.

## Do not hide the failed or weaker results

The [first exploratory model](exploratory-failure/report.json) failed both evaluation
score gates and would receive no adoption reward. Its executed algorithm snapshot and
model bytes are retained. A feature-quantization/class-imbalance correction subsequently
improved the controlled task, but it reused the same evaluation partitions and is not
an untouched future-window result.

On190 consumer examples, the later base got100 correct; routed composition119; the
best single expert125; mean-delta merge123. Thus the composition improves over its base
but **does not beat the strongest single expert or simple merge on this consumer set**.
All controls remain in [the model report](model-report.json). The score decision and
[actual bounded settlement](settlement-report.json) do not imply global optimality.
The experiment's two signed evaluators are not independent operators.

[Native raw work costs](work-cost.json) show the unresolved asymmetry: median generation
about3.49ms, valid verification3.73ms, invalid verification3.71ms, cheap forged-ticket
construction about0.00133ms on the recorded host. These isolate single-attempt costs at
the benchmark's permissive ticket target; they are not a measured network attack rate
or a hardness theorem. The full-recompute verifier is not production-eligible.

## Reproduce and invalidate honestly

Run the commands in [the executable-contract guide](../../formal/pon-nakamoto-v1/README.md).
The campaign must write a new output directory; it never regenerates golden vectors
inside tests or deletes a prior failed result. Source/configuration changes invalidate
these observations until re-executed under the new context. Hash consistency proves
which data was retained, not who independently reviewed it.

Not accepted: cost-hardness and public proof-admission security; ordinary native node and
Hepta owner integration; independently administered evaluation and geographically distinct
availability; physical power loss/WAN consensus; unseen future model efficacy. Production
activation remains false. No old BFT or successful-stub fallback was introduced.
