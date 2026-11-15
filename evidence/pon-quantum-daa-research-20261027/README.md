# Conditional quantum PoN and DAA observations

This is a single-operator arithmetic/cost-model receipt, not native admission,
a quantum circuit run, a security theorem or release acceptance. The executed
source is **c9bec058eed88708944b29e7b9332c9617849015**, based on Chain #498,
4b6b8a91b6dfe41fbd7f40f40b359d535c2c4251. The later evidence-only commit is not
substituted for the source that actually ran.

See the [research contract](../../formal/pon-nakamoto-v1/QUANTUM_DAA_RESEARCH.md)
for exact assumptions, pure-PoN boundaries, integer rules, references and
remaining gates. The [execution receipt](execution.json) records command exit
codes; [report.json](campaign/report.json) binds parameters and model sources;
the [manifest](campaign/manifest.json) hashes all 11 compressed row streams.

## Results and actual resource use

The producer executed **11 scenarios and 109,190 rows** in 3.151470 seconds
wall time and 2.838032 seconds Python CPU time. Whole-process peak RSS was
54,324 KiB. This measured Python execution and compressed row serialization
on the environment recorded in the report. It did not measure W1, a proof
generator, an attack network, reversible gates, logical qubits or QPU time.
Those physical resource estimates remain unknown/null.

The attacker is assumed to produce baseline work at one quarter of the
honest network rate. The honest comparison is deterministic expected-rate
arithmetic. A conditional schedule counts as complete only if it has more
credited work and brings the tip within ten modeled seconds of current time.

| Cost/policy experiment | Rows | Work / honest model | Tip caught up | Conditional schedule |
| --- | ---: | ---: | --- | --- |
| Periodic, classical control | 976 | 0.250004 | No | No |
| Periodic, quantum-query hypothesis | 9,824 | 2.445191 | Yes | Yes |
| ASERT160 raw, bounded tail | 12,592 | 2.295444 | No | No |
| ASERT160 median11, bounded tail | 12,592 | 2.292316 | No | No |
| ASERT160 raw, extended tail | 12,946 | 2.287589 | Yes | Yes |
| ASERT160 median11, extended tail | 12,969 | 2.284138 | Yes | Yes |
| ASERT7200 raw, bounded schedule | 1,104 | 0.244222 | No | No |
| Fixed p, linear mandatory cost | 976 | 0.250002 | No | No |
| Fixed p, sublinear mandatory cost | 9,824 | 2.445174 | Yes | Yes |
| Periodic plus 5-second proof delay, bounded tail | 12,464 | 1.479341 | No | No |
| Same proof delay, extended tail | 22,923 | 1.061998 | Yes | Yes |

The failed bounded schedules are retained alongside extended runs. They do
not certify security. Successful schedules are conditional counterexamples
to the stated arithmetic/cost premises, not demonstrated native attacks.
The fixed-p counterexample makes the missing linear joint-cost assumption
explicit. No whole-chain post-quantum conclusion follows from these runs.

## Checks and retained failure

- The [18 dedicated tests](tests.log) passed on the executed source, including
  18 pinned upstream BCHN CalculateASERT vectors, honest clock controls,
  future-wait charging, fixed-p cost counterexamples and receipt mutations.
- [Readback](readback.log) passed all 109,190 rows: inventory/source hashes,
  separate integer work and timestamp calculations, and shared-model replay.
  It does not independently attest CPU time or cryptographic premises.
- The [34 existing negative source-integrity tests](source-integrity.log)
  passed. Their deliberately rejected child receipts print FAIL; those
  lines are expected negative controls, not omitted successful runs.
- [Repository check](repository-check.log) **failed with exit 2**:
  “CI contract: work-cost and DAA reader controls must execute once in their
  original lane.” This package changed no existing CI files. The full
  Markdown scan precedes that failing CI-contract check in the checker.
  This existing integration gate is retained, not silently marked passed.
- Native Cargo graph, lockfile, Rust tests, strict Clippy and formatting
  were not run by this formal-only package. They remain root integration
  gates; this receipt does not certify them.

To replay the preserved campaign from a source tree with the same model
file hashes:

~~~bash
python3 formal/pon-nakamoto-v1/experiments/quantum_daa_campaign.py --verify evidence/pon-quantum-daa-research-20261027/campaign
~~~

All native/quantum/hardness/production acceptance flags remain false.
The release conclusion is **NO_GO**.
