# Constructed reversible components: original observations

Tested source: `7d12655bd5cfc967c6150bba00ab349826c1bf67`. Both raw-byte source checks
returned the same clean commit/tree and all six component controls passed.
The full observation reopened and executed the saved netlists, checking
113 field-multiplication cases and 7 SHA-256 messages.

| Constructed component | Logical qubits | Toffoli gates | Total gates including inverse | All-gate dependency depth | Artifact bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Fq32 multiplication | 6550 | 6414 | 19434 | 884 | 156051 |
| SHA-256 compression, 64 rounds | 117293 | 77306 | 388026 | 13351 | 3109204 |

These are the costs of this explicit, deliberately simple construction under
all-to-all gate connectivity, not a best-attacker lower bound. The full field
observation took 0.682317 seconds
and the hash observation 3.532158
seconds of classical construction/reopen/basis checking on this shared machine.
They are not quantum execution times.

The [full report](report.json) retains every input and expected/actual output.
The [compressed original observation](exact-observation.tar.gz) retains the two
actual gate lists and all exact-source logs. Its hash and byte count are in the
[artifact manifest](artifact-manifest.json). The earlier pre-decoder observation
is retained separately as [predecessor evidence](predecessor-before-strict-reopen-report.json);
it does not qualify the later source.

The complete oracle, coherent rejection sampler, full reversible matrix/memory
schedule, phase marking, physical architecture and quantum proof-system
soundness remain absent. No quantum hardware or mining attack was executed.
See the [scope and reproduction contract](../../formal/pon-nakamoto-v1/REVERSIBLE_COMPONENTS.md).

The original repository/link check passed with 25 packages and 1,277 local links
on the pre-commit candidate. All 50 repository-boundary controls and 34 actual
Git source-integrity controls passed on those same source bytes before commit.
The exact committed-source run separately repeated the six component controls
and full observation, with source verification before and after. Locked Cargo
metadata retained the original 25-package graph. No Rust source, lockfile or
production parameter changed; a new hosted whole-source gate remains separate.
