# Historical W1 verifier CPU readback

**HOLD_NO_GO.** This packet rechecks the eight recorded #795 executions and
their verifier CPU receipts. It generates **zero new proofs**, runs no native
Node campaign, and does not produce a qualified TPS value.

## Finding

The tagged verifier's pooled median is **0.544260107 seconds of outer wall
time** but **2.36 CPU-seconds of user plus system time**. The four CPU
observations are 2.43, 2.29, 2.56 and 2.20 CPU-seconds. The original service
contract's nominal arithmetic budget is `0.25 CPU × 4 seconds = 1 CPU-second`
for the workload, including the honest and hostile requests. The eight-thread
wall-time observation therefore does not establish the original service gate.

The historical manifest reports CPU affinity 0–7, Rayon 8 and a shared host.
Its initial reported cgroup has `cpu.max = max 100000` and `memory.max = max`;
these observations are distinct from the required constrained campaign. The
comparison does not extrapolate a 0.25-CPU latency or assert an irreducible CPU
lower bound. A different implementation or thread configuration may change
paid CPU work. No memory, hard-deadline, production-slice or hostile-load gate
is established by this readback.

| Cohort | Completed / planned per arm | Legacy verifier CPU median | Tagged verifier CPU median | Tagged verifier wall median |
|---|---:|---:|---:|---:|
| Retained | 2 / 2 | 6.04 CPU-s | 2.36 CPU-s | 0.544260107 s |
| Dense | 2 / 2 | 5.915 CPU-s | 2.38 CPU-s | 0.616325245 s |
| Both fixtures pooled | 4 / 4 | 5.93 CPU-s | 2.36 CPU-s | 0.544260107 s |

GNU time prints user and system values in hundredths of a second. Decimal
arithmetic preserves those reported values; the table does not imply finer
physical measurement accuracy. Medians describe these retained observations,
not confidence intervals, tail estimates or independent production tasks.

## Sources and identity

The complete original manifest, summary and all eight verifier GNU time
receipts are retained under [originals](originals). Their published source is
commit `1fe2f31c70977a030aec73b63fe0617f34d15a77`, PR #795. Every source URL, Git
blob identity, byte count and SHA-256 appears in the generated
[report](report.json). The reader hardcodes both Git blob and SHA-256 pins;
a caller-supplied index cannot replace them. These are reproducible content
bindings, not independent attestations of the historical machine.

The original measurement used a resolved merge snapshot:

- HEAD: `cfef87ff6e09f998cb8fc5d3165fce8ac9eb2da1`.
- MERGE_HEAD: `09fbc0f45151a68a1bf205641171840fbf309882`.
- Index tree: `26785a22b3118c718f71c1774dc1c1961db410e9`.

The publication commit and measurement source remain separate. This reader
reproduces the recorded source-snapshot equality; it does not rebuild the
historical binaries or relabel that experiment as a new execution.

The fixed eight-slot plan remains visible even if a file or run is missing.
Exit codes, timeout booleans and unknown values remain separate. Nonzero exits,
signals, duplicate runs, changed inputs, malformed CPU fields, mismatched
commands or missing receipts cannot become successful observations. Known CPU
cost from an unsuccessful run remains visible; success-only medians carry both
the completion count and original planned denominator. Two fixture identities
remain two tasks despite repeated executions.

## Reproduce the readback

From the repository root:

```sh
bash scripts/project-preflight.sh
python formal/throughput-v1/proof_cpu_metrics.py \
  --evidence-dir evidence/pon-throughput-20261108/proof-cpu
python -m unittest discover -s formal/throughput-v1 \
  -p test_proof_cpu_metrics.py -v
```

The [reader](../../../formal/throughput-v1/proof_cpu_metrics.py) uses only the
Python standard library. JSON decimal measurements are strings. Missing or
changed evidence causes an incomplete/invalid result and exit 1; it never
silently substitutes zero, a faster phase, another run or a new fixture count.
The optional `--output` writes a new file and refuses to overwrite an existing
observation.

The latest local validation passed **26 tests** and reproduced `report.json`
byte-for-byte; see [validation-hardening.json](validation-hardening.json) and
[the complete test output](unit-tests-hardening.stderr.txt). The report SHA-256 is
`c5acf7e338900b75d983a04a7907a9fd464adcc0e8361b36ceef01c85a7d51f3`.
The preceding [21-test pass](validation-final.json) remains unchanged. Independent
review then hardened the arithmetic helper against a contradictory GNU nonzero
exit diagnostic, malformed object/argument types, extreme Decimal exponents and
noninteger declared counts. The fixed corpus pins already prevented changed
files from becoming a complete readback. The extra checks also protect the
helper when called with unpinned in-memory records. Duration parsing has a
one-day upper bound and bounded decimal representation; this parser limit does
not alter the original four-second service contract.
The first [validation](validation.json) recorded one failing test because its
expected merge-head literal omitted two characters. The test literal was
corrected to the original manifest; original observations and reader arithmetic
were unchanged. That initial failure and its full log remain preserved.

## Combining schedule and hash changes remains a new experiment

The original tagged R1 uses SHA component 1 and packed arithmetic component 4.
The separate #783 scheduled-SHA comparison uses legacy component 5 and reports
a slower complete verifier despite a faster proving pipeline. No tagged plus
scheduled-SHA execution is present in this packet. Historical gains must not
be multiplied.

A combination experiment requires four fresh arms under the same resource,
input, compiler and scheduling contract:

| Arm | Hash profile | SHA relation implementation |
|---|---|---|
| A | Legacy Poseidon2 | Original SHA component 1 |
| B | Legacy Poseidon2 | Scheduled SHA component 5 |
| C | Tagged SHA3-512 R1 | Original SHA component 1 |
| D | New tagged scheduled-SHA namespace | Scheduled SHA component 5 |

The new arm needs its own frozen descriptor, proof magic, reference vectors,
bounded scanner and freshly generated proofs for both components. The tagged
descriptor enters every hash frame, including arithmetic frames; the old
arithmetic proof cannot simply be copied into a new profile. All setup,
preprocessing, CPU, wall, RSS, bytes, failure and timeout costs must be retained.
Even a successful four-arm proof comparison would still leave mining,
production admission, confirmation, WAN and malicious service costs to the
independent end-to-end campaign.

Primary upstream explanations are the
[integrated measurement](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/1fe2f31c70977a030aec73b63fe0617f34d15a77/formal/pon-nakamoto-v1/p3_shared_primitive_qualification/BASE_INTEGRATION.md),
[frozen tagged profile](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/1fe2f31c70977a030aec73b63fe0617f34d15a77/formal/pon-nakamoto-v1/p3_shared_primitive_qualification/PROFILE.md),
and [scheduled-SHA measurement](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/09fbc0f45151a68a1bf205641171840fbf309882/formal/pon-nakamoto-v1/w1_public_stark_research/PUBLIC_SCHEDULE_MEASUREMENTS.md).
