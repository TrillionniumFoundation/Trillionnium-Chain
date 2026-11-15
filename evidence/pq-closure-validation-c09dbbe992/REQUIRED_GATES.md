# C1 required-gate supplement

This separate local execution completes two retained repository-truth gates for
commit `c09dbbe9921da12db8bf7240a8a95a0e9a789e50`, tree
`f15a7ee4a0f5455eaf965db01dcd49e02a5f22b6`:

| Original command | Observed top-level tests | Exit | Timeout | Skipped |
| --- | ---: | ---: | --- | ---: |
| `python3 -B scripts/ci/test_pq_chain_claim_guard.py` | 55 | 0 | false | 0 |
| `python3 -B scripts/ci/test_ci_execution.py` | 77 | 0 | false | 0 |

The 77 verbose success IDs include 43 raw source-integrity controls, 7 process
ownership controls, 9 Rust shard controls, 9 required-native-result reader
controls, 8 observation controls, and 1 source identity control. The claim guard
retains exactly 55 success dots and a successful unittest summary; its original
log does not contain individual test IDs. The source-integrity fixtures print
five deliberately failed nested receipts and one successful nested receipt to
stdout. Those original bytes are retained; all 77 outer tests finish `ok`.

The two original materialized source snapshots are byte-identical, with SHA-256
`81966162e2ae881348ae09cb94879b8b705fd309fba1d79b1d30aeb86f676b1f`.
They cover 5,135 materialized tracked files and 171,498,180 bytes. Another 22,777
tracked paths remain absent under sparse checkout. `full_checkout_materialized`
stays false. Independent packaging verification compared the listed files to
both the C1 Git objects and the actual materialized bytes and modes.

## Accounting and retained limits

The [original static package](static-summary.json) remains unchanged at 577
top-level Python executions. This supplement adds 132, giving **709 top-level
executions across the retained runs**. This is not a count of 709 independent
security properties; the count of independent security properties is unknown.
The earlier integration attempt still has an unknown terminal state, its 18
progress dots remain excluded, and no single uninterrupted run is claimed.

This supplement does not contain native workload or hosted CI results. Its
verifier does not execute tests, Cargo, the original harness, or native work.
All whole-chain qualification and production activation flags remain false.

## Files and read-only verification

- [required-gates-summary.json](required-gates-summary.json) derives the two
  completed results and their counting scope from the original logs.
- [required-gates-raw-c09dbbe992.tar.xz](required-gates-raw-c09dbbe992.tar.xz)
  retains all nine regular files from the original supplement directory plus
  the original `validate_required_supplement.py` harness. The unused empty
  `qrom-observations` directory has no files to retain.
- [required-gates-raw-index.json](required-gates-raw-index.json) gives every
  original file's byte length and SHA-256.
- [required-gates-source-verification.json](required-gates-source-verification.json)
  records the independent source comparison, source-derived execution roster,
  and the identities of all eight preserved original static-package files.
- [REQUIRED_GATES_SHA256SUMS](REQUIRED_GATES_SHA256SUMS) covers this supplement's
  six payload files. These integrity hashes do not authenticate an external
  operator or create a security attestation.

Run the [read-only verifier](verify_required_gates.py) after placing these files
beside the original static package:

```bash
python3 -B evidence/pq-closure-validation-c09dbbe992/verify_required_gates.py
```

Optional `--originals /path/to/original/workspace` compares all archived bytes
with the original files. Optional `--git-source /path/to/repository` reads local
C1 Git objects and checks every retained source record. It disables lazy fetch
and Git replacement objects. Neither option launches the original tests or
changes the repository.
