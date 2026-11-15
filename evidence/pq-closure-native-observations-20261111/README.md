# Exact-source native observations — original failures retained

These packets preserve separate native process observations. The original C1
group failed its two 1,200-second aggregate targets. Later observations of
remaining cases cannot change those failures or establish the original aggregate
budget. Whole-chain PQ qualification and production activation remain false.

## Original C1 group

The executed commit is `c09dbbe9921da12db8bf7240a8a95a0e9a789e50`, tree
`f15a7ee4a0f5455eaf965db01dcd49e02a5f22b6`. The durable job
`1a1c8c0948c-135c4-200` completed all 27 planned commands, with 25 successful
commands and two timed-out native targets. The job ended with exit 1; its outer
job deadline did not time out. The actual command group ran from
`2026-11-11T03:57:37.330856+00:00` to
`2026-11-11T05:32:53.392866+00:00`.

| Original native target | Planned names | Complete target result | Separately retained partial successes |
| --- | ---: | --- | ---: |
| M06 account profile and development scope | 9 | Both targets passed | 0 |
| Root owner V3 | 20 | Passed | 0 |
| Recovery floor V4 | 9 | Passed | 0 |
| Provider effect readback V4 | 14 | 1,200-second timeout; SIGTERM, exit -15 | 4 |
| Root budget V4 | 6 | Passed | 0 |
| Witnessed Root V5 | 17 | 1,200-second timeout; SIGTERM, exit -15 | 6 |
| Durable witness V5 | 12 | Passed | 0 |
| Node scope, settlement, complete-key TLS, QTX1 recovery, distinct invalid work | 10 | All selected targets passed | 0 |

The 13 completely successful native targets account for 66 of the 97 planned
names. The two failed targets contain ten additional named `ok` lines, so the
original logs contain 76 named successes. Those ten are partial observations,
not complete target passes. Strict workspace/all-target/all-feature Clippy also
passed with warnings denied. Version, locked/offline metadata, formatting,
repository, inventory and source-corpus commands passed.

A successful test means its stated assertions completed. Some tests deliberately
retain common-restore counterexamples in which all relevant authorities are
rolled back together. Their successful completion is evidence that the stated
limitation remains reproducible; it is not evidence that every restore attack
was rejected.

The original [archive](original/native-original-c09dbbe992.tar.xz) is 1,557,288
bytes, SHA-256
`6d22e3ca7dcd98a75da46f6717f122f2293fa0d870a5aa2807e7f8252aee6acd`.
Its 90 members include original raw stdout/stderr, receipts, exact plans,
before/after source and Provider records, the runner, and capacity-recovery
preparation. The [export receipt](original/export-receipt.json) and
[portable verification](original/portable-verification.json) remain separate
from the recorded workload result.

An [independent Git verification](original/git-verification.json) checked all
27,912 tracked file entries against their Git content, including 20,796 distinct
blob identities and 2,554,106,689 bytes summed across entries. Source and
Provider before/after records agree. This verifies the retained source binding;
it does not attest execution on the host.

## Separate observations of remaining C1 cases

The Provider readback subset completed all ten selected names, with zero failed,
ignored or measured cases and exactly four filtered original successes. Its
native command exited 0 after 888.0155 seconds under the unchanged 1,200-second
limit. All three commands passed, full source and Provider before/after records
matched, and the group closed at `2026-11-11T06:10:20.356975+00:00`. It retains
`original_group_failed=true` and `aggregate_budget_qualified=false`.

The [readback archive](readback/native-readback-subset-c09dbbe992.tar.xz) is
1,485,388 bytes, SHA-256
`878e1c55747030ef3629edea182a39ae508cdf4362cdce89078251199e57844f`, with 18
verified members. Its [producer receipt](readback/export-receipt.json),
[portable verification](readback/portable-verification.json) and
[independent repeat of the evidence check](readback/independent-verification.json)
are retained. Neither evidence check reruns a native workload. A separate
[read-only observer record](readback/postcheck-observer.json) shows the slow
post-run source audit making I/O progress; no signal, injection or workload
restart was used to resolve that delay.

The witness V5 subset completed all eleven selected names, with zero failed,
ignored or measured cases and exactly six filtered original successes. Its
native command exited 0 after 967.2132 seconds under the unchanged 1,200-second
limit. All three commands passed, full source and Provider before/after records
matched, and the group closed at `2026-11-11T06:36:09.610+00:00`. It likewise
retains the original aggregate failure.

The [witness V5 archive](witness-v5/native-witness-v5-subset-c09dbbe992.tar.xz) is
1,485,528 bytes, SHA-256
`6c43489d81a1d809a4a85d04bd1cc7381466509606468930049fb83124328d12`. Its
[producer receipt](witness-v5/export-receipt.json),
[portable verification](witness-v5/portable-verification.json) and
[independent evidence check](witness-v5/independent-verification.json) are
retained separately.

The [named coverage calculation](C1-COVERAGE.json) compares the independently
fixed expected roster with actual recorded successful names. It finds exactly
97 distinct names: 66 from complete original targets, ten from partial original
targets, and 21 from the two separate subsets. There are no missing expected
names or repeated completed names. This is coverage across three process groups,
not a successful original 97-name aggregate run or a count of independent
security properties.

Each subset lists the exact remaining names first and executes the original
binary through a held, hashed file descriptor. Provider readback skips precisely
the four original successes and selects ten names; witness V5 skips precisely
six and selects eleven. Both retain one test thread, the original 1,200-second
limit and original internal budgets. Neither invokes Cargo or rebuilds its
executable. No additional subset or relaxed retry is inferred from these records.

The ELF binaries are not included in the archive. Their paths, sizes, SHA-256
values and descriptor-binding checks are retained observations. Offline
verification does not independently rehash an absent ELF or prove that a host
executed it.

## Exact C2 recheck

C2 is `0e554f36ffdde3053a5eb1756eb5e526b1935032`, tree
`753cdbad6714f00d8ccb9ddbb47f0fd71280ee62`. Relative to C1 it changes exactly the
readiness checker, the corresponding test file, and the corpus JSON containing
two reviewed blob-pin updates. Rust source blobs and Cargo manifests/lockfiles
are unchanged.
The corpus is embedded in Node library/example inputs, so this is not an
evidence-only source revision.

The durable job `1a1c959a9a8-2564-84` completed all 14 commands successfully and
closed at `2026-11-11T07:02:24.631261+00:00`, with exit 0 and complete durable
output. The eight native cases comprise four Node account-scope cases, one
settlement case, and three complete-key TLS identity cases. Strict
workspace/all-target/all-feature Clippy completed in 70.0103 seconds with
warnings denied. Both test and development profiles retained their original
unoptimized builds with debug information. Source and Provider before/after
records match; no command remained unstarted and no group fatal error occurred.

The [C2 archive](c2/native-c2-0e554f36ff.tar.xz) is 1,545,892 bytes, SHA-256
`5883dad77151ce4632caac4e442e6be1d959bf8fb442a9c41a7fa09dfd0ad804`,
with 51 verified members. Its [producer receipt](c2/export-receipt.json),
[portable verification](c2/portable-verification.json), and
[independent evidence check](c2/independent-verification.json) are separate from
the workload observation. The verifier also checks the bindings to the original
C1 archive and both remaining-case archives. Original C1 failures are retained;
the C2 pass does not establish either failed C1 aggregate's time budget.

The selected C2 plan contains 14 commands, including eight actual native Node
cases and strict workspace Clippy. It reused the private target only after all
three C1 observation groups have closed. This is not a clean-build assertion.
The C2 source snapshots cover 27,912 tracked entries and 2,554,108,569 bytes;
the exact three changed blobs account for the 1,880-byte net delta. Earlier C1
native and hosted observations keep their original source identities.

## Reproduce the evidence checks

The fixed [verifier instructions](verify/README.md) document the complete CLI.
The preparation-time review status in that file is retained unchanged; actual
verification results are stored beside each delivered archive. The verifier
scripts read packet contents without extracting or executing native binaries.

Run the original packet check from this directory:

```sh
python3 -I -B verify/verify_desktop_native.py \
  --archive original/native-original-c09dbbe992.tar.xz \
  --receipt original/export-receipt.json \
  --expected-plan verify/expected-native-plan-c09dbbe992.json
```

Optional `--git-source /absolute/path/to/repository` recomputes referenced C1
Git blobs with lazy fetch and replacement objects disabled. Without that option,
the result explicitly leaves this additional recomputation unclaimed. Adding
`--output /absolute/path/to/new-result.json` creates a new result exclusively.
Evidence-verifier success and workload success are separate fields.

Check the two C1 remaining-case packets independently:

```sh
python3 -I -B verify/verify_desktop_subsets.py \
  --kind readback \
  --archive readback/native-readback-subset-c09dbbe992.tar.xz \
  --receipt readback/export-receipt.json \
  --original-archive original/native-original-c09dbbe992.tar.xz \
  --original-receipt original/export-receipt.json

python3 -I -B verify/verify_desktop_subsets.py \
  --kind witness-v5 \
  --archive witness-v5/native-witness-v5-subset-c09dbbe992.tar.xz \
  --receipt witness-v5/export-receipt.json \
  --original-archive original/native-original-c09dbbe992.tar.xz \
  --original-receipt original/export-receipt.json
```

Check C2 and all required cross-packet bindings:

```sh
python3 -I -B verify/verify_desktop_c2.py \
  --archive c2/native-c2-0e554f36ff.tar.xz \
  --receipt c2/export-receipt.json \
  --readback-archive readback/native-readback-subset-c09dbbe992.tar.xz \
  --readback-receipt readback/export-receipt.json \
  --witness-v5-archive witness-v5/native-witness-v5-subset-c09dbbe992.tar.xz \
  --witness-v5-receipt witness-v5/export-receipt.json \
  --original-archive original/native-original-c09dbbe992.tar.xz \
  --original-receipt original/export-receipt.json
```

The complete delivery index records the separate hosted performance and API
failures. None of these native packets changes hosted CI status, grants release
or production permission, proves quantum mining security, or supplies a
whole-chain lifetime failure bound.
