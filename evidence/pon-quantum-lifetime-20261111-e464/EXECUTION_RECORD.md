# Frozen B execution and C archival successor — HOLD

Recorded on 2026-11-12 UTC. This record separates complete observations,
expected refusals, interrupted attempts and commands that were never run.
The [machine-readable summary](execution-summary.json) binds the original
receipts and logs to the [complete archive](validation-evidence.tar.xz).
Packaging and source-integrity checks do not grant cryptographic acceptance.

## Source identities and scope

| Identity | Role |
| --- | --- |
| `6ac9a79c2fb37d6102c526c354fe2d448a9f4e6d` | Existing #908 source from which this successor continues |
| `1f2b0187d4522b5248294ddab318f34a63bdc5a3` | Implementation checkpoint selected by the lifetime report's 20-source survey |
| `523a4f431b65f8a52128962f5880c4030e3e05db` | Frozen B source actually used by the completed scoped, CI and native observations below |
| `51b57df779e46bb16518c5c6c7aef90e48faa06d` | Frozen B tree |
| C | Later archive, execution-documentation, sole-plan and corpus-pin successor; the B executions are not represented as executions on C |

The original physical source checks before execution, after environment
recovery and after the final native attempt each covered **28,341 tracked
entries and 2,578,941,912 bytes**. Their 423-byte JSON results are identical,
with SHA-256
`68b23e7425686170f9190f09949809ec34650f4ad2025a1d47ea1062b26c6043`.
The final guard returned 0 and the worktree was clean before C edits began.
The archive retains each JSON, command output and the separate
`verification/committed-b/source-window-observation.json` reconciliation.

These are physical byte checks at the recorded snapshots. They do not prove
continuous exclusion of writes between snapshots. Per-command observers also
recorded HEAD/index identities; their records explicitly do not claim an
individual full physical-source check. The broad discovery below began before
B and crossed HEAD changes; it has its own weaker source scope and is not
relabeled as a frozen-B execution.

## Completed scoped Python observations

Thirteen complete suites executed **272 unittest methods**, with no observed
method failure, error or skip in these completed suites. The original first
eleven complete receipts are retained. After the managed environment
disconnected during the first proof-profile-binding attempt, the incomplete
attempt was preserved and that whole suite was run again in a new output
directory. No partial count from the interrupted attempt enters this table.

| Complete suite | Methods |
| --- | ---: |
| `test_quantum_adversarial_search.py` | 12 |
| `test_quantum_candidate_check_clock.py` | 6 |
| `test_quantum_daa_model.py` | 19 |
| `test_quantum_network_sim.py` | 39 |
| `test_quantum_oracle_resources.py` | 27 |
| `test_quantum_posterior_policy.py` | 23 |
| `test_quantum_resource_clock.py` | 19 |
| `test_w1_quantum_oracle.py` | 17 |
| `test_w1_marked_domain.py` | 34 |
| `test_w1_quantum_restricted_oracle.py` | 12 |
| `test_w1_upstream_security.py` | 14 |
| `test_pq_proof_profile_binding.py`, complete rerun | 31 |
| `test_w1_lifetime_ledger.py` | 19 |

The fixed QROM roster separately completed **105 of 105 named controls** and
its reader returned 0. It repeats the 19 lifetime-ledger tests already counted
above. These are execution counts, not disjoint unique-test counts. Its own
soundness, production and quantum-work qualification fields remain false;
unconditional project security bits remain null.

Five report reproductions matched the complete canonical JSON of the
retained lifetime, upstream-security, proof-profile-binding, persistent-policy
and refresh-policy reports. The two policy verification commands also matched
their complete canonical reports. The following actual nonzero results are
retained as successful observations of the declared refusal behavior:

| Command mode | Actual exit | Observed meaning |
| --- | ---: | --- |
| Upstream security `--require-current` | 2 | The selected proof profile is ineligible for current use |
| Proof-profile binding `--require-current` | 2 | The bound selected profile is ineligible; no numerical lifetime bound or activation is granted |
| Posterior policy `--require-qualified` | 3 | `REFUSED_UNPROVED_NATIVE_QUANTUM_SECURITY` |

The combined scoped campaign has 25 complete command observations: 22 zero
exits and these three expected nonzero refusals. Full diagnostics and report
comparisons are retained. This count does not incorporate the incomplete
attempt as a complete command.

## Completed CI source-contract controls

| Complete suite | Outer unittest methods | Reported seconds | Exit |
| --- | ---: | ---: | ---: |
| `test_ci_contract.py` | 189 | 284.706 | 0 |
| `test_ci_source_integrity.py` | 43 | 14.998 | 0 |
| `test_pq_research_integration.py`, complete rerun | 61 | 234.219 | 0 |

These **293 outer methods** have zero failures, errors or skips. Nested test
summaries printed by fixtures are not added to the totals. The original
research-suite session became unavailable with no terminal receipt or
unittest summary. Its 4,135-byte partial log and start record remain intact,
with a separate `UNKNOWN_INTERRUPTED` reconciliation whose actual exit and
timeout fields are null. Only the subsequent complete 61-method run counts
as completed. The earlier 189- and 43-method suites were not rerun.

The 272 scoped, 105 QROM and 293 CI figures remain separate. No combined
unique-test total or all-repository test-pass claim is made.

## Preserved broad formal exploration across source changes

Broad single-interpreter discovery started before B was frozen and crossed
HEAD changes from `6ac9a79c2fb37d6102c526c354fe2d448a9f4e6d` to B. It was
stopped with status `INCOMPLETE`, reason `STOPPED_RESOURCE_BUDGET` and
observed tool exit 130. The original verbose log contains 554 completed
method result lines:
**542 `ok`, 10 `FAIL` and 2 `ERROR`**, plus one separate `setUpClass` error
event. No final `unittest.testsRun`, terminal summary or aggregated traceback
was captured. The full log, manifest, before snapshot and runner are retained.

The recorded stop context includes incompatible global evaluation-policy
lanes in one interpreter and a historical-clone fixture consuming the
available scratch budget. The source-only failure classification is retained
as such; no missing traceback or definitive failure cause is reconstructed.
Four snapshotted script files changed during this source-changing phase.
Although the recorded formal Python and test-module bytes were unchanged, there was no
complete repository guard or final runtime import inventory. This exploration
is therefore neither an exact-B test run nor a complete formal-suite pass.

## Native execution remained incomplete

The retained setup identifies the borrowed Rust 1.95.0 toolchain and OpenSSL
3.5.9 provider SDK. Default, all-feature and fuzz-workspace Cargo metadata
commands returned 0, as did the formatting command. A separately retained C
SDK smoke program compiled and ran successfully. It did not execute native
Rust PQ tests, rebuild the SDK or run the provider's upstream test suite.
The source, executable, logs and original scope flags are all archived.

| Strict Clippy attempt | Observed status | Cargo/owner exit | Seconds |
| --- | --- | ---: | ---: |
| `20261112T000913Z` | `RESOURCE_BLOCKED`; owner stopped its build after three low-resource observations | -15 | 123.529 |
| `20261112T002723Z` | `RESOURCE_BLOCKED`; owner stopped its build after three low-resource observations | -15 | 96.741 |
| `20261112T003331Z` | `COMMAND_FAILED`; compiler child terminated by SIGKILL while compiling `trnm-pon-node` library tests | 101 | 243.579 |

For the third attempt, the observed child signal is 9 and the owner's
`resource_refusal` is null. Its underlying cause is **unknown**; an OOM cause
has not been established. The recorded SQLite I/O-boundary warning reports
an incomplete normal Cargo loader-directory set and remains
`UNQUALIFIED`. That warning is retained without attributing the later SIGKILL
to it. Source/head/tree/lock observations and borrowed toolchain/provider
hashes matched before and after this attempt.

Regular workspace tests and doc tests are **`NOT_RUN`**. The ignored
capacity/growth campaigns were outside the declared validation scope and
are also `NOT_RUN`. No further native compilation was scheduled after the
third attempt. There is no strict-Clippy pass, complete Rust baseline pass
or new native-test total on B.

The first cache-relocation receipt remains `FAILED`. Its later verification
receipt was left `RUNNING` without a captured terminal result; completion
and deletion are not inferred. These original bytes remain unchanged.
Similarly, the third-attempt summary's original pending source-after field
is preserved. The later successful source-window observation reconciles that
pending field in the new summary rather than rewriting the original receipt.

## Lossless archive and reproduction

The [archive](validation-evidence.tar.xz) is **2,377,812 bytes**, below the
unchanged **4,194,304-byte** source-reader cap. No part splitting or reader-limit
change was needed. Its SHA-256 is:

```text
82e3f7e88b83cde4bc3edff7db6b28f0cd81724978ca6929c51cb46192b43467
```

The [member manifest](validation-evidence.members.json) records **159 regular
members and 13,248,004 total member bytes**, with individual lengths, SHA-256,
Git blob identities and modes. They include 153 original verification files,
five exact-B observer/source-guard helpers and the archive producer. The
[packaging record](validation-evidence.packaging.json) records a full member
readback and comparison with the unchanged original files. It does not claim
that every embedded execution passed.

The third native attempt remains a nested 15,248-byte archive with its own
12-member inventory, original command streams, resource samples, runner,
route and final summary. Its original SHA-256 is
`2273c4cbb070d3ba4534337488a6f2676c61e48027dcf59f714a64f08bb2360d`.
The review-only PR prose draft is explicitly excluded. No original execution
log, failed receipt or unknown result is excluded for being unsuccessful.

An earlier packaging candidate returned 1 after the source-window record
appeared during collection. Its full exception, original producer, member
inventory and candidate identity are retained under `verification/packaging/`.
That draft was never promoted to the final archive. The final archive was
created only after the source-window and third-native records were complete.

To inspect this archive without running any tests, from this evidence directory:

```bash
sha256sum validation-evidence.tar.xz
tar -tJf validation-evidence.tar.xz
```

Every archived receipt and log named by the machine-readable summary uses
its exact archive member path. The current corpus pins cover the archive,
its manifest and packaging record, the execution summary and this record.
The sole-plan and evidence README pin updates do not change implementation
code or reinterpret the tested B identity. Any later checks on committed C
must retain their own actual command results and source identity.

## Security outcome

The complete reversible oracle remains an existing fixed-context
construction. Its implementation costs remain upper bounds. This campaign
provides no quantum-hardware execution, physical fault-tolerance calibration,
optimal attacker-cost lower bound or joint W1/DAA/timestamp/chainwork theorem.
The finite posterior policy remains conditional on its declared ideal model.
Lifetime security bits and error upper bounds remain null; the independent
authorization, computation-relation and quantum-work qualifications remain
false. Whole-chain qualification and production activation remain **HOLD**.
