# Exact merged native validation

The frozen source is commit `2d46d8682201bc0619f5b156af50e77fb399322e`,
tree `5ae5317304588cca8295a19dd512c8e853f1ef5b`.
The successful HeptaRuntime job is `1a1b8800181-12894-fd1`.
Its authoritative status is succeeded, exit 0, with complete durable output.

## Coverage

[coverage.json](coverage.json) and [source-identity.json](source-identity.json)
bind the result to the exact source. The
[stage record](original/attempt-02/stages.json) retains every command, elapsed
time, and return code. Locked/offline Cargo metadata, workspace formatting, and
strict Clippy over the library, four retained tests and two examples passed.

| Native test target | Passed |
| --- | ---: |
| cell_native_v1 | 12 |
| native_owner_journal | 10 |
| native_owner_observation | 10 |
| native_risk_ledger | 11 |

Two subprocess helper entries remain ignored by the ordinary test harness and
are exercised by their parent tests. Independent reader suites passed 21 owner
tests and 25 risk tests. The actual CC1 packet join and all 16 composition tests
passed.

The owner and risk standalone examples were rebuilt from this exact source and
executed into two new directories. Their original journals, packet artifacts,
SQLite files, child plans, run records and independent results are retained:

- [Fresh owner run](original/attempt-02/fresh-native-owner/run.json)
- [Fresh risk run](original/attempt-02/fresh-native-risk/run.json)
- [Owner independent result](original/attempt-02/owner-checked.json)
- [Risk independent result](original/attempt-02/risk-checked.json)
- [Actual CC1 composition summary](original/attempt-02/composition/summary.json)

The risk run has eight starts, seven covered native confirmation intents, six
outcomes and two unresolved charged starts. Its expenditure is 36 units of a
40-unit declared capacity, with denominator 1000. These are bookkeeping units;
the global failure probability remains null.

## Preserved first attempt

The first job, `1a1b87da53a-12894-fc6`, exited 1 before native compilation.
Its harness incorrectly required merged AGENTS bytes to match the first
parent. The incoming commit legitimately added the ProfHepta/HeptaRuntime
GitHub instruction. The instruction was read and followed; the second harness
checks AGENTS against the exact merged Git object. No repository policy,
source or SQLite qualification guard was changed.

The original first-attempt stage logs remain at the root of
[original](original). Its full runtime stdout, stderr, command and terminal
status are retained alongside the complete successful attempt. This harness
failure is not represented as a source regression or a native test failure.

## Byte integrity and scope

[binary-sha256.json](binary-sha256.json) records the exact post-validation bytes
of the two examples and four test executables. Executables and build caches
are not copied. These hashes are measurements after validation and do not
constitute independent execution attestation.

Source snapshots retain original bytes. Markdown snapshots use `.md.source`;
their original logical names and retained paths are recorded by the source
manifest. [physical-files.json](physical-files.json) records file sizes and
hashes, while [SHA256SUMS](SHA256SUMS) covers every retained file except itself.

The validation does not cover the entire workspace, authorize production
activation, authenticate physical clocks or hidden inventory, or establish a
conditional probability law. All existing qualification limits remain in force.
No final merge commit or push was performed by this validation task.
