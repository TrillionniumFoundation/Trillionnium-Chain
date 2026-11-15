# Local build attempts, preserved failures, and publication identity

These are preparation and build observations, **not native test passes**. No
test case ran during any of the five attempts. The original Cargo manifests,
source-pinned compiler requirement, SQLite layout guard and service budgets
were not relaxed.

| Attempt | Actual observation | Exit |
| --- | --- | --- |
| 01 | The available manual toolchain was 1.96 rather than the required 1.95; stopped before tests. | 130 |
| 02 | Exact 1.95 was available, but the SQLite build guard required an absolute real `RUSTC`; stopped to correct the command environment. | 130 |
| 03 | The manual toolchain lacked its normal loader-library directory in the command environment; stopped to supply the real installed directory. | 130 |
| 04 | With those original environment checks satisfied, the `trnm-pon-node` lib-test compiler was terminated by signal 9 (`SIGKILL`). | 101 |
| 05 | A single-job, locked, offline `cargo check --tests` also lost the lib-test compiler to `SIGKILL`, while emitting metadata. | 101 |

The signal alone does not identify its cause. Partial dependency builds, a
production library metadata file and integration-test check artifacts do not
turn either complete command into a pass. There is no successful native test
binary from these attempts and no local business throughput measurement.

The first suitable compiler was the real Rust 1.95.0 installation. The command
environment used its absolute compiler path and its actual `lib` directory;
no build-guard code, allowlist, witness or fallback was changed. The complete
commands are retained in the original attempt manifest, and original
stdout/stderr are retained in the five `.txt` files. The original manifest's
`.log` names map to the same basename with `.txt` here because repository ignore
rules exclude `.log` delivery. No log bytes changed: the original and delivered
size/SHA-256 pairs match. Their delivered names and content hashes are in
[members.json](members.json), with original names and classifications in
[history-preliminary-build-attempts.json](history-preliminary-build-attempts.json).

These were preliminary runs while source declarations were being integrated;
they are not advertised as a final immutable-head qualification. The later
hosted comparison must preserve its own source-before/source-after, exact
compiler and artifact observations.

## Publishing the same source trees

The preferred HeptaRuntime channel returned timeouts and later internal errors
for transfer operations. No successful source-transfer receipt was obtained.
The already-authorized GitHub connection independently identified `ProfHepta`.
It published the reviewed Git blobs with exact hash equality.

| Source point | Local preparation commit | GitHub commit | Identical tree |
| --- | --- | --- | --- |
| Old production plus the seven new controls | `a53aaee3c827f29abeaa2aa3d4ef7355205dba40` | `d6bbac6baf9e5356721ab56f7432058d07b6b49b` | `653b1a8b483ccdbf69b272255ec0369d98296302` |
| Implementation and original evidence | `9029f2ab2c6382aaaf096b841a20fbf335f4b172` | `b7e38fdc2e43c468692abc52aec03737f2df7f1b` | `b75d318fc7b7b027a810f4a70a9cd91e0b3930f8` |

Publication changes commit metadata, not source bytes. The GitHub commit
objects were reconstructed from the returned metadata and accepted locally
only after their complete Git SHA-1 identities matched. The API's UTC dates
omit the raw author/committer timezone; the matching raw objects use `-0500`.
Both old local commits remain retained, rather than being relabeled as hosted
execution. See [publication-source-map.json](publication-source-map.json).

The final source locks must name the real published implementation commit.
Tree equality does not create a native test result or close the original
confirmation campaign.
