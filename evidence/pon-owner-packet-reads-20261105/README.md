# Operator-owner stored packet read boundaries

Validated source `0083f3c1bfca1e03af63ad3c6f6e11199b7bfbed`, based on candidate `133c0d458e46daccbe43f6d758d3887a40a72c0b`.

Seven equality/decode reads use the existing 1 MiB packet boundary plus one sentinel byte. Oversized BLOBs remain unequal or codec-invalid; NULL and non-BLOB conversion errors, packet column names, absent-row behavior, callback ordering, provenance and local journal facts are preserved. Two digest-only authorization reads hash the complete borrowed SQLite BLOB. They do not truncate the authorized digest or introduce a packet codec prerequisite.

The change avoids oversized Rust packet copies from damaged/restored storage. It does not bound SQLite allocation, hashing CPU, lock duration or process RSS. Digest hashing now occurs while the row statement is alive. No packet schema, wire encoding, authorization threshold, allowance, original 4000 ms deadline or hostile-W1 requirement changes.

## Verification

Original locked Cargo test configuration: **157 distinct passed, 0 failed, 1 existing ignored**. The focused digest test and two owner gate tests are subsets, not additional passes. Full native-authenticated, mining-owner, continuous-owner, PQ-startup, task-observation, admission-wire and request-observation selections passed. Strict workspace/all-target/all-feature Clippy, formatting, 37 source controls, 100 CI controls, 526 source pins and 26 inline workflow pins passed.

The mining fixture reaches all three modified mining paths using synthetic wire-valid work, not a fully admitted W1 proof. The new continuous fixture covers three ordinary paths and the active-tip shortcut, not every digest-activation or PQ-startup negative branch. The shared digest conversion regression covers 4 MiB blobs with matching bounded prefixes but different tails, full SHA identity, empty/missing values and conversion errors. Existing real PQ startup tests provide positive bootstrap/controller/history/cold-reopen coverage. These focused tests are not a full-node suite or pinned-provider PQ qualification.

Two earlier compiles were interrupted by environment restarts. An intervening build failed at linking with undefined hidden symbols; no native tests ran in those attempts. Only this task's interrupted incremental caches were reversibly archived and verified before a fresh same-profile compile succeeded. These outcomes remain in the raw logs; cache inconsistency is a suspected diagnosis, not a concealed source failure. No other task artifacts were removed.

See [machine-readable verification](verification.json) and [raw logs, source patch and reproduction job](raw-validation.zip). The final evidence-only commit does not alter tested source. Original native campaign and fixed Host F0 remain separately required on the exact integration head. No release, activation or global blocker closure is claimed.
