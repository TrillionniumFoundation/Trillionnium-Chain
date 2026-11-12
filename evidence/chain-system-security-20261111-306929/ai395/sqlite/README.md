# SQLite fixed-source native observations on AI395

All 17 focused controls and 15 retained compatibility controls passed. The four
affected packages' strict Clippy command also passed. The original native owner
exited with code 0 and complete captured output.

Tested source: bac6b7659bd7e2d633e25c2da0add60f6a10c7fb. The 20 command receipts each record matching full
tracked-source identities before and after execution: 28327
entries and 2578801275 bytes. Builds used Rust 1.95,
the default Cargo features and profiles, one build job and one libtest thread.

| Package | Focused | Retained |
| --- | ---: | ---: |
| trnm-data-availability | 8 | 3 |
| trnm-mvcc-fee | 3 | 3 |
| trnm-service-settlement | 2 | 3 |
| trnm-task-kernel | 4 | 6 |
| Total | 17 | 15 |

The retained controls use the exact current ELFs identified by the focused Cargo
runs. All 15 were pinned and observed by the repository's native-process
recorder, and their exact named-test checks passed. ELF hashes were checked
again after Clippy. Executable bytes are retained in the build target, not
packaged in this evidence directory.

The strict command is cargo clippy for these four packages with --locked,
--offline, --all-targets and -- -D warnings, without an all-features override.
The exact argv, environment, source identity, raw output and terminal status
remain in the original receipts. The driver, test plan, launch input, actual
launcher and original owner output are preserved alongside them.

[verification.json](verification.json) checks 32 distinct crate/test pairs,
20 successful command receipts, their raw-log bindings, full-source equality,
native executable pins and the provider/tool input identities.
[manifest.json](manifest.json) lists every published payload by path, size and
SHA-256. [native-records.tar.gz](native-records.tar.gz) is an exact copy of the
curated raw records and execution inputs. Original zero-byte command streams are
preserved; Hepta temporary lock/cache files are excluded without modifying the
original receipt directory.

Two controller binary-read requests timed out while observing already durable
files. Those transport errors are retained in owner-observations.json. The AI
startup verified the launch, driver, plan and provider bytes before execution;
the original native owner and all command receipts completed independently.

These observations qualify the recorded local SQLite opening and compatibility
controls on the specified candidate. The earlier old-source negatives and the
original 9021 native observations keep their own source identities. The original
cloud Clippy interruption remains an incomplete historical observation.

The local metadata refusal still has a check/open race boundary. Ordinary WAL
owners keep their existing contracts. This work does not establish a remote
consensus exploit, global network liveness, external-effect rollback or
whole-chain security. Production activation and release acceptance remain false.
