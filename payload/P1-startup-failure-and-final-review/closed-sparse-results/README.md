# Closed P1 sparse-checkout startup records

This archive preserves four completed ROG evidence directories as their original bytes.
It does not rerun the repository lane, its tests, the original producers, or any Git command.
It excludes the active full-v2 directory and the source worktree/Git database.

## Preserved originals

| Original directory | Files | Bytes |
|---|---:|---:|
| final-repository-truth-offline-6a8cd5-v1 | 35 | 24,402 |
| P1-index-flag-diagnostic-v1 | 22 | 4,199,223 |
| P1-sparse-checkout-precorrection-v1 | 5 | 4,133 |
| P1-sparse-checkout-correction-v1 | 33 | 8,396,904 |
| Total | 95 | 12,624,662 |

The first run remains failed: its 17 recorded stages stop at source verification and the
repository-truth test command did not start. Its source-before.json and source-after.json
were absent and are not fabricated here. The later correction remains separately recorded
as FULL_CHECKOUT_RESTORED_AND_ORIGINAL_SOURCE_VERIFIED. Root's normal sparse-checkout
disable restored two tracked historical ZIP files from existing local objects; neither
restored ZIP body nor the source/Git directory is included in this archive. No source
commit, gate logic, test expectations, quota, worker count, or deadline was changed by
this capture. A successful checkout verification is not a full lane or hosted performance pass.

All three 4,191,866-byte flags stdout files are retained in full, including their NUL bytes.
The empty first-run ci-observations and tmp directories are recorded and recreated.
The twelve selected original Mac root start/terminal/log records preserve all four actual
closed PTYs. Unrelated and active root tool records are excluded.

## Verification and transport

The ROG packager checked an exact previously observed inventory, all four original summary
SHA256 values, regular single-link files, canonical NOFOLLOW directory traversal, and
stable file/directory fingerprints. It reread all 95 original files for their SHA256 after
writing the ZIP. All 99 ZIP members (95 originals plus three package records and index)
were verified for CRC, bytes, and SHA256 on both ROG and Mac.

The ZIP is 1,095,716 bytes with SHA256
a6057f107f220d146be4fbe70d6ef60b369bf29eaa40f65a640556fd4840b844.
Seventeen official binary reads were pinned to one source version and copied through
five create-only official Mac binary writes. Every read chunk and write part was checked
against the assembled ZIP. Binary payloads reside in the exact parts/ZIP; read metadata
explicitly omits repeated base64 text. Full write receipts and actual packaging/receiver
PTY records are retained. The receiver used only the exact ZIP index, no extractall,
and checked each newly written target again through a stable descriptor.

The scope is the four explicit closed evidence directories, their transport/package
records, and the twelve selected original root tool records. It is not an audit of an
active run, the repository, its history, or all secrets. No stage was written during
this capture; any later materialization has its own receipt and baseline protection.
