# Selected PFT owner: actual validation records

This evidence follows [PR #1027](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/1027).
The four original SQLite-owner-to-wrapper controls remain **unexecuted**.
The exact source is `1bd4a71c6efaa6921237fd4612d37cb7ef0e4645`; this slice changes no production source, assertion, profile, dependency or acceptance threshold.

## Preserved observations

| Gate | Actual observation | Scope |
| --- | --- | --- |
| Earlier c471 follow-up | 2 original SQLite controls passed; real wrapper library typechecked | 118.451852001 s; preserved in #1027, not rerun here |
| First actual four-control gate | Cargo exit 101; 55 missing-file diagnostics; compiler summary 110 errors; 0 tests | 172.260651891 s outer; input materialization failure |
| Complete lexical input repair | 72 original Git blobs / 1,960,862 bytes restored | No source or test change; no Cargo invocation |
| Separately authorized environment follow-up | Original 180 s command deadline reached; owned group killed/reaped; exit −9; 0 tests | 181.941599870 s outer including cleanup and source checks |

Neither failure replaces the original 240-second attempt or the earlier separately scoped pass.
The cleanup reservation was 66 seconds; it did not extend the 180-second test deadline.
All 1,850 source pins and seven prior receipts were unchanged across the follow-up.
No automatic rerun, old 9/11/6/2 controls, private input, scientific fit or prediction occurred.

## Exact lexical input closure

The fixed `trillionnium` subtree has 1,718 blobs, including 1,639 `.rs` files.
All 1,952 lexical `include_bytes!`, `include_str!` and `include!` occurrences resolve to 1,788 unique targets, including `examples`, `tests` and build scripts.
Every target is checked against the fixed Git blob and mode; parent and leaf symlinks are refused.
There are zero missing targets, unresolved expressions, lexer failures or external Rust `include!` targets after repair.
The proof reconstructs 368 Git trees. It covers these literal/concat-manifest expressions, not general macro expansion or a whole-repository build.
[restored_72_git_blobs.jsonl](restored_72_git_blobs.jsonl) is a derived, one-record-per-file review index.
The recorded scanner, materializer and gate driver retain their original isolated paths and are execution records, not installed production commands.
The initial read-only scanner was interrupted for repeated string-slicing overhead; the retained linear scanner produced the completed inventory. No numerical control was retried in that change.

## Optional SQLite-I/O qualification remains false

The follow-up stderr contains the optional `trnm-sqlite-io-boundary` UNQUALIFIED warning and `Compiling trnm-pon-node`; it contains no new Rust error or test output.
The [fixed build fence](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/1bd4a71c6efaa6921237fd4612d37cb7ef0e4645/trillionnium/crates/trnm-sqlite-io-boundary/build.rs) admits ordinary Node compilation while its bounded-I/O API remains unsupported.
Its canonical-real-RUSTC and no-external-RUSTFLAGS requirements are not qualified by this frozen `-D warnings` gate. The warning does not establish the cause of the timeout.
No bounded-I/O witness, host permission, real adoption, FinalUse, quality, reward, payment or activation is claimed.

## Original bytes

The three `*_originals.json.zlib` files are compressed original-artifact envelopes, with each member's raw bytes in base64, byte length and SHA-256. `fixed_include_inputs.json.zlib` is a separate packet containing exact public Git metadata and 72 original build inputs with explicit UTF-8 or base64 encoding.
`first_failure_originals.json.zlib` retains the nine first-gate originals; `include_closure_originals.json.zlib` retains the four closure originals; `environment_followup_originals.json.zlib` retains the seven follow-up originals.
For publication, the three larger archives are stored as at most 65,536-byte parts; [ARCHIVE_PARTS.json](ARCHIVE_PARTS.json) fixes order, offsets, per-part digests and the unchanged whole-archive digests. Concatenate the listed parts and verify the complete SHA-256 before decompression. The follow-up archive remains one file.
Native GitHub uploads first retained TLS/reset failures and HTTP 400 responses for whole-archive requests; splitting changes storage layout only.
Logical artifact inventories and digests are in [ARTIFACTS.json](ARTIFACTS.json). Raw outer receipts, gate receipts, stdout, stderr and executed follow-up driver remain byte-exact; [OBSERVATION.json](OBSERVATION.json) is explicitly a derived summary.
Native readback pinned the immutable file version, verified every chunk and whole archive, then verified all decoded members. One closure-archive chunk returned INVALID_ARGUMENT; its same-version read retry succeeded. No measurement was reconstructed from a summary.
Remote CI is separate: the latest observed first page for 1bd4 lists 19 queued runs, which are not passes. Earlier CodeQL, missing-artifact and service-acceptance failures remain preserved.
