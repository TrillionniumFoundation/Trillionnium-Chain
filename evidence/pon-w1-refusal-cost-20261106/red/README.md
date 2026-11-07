# Pre-fix regression evidence

This bundle preserves **two executed native regression failures** and all three
preceding dependency/build failures. It contains no test executables, dependency
archives, credentials, or remote-host inventory. The recorded UTC timestamps and
local workspace paths in the original command records are unchanged.

## Attempts and observed outcomes

| Attempt | Observed result | Evidence |
| --- | --- | --- |
| W1 cache, default offline registry | Exit 101: `wait-timeout` absent; test did not run. | [original log](w1-cache/pre-fix-c-variants.log.gz) |
| W1 cache, existing offline registry | Exit 101: `zeroize 1.8.2` absent; test did not run. | [original log](w1-cache/pre-fix-c-variants-existing-cache.log.gz) |
| W1 cache, restored task-local registry | Exit 101: one native test failed, zero passed. Four canonical C variants each replayed **512 transcript tiles**; the regression expected `512, 0, 0, 0`. All four still returned `Err(Relation(Transcript))`. | [native failure](w1-cache/pre-fix-c-variants-native-red.log.gz), [identity and all three commands](w1-cache/pre-fix-source-and-attempts.json) |
| Node owner, release profile | Exit 101: the `trnm-pon-node` lib-test compiler process received **SIGKILL**; test did not run. This bundle does not establish the cause of that signal. | [command record](owner/owner-red.json), [original log](owner/owner-red.log.gz) |
| Node owner, explicit test-profile environment | Exit 101: one native test failed, zero passed. A real complete W1 granted completion priority; with an explicitly injected credit deficit, the shared writer reached the refill-wait path: **two resource checks**, `TEST_REFILL_WAIT_UNDER_OWNER`. | [command record](owner/owner-red-test-profile.json), [native failure](owner/owner-red-test-profile.log.gz) |

The W1 failure demonstrates a negative-cache identity miss when only canonical
C bytes change. It does not demonstrate forged valid consensus work. The owner
failure is a deterministic scheduling control, with `injected_credit_deficit`
true and `service_qualified` false in its original output. It does not measure an
attack amplification ratio or establish the original four-second service gate.

The missing `zeroize` archive was copied from an existing local archive only
after matching the locked SHA-256; the original [restoration record](w1-cache/zeroize-cache-restoration.json)
is retained. The archive itself is not included. The SQLite I/O-boundary
`UNQUALIFIED` warnings in both Node build logs also remain unchanged.

## Source and build identity

Both regressions use baseline commit
`0ca272d09d1522b0ffd740e441b6d3de1ed81de6`, tree
`8c3417aa4bfec4c8ed068d615bba83583360a632`.

The W1 run used the baseline plus the [tests-only patch](w1-cache/regression-only.patch),
with exact dirty-file blob and SHA-256 recorded in its original identity JSON;
it is not represented as a new clean source commit. The owner run used tests-only
commit `6228b3da159c0bb69f9dbe50815f70a1a53a3171`, tree
`7131ac7ed6b2033323bded0e0ca09c6d8568655d`. Its [patch](owner/regression-only.patch)
is the read-only full-index Git diff from the baseline; [source identity](owner/source-identity.json)
records the parent, only changed path and exact blobs. Both command recorders
verified the owner tree before and after; that identity check itself ran no tests.

The successful Node compilation used the recorded environment
`CARGO_PROFILE_TEST_OPT_LEVEL=0`, `CARGO_PROFILE_TEST_DEBUG=0`, and
`CARGO_PROFILE_TEST_CODEGEN_UNITS=256`. These are global test-profile settings,
**not an all-crates opt-level-zero build**. The unchanged pinned
[Cargo manifest](owner/test-profile-Cargo.toml) retained package overrides:
`trnm-pon-node`, `trnm-crypto-primitives`, `trnm-protocol`, `curve25519-dalek`,
`ed25519-dalek` and `sha2` use opt-level 3; `trnm-mvcc-fee` uses opt-level 1.
Those package opt-level overrides were not changed by the global opt-level-zero
setting. Cargo's top-level `[unoptimized]` banner does not describe each crate's
effective override. These local regression builds do not certify release
performance, memory limits, CPU quotas, or service qualification.

## Byte preservation

[manifest.json](manifest.json) records original and stored lengths, SHA-256
hashes, original Git blob IDs, source names, and compression for every delivered
file except the manifest itself. Original JSON and patch files are copied
byte-for-byte. Logs use deterministic gzip (empty filename, `mtime=0`, level 9);
decompression restores the exact original bytes, including the release failure.
Recorder `log_file` names retain their original `.log` spelling; append `.gz`
for the stored file in this bundle. Packaging verified every recorded log hash,
the restoration checksum against the frozen lockfile, and both patches by
reconstructing their exact recorded source blobs in temporary directories.
Packaging did not run Cargo, rewrite historical results, or qualify a repaired
candidate.
