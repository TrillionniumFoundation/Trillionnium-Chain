# Validation receipt index

[The raw validation archive](../validation-raw.tar.gz) retains commands, stdout,
stderr, exit status and source identities from the owned recovery checkout.
[Its member inventory](../validation-archive-index.json) records every included
regular file's length and SHA256. Archive paths are evidence identifiers;
building the future publication commit requires its own clean-source checks.

The archive deliberately excludes toolchain binaries, compiled Cargo targets,
the OpenSSL build tree and its disposable private smoke keys. It includes the
unchanged pinned provider script's public build/smoke log and qualified provider
receipt, so source version, archive digest, actual algorithm smoke and export
conditions remain inspectable.

## Completed component observations before publication

| Component or command scope | Observed result |
| --- | --- |
| Native all-target/all-feature tests, with pinned OpenSSL 3.5.9 | 240 passed, 0 failed, 0 ignored |
| Native all-target/all-feature strict Clippy | PASS, `-D warnings` retained |
| Independent W1 v2 verifier unit tests | 2 passed |
| Independent verifier all-target strict Clippy and release build | PASS |
| Staged backend all-feature tests | 22 passed, 0 failed, 0 ignored |
| Staged backend all-target/all-feature strict Clippy and retained release build | PASS |
| M12 GenerationV2 component tests before final experiment-config expansion | 10 passed |
| Real Node component controls before final experiment-config expansion | 6 passed; heavy test explicitly ignored |
| Initial added CI command block, actual argv and count guards | 66 passed; later added controls have separate records |
| Independent CI lane controls after global-duplicate repair | 35 passed |
| Independent PQ source contract controls | 39 passed |
| CPU worker data contracts | 12 passed |
| Worker actual process supervision | Ordinary child reaped; escaped-session descendant killed/reaped and operation refused |
| Final cancellation/coordinator/staged/identity/historical-reader group | 100 passed |
| Actual complete-receipt receiver controls | 7 passed, no skips |
| Matched verifier ABBA | 40 accepted rows, one historical receipt, zero fresh generations |

The 100-control group consists of 22 cancellation controls, 20 coordinator
controls, 32 retained staged-observer controls, four immutable winner-reader
controls and two eleven-control historical reader groups. It is separate from
the actual nested-session operating-system reproduction and repair observation.
Some command groups overlap; their counts must not be added into an independent
sample population or an all-workspace coverage claim.

## Failed observations retained

- Original checkout/fetch and lock-recovery observations remain at their original
  owned locations and are summarized in the recovery receipt.
- Initial native strict Clippy failed with system OpenSSL 3.0.13 at an existing
  optional PQ test API. Isolated pinned 3.5.9 preparation preceded the corrected run.
- The first retained-guest locked build required two explicit existing-package
  dependency edges; it did not silently update dependency versions or checksums.
- Initial backend and async adapter Clippy findings were fixed without weakening
  command flags or test assertions.
- Three original cancellation fixture timeouts from declaration fsync were kept;
  corrected fixture placement used the same deadlines and assertions.
- CI negative tests found a duplicate invocation in another lane; the checker was
  repaired to enforce global uniqueness. The stale current inline pin failure is
  retained and its subsequent source-specific refresh is separate.
- The original equal-five-second nested cleanup failure left an actual backend
  leaf alive. Only the known test-owned PID/birth identity was killed and reaped.
  The explicit outer cleanup budget passed the same actual session-lifetime control.
- The first fixed-backend acquisition wrapper had an overescaped version regex;
  the archive/binary were not downloaded again or repinned. Exact version and hash
  verification have a separate successful receipt.
- The Kaggle CUDA preparation request was rejected before submission. Colab
  binding/release refusals and later missing-runtime observation remain separate.

No failed, canceled, late, unknown, ignored, or unexecuted operation is promoted
to a successful proof, complete resource verdict, Node admission, or payment.
