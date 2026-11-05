# PQ native source reconstruction, 2026-10-27

This is a new candidate based on `c584028b1622fb9b5f5ee0581d097f3e527909c8`,
whose upstream source is `ac469237422d43805845e8b9a6839ad14e1028e7`. It does not
recreate or claim the missing historical Git objects or the original lost
checker, test, contract, CLI source or logs.

## Recovered source inputs

The surviving native test executable has SHA-256
`d86b3d685d9ccddf7cecaa305a2c2f15bd494fc95770fe3d7796c545bf453a79`.
Its two identical embedded source tables contain 1,032 native/config inputs,
14,264,449 bytes. They are two tables in one build, not independent witnesses.
Exactly 1,013 inputs match the upstream source; the other 19 form the recovered
patch with SHA-256
`b020b340d400a9f175c2e58b1e79db05d8e02b4a3fbf72eaf96c02c2c9a7dcfa`.
The patch applied cleanly to the present base. These bytes include the native
PQ network/store owner, legacy listener guards, real ML-DSA tests and CLI canary.

Three changed pinned files were absent from the executable and required new
reconstruction: the integration checker, its tests and the network owner
contract. **Correction on 2026-10-28:** the previous statement that CLI `main.rs`
was outside the embedded inventory was wrong. The baseline `main.rs` is present
at ELF offset 10,704,803, length 124,046, with Git blob
`13eaca34f2fe3b46b25d387836f978a38168e40f`. It matches the baseline source exactly.
Only the newer surviving CLI's changed `main.rs` bytes remain unrecovered.
The [independent byte extraction receipt](../pon-pq-account-native-20261028/main-source-provenance-correction.json)
records the executable, span and content hashes, as well as both old report
hashes. New CLI repair source is new work, never a fabricated historical recovery.

## Previous surviving executable observations

A fresh invocation of the surviving executable in the previous session passed
six PQ network tests and one CLI canary. Those are executable observations, not
compilation or full exact-source acceptance of this new candidate. They cannot
qualify its reconstruction. The native implementation exercised real TCP, actual
Node submit and W1, lost ACK, re-signing one logical operation, cold cached
responses, context/nonce conflict and downgrade refusal, real reorg-preserved
revocation and expiry retirement.

The large-request budget observation was 13 completed invalid packets charging
13,724,854 bytes. The next same large request class plus worst-case 2 MiB response
reservation exceeded 16,777,216 bytes; the refusal survived reopening. It did not
show smaller requests could not fit, CPU exhaustion or an honest-service SLA.

## Fresh exact-source validation

Rust 1.95.0 and OpenSSL 3.5.9 compiled the reconstructed source successfully.
The initial network-isolated invocation recorded four passing tests and two
`TcpListener::bind` failures with `EPERM`; the original failure and compiler log
are retained in `native-initial.*`. A reviewed invocation of the identical
executable with disposable loopback listeners passed all **six tests**, zero
failed/ignored, in 2.5067 seconds. Before that invocation, every entry in the
recorded native source manifest was rehashed and matched.

The new executable is 313,347,528 bytes, SHA-256
`528c76dcbf1cf2e5823345641a762f0f9fd8ab3dad27bf873821dc4b9a810662`.
The native source manifest has SHA-256
`41ecb6b2ea8094c02a5ba9473b80663ae6aa8ef313ecf8f0920bc8e306fa7381`.
`native-loopback.record.json` binds exact arguments, source and executable
hashes, UTC times, elapsed time and both output-stream hashes. This is a new
source build, separate from the recovered historical executable above.

The reconstructed source checker verifies **133 blobs** and keeps whole-chain
activation false. Its **24** tests include missing/native source pins, nested
Node PQ source, changed flags and version/size types, missing reports, traversal
and symlink controls. Project preflight and complete workspace formatting also
pass. Their fresh logs and exact arguments are retained under `source-gates`.

The fresh CLI canary and full exact-candidate Clippy are **NOT RUN** at this
checkpoint. Source continuation must record their actual outcomes before making
any such claim. No original failure is overwritten by a successful retry.

This candidate is default-off, loopback-only native transport authorization.
PNX1 account/task/install owners remain classical and are not certified by
transport signatures. No CodeQL alert is dismissed, no production activation is
enabled and no independent WAN or physical antirollback claim is made.
