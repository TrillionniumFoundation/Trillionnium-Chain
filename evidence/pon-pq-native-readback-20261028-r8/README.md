# Native PQ readback and actual post-intent counterexample

The new exact regression **fails on unchanged production code**: five declared
signed socket calls were all attempted and observed; all three honest followups
failed. A real ML-DSA signed `PQ_NETWORK_DEADLINE` result was retained after the
original ten-second deadline, but the genuine durable reorg intent remained
`done=0`. Its original operation was terminal in the durable PQ ledger. Subsequent
valid peers were refused before new operations could begin. Cold reopen succeeded
but did not preserve the observed live State/ledger comparison.

The [readback](readback.json) binds this observation to exact clean commit
`6762be6ba` (the full commit is retained there), the raw source before/after
maps, every original packet/request/available response, all five call results,
full live State and SQL snapshots, actual owner-fence probes and the cold readback.
The exact test selected one case and reported zero passed, one failed and zero
ignored. Twelve desired recovery checks failed. This is a runtime counterexample
for the specified scheduling cut, not a signature forgery or a physical-kill test.

The test uses the actual serial loopback PQ production listener, real native
ML-DSA keys and complete W1/M06. Its existing test-only pause occurs after the
durable intent and waits for the original real deadline; it injects no error
code. The first operation's recorded status, exact identity and independently
verified retained signature establish completion; a client timeout is not used
as proof that the handler finished. The scope covers peer operation sequences.
It does not add a new account-migration, paid-CPU, public-network or WAN result.

## Earlier passing results keep their own scope

The original eleven Node/M06 PQ tests passed on clean `e7ab8cce`: real QTX1,
complete W1, account nonces, forks/reorgs, cold replay and loopback distribution.
They took 239.241452 seconds including compilation and 2.55 seconds in the test
harness. The later exact source `e3afbbf4` passed full locked all-features Cargo
metadata, formatting, and strict full-workspace/all-targets/all-features Clippy.
Neither result covered the subsequently added post-intent timing case. The
counterexample therefore remains a blocker despite those passing results.

## Failures and costs remain complete

The [raw archive](raw-native-records.zip) preserves the first Node precheck
refusal, the second Node disk-floor termination, the third Node success, source
gates, both new regression attempts, runners and the settled process-tree guard.
The new regression's first attempt failed test macro compilation in 1.591871
seconds with 1.322636 child CPU seconds, and never ran the case. The corrected
test then built and ran: 433.211385 seconds including build, 424.179358 settled
child CPU seconds, sampled peak RSS 2,613,161,984 bytes, and sampled target growth
471,113,728 bytes. The latter guard had no errors or surviving owned processes.
Its CPU/RSS/disk thresholds are sampled stop controls, not kernel hard limits.

The earlier Node disk-floor attempt used direct-child wait4 and cannot establish
complete CPU settlement for its interrupted descendants. That limitation and
the unknown origin of reappeared raw archive files are retained explicitly.
The actual successful Node binary and failed regression binary were fully
preserved in lossless gzip archives, with decompressed size/SHA equality checked
before redundant loose executable removal; their receipts are included. Large
binary payloads are kept in the coordinator's separate raw evidence archive.

The [manifest](manifest.json) binds every exact raw member and the complete ZIP.
Independent inherited-PQ source review and the local-only repair proposal are
inside the same ZIP. This packet reports the baseline, not a passing repair;
future repair results must be bound separately to their actual source.
