# R1 queue and fresh-service failure evidence

The original queue diagnosis is tied to the dated ready002/003 observations. R1 and old N2 use byte-identical required workflows with the same PR concurrency group and cancel-in-progress false. Old N2 still had four Rust shards. The independent ready004 records later show R1 queued with 18 jobs and old N2 cancelled/completed; this review did not perform the cancellation or repoll the queue.

Both current R1 W1 fresh-service artifacts are complete official downloads with API size/digest and original upload-log digest agreement. Every one of the 57 members in each ZIP was read to EOF, CRC and SHA256 verified. Source-before and source-after bytes agree. The prospective commit has the exact R1 tree. The inner verifier's kind=head describes its checked-out commit; the outer source records preserve the prospective-merge relationship.

The two original Rust controls each report one test passed, while their retained business reports say finite_target_met=false and the reader returns CONFIRMATION_TARGET. The two fresh controls fail at fresh_challenge.rs:244:5 with the original four-second/six-depth assertion and native exit101; the runner reports FRESH_NATIVE_TEST_FAILED. All four last-replay diagnostics retain PUBLIC_REQUEST_DEADLINE. The four-second/16-worker parameters and original Host limits are unchanged. Build/source/Host controller checks do not explain away this measured business failure.

These two W1 jobs are separate from the required protocol five-control lane. This record neither adds a new merge-policy requirement nor grants performance/production qualification. It does show a concrete current-source failure deserving diagnosis. The P1 immutable prefix cache is present; no quantified benefit or successful four-second remedy follows from that fact.

Large reports, SQLite files and the compiled binary are retained once inside the two complete ZIPs; no artifact executable was run. Selected bounded logs/JSON are extracted verbatim. Initial log-network failures, temporary PTY lost observation and the same-session natural exit0 are preserved.

No source, workflow, limits, PR, protection, Git refs, or frozen stage were changed.
