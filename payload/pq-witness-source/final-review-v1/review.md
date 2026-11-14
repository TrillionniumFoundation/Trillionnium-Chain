# R1 PQ TLS witness refusal: closed static review

The original selected-binary control failed before TLS handshake, while charging the durable ingress owner. The server reported PQ_WITNESS_DEADLINE after 261,315 microseconds; the client then saw TLS I/O connection reset. The child remained alive until panic cleanup killed the owned process. These are three distinct events.

The complete original log is pinned in summary.json. It contains one pre-step source identity for R1 2a86462a1ab20c68151719ba4635e3c294391e64, tree 5c26776f96f15fd131e85a5c2d7c5e895ad7fab4; a second post-step identity was not found. Captured implementation bytes came from that immutable commit. The failure artifact is referenced, not downloaded by this review.

## What the source establishes

PqTlsServer::connection calls durable charge_connection before channel acceptance. Its transaction first verifies the witness Current checkpoint and local protected root. An actual ingress counter change then requires a new root and authenticated AdvanceCas. Each witness request independently clamps the original deadline to a new 250 ms maximum exchange. Current must still be live on final return; authenticated committed CAS has deliberately different receipt-retention semantics so the local database can reconcile an already durable remote change.

The TLS diagnostic deadline_elapsed=false is about the outer connection deadline. Its zero ingress_charge_calls counts only TLS BIO charge callbacks. Neither proves that the inner witness exchange remained live, that no outer durable charge began, or that a CAS did not commit.

The failure is at the third child's replay after reopening. The listener is bound before the witness owner starts; database opening validates the witness before READY. Earlier children are joined, and temporary Current clients drop their streams. Reading these paths did not establish a readiness or leftover-connection defect. The test has an empty request-stage vector; inner witness instrumentation is confined to cfg(test), so this selected CLI does not reveal the expired subphase.

One successful witness exchange performs two signatures and four canonical verifications. The key objects already retain their signing key and verifier. Removing a self-check, reusing trust, dropping a fresh root or Current check, or loosening the 250 ms cap would change the current contract. Existing cancellation, rollback, late-Current, and committed-CAS controls are retained.

## Remaining causal gap

The original refusal cannot distinguish Current from CAS, signing from scheduling/I/O or SQLite work, or pre-send expiry from post-response freshness rejection. No sufficiently supported implementation fix emerged. This does not establish that the failure is benign or that CPU alone caused it.

No test, benchmark, observer patch, provider installation, environment change, source edit, remote write, or stage write was performed. Root requested closure without repeating the original selector in the absence of a discriminating hypothesis. The hosted failure remains open.

All small reports and exact source captures are indexed. Capturing a file is not a claim to have proved every body in it. The first locator extraction's cap failure is preserved with its actual terminal; successful bounded excerpts are derived locators, not substitutes for the original complete log.
