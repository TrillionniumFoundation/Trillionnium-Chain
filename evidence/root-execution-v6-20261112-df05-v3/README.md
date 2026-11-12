# Root V6 native execution evidence — HOLD

Tested native source: 87943f6229d8785c3f431ede5eadba62b634ab8c

Source tree: 5d2538f404e32319ea1084a6c79f37c52503546f

The prior tested source 92934b64f80ee9b20bcc070a08ca0966b7c5741d has tree b1882c2e46827abfd1db5f8744be043d5776df6d; its executions retain that earlier identity.

The evidence commit is an archival child. It is not a new test execution.

[Native summary](native/SUMMARY.json), [command receipts](native/commands.json), [ordered original-byte and chunk manifest](PUBLICATION_PACKAGE.json), [copied-Lease supplementary receipt](supplemental/FINISHED.json).

All native command failures, timeouts and incomplete results remain visible. Formatting, Python controls and source checks do not substitute for native tests.

The supplementary complete socket_ownership target uses a new 1200-second outer bound. Its three original tests and internal bounds are unchanged. A timeout is a failed execution.

Prior retained native failures and selected reconstruction receipts are in prior/root-prior-evidence-selected-v2.tar.gz. That historical archive is explicitly incomplete: original cloud logs remain missing.

The failed validation-v1 invocation, original driver and FAILED marker are retained under prior/validation-v1-failed. That attempt stopped while awaiting source and executed no Rust tests.

The complete manifest-bound validation-v2 originals and the old publisher's actual refusal are under prior/validation-v2-rejected. Its V4 provider timeout receipt recorded 1712 bytes, while the final log had 1798 bytes; the original receipt and the final log remain unchanged, including the originally hashed prefix. That failed run is historical evidence, not a qualification of this new source.

Selected original source-preparation records, the earlier space-gate refusal, and the exact late-write prefix check are retained under source-preparation. The handoff excludes opaque runtime metadata, private input bodies and environment dumps; it makes no native test qualification claim.

ARM, prospective-merge validation, the original three 30-second campaigns, distributed witness independence, actual external effects and production activation remain unqualified.
