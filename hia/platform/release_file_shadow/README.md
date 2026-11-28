# M15 retained-descriptor streaming shadow

A single-use qualification owner takes an already selected synthetic Unix file
descriptor. It duplicates the descriptor once and privately closes that
duplicate on success, refusal, or error. It does not take a pathname, reopen a
file, reset the offset, or identify a directory root. Duplication keeps the
same open-file-description offset; the caller must keep exclusive use during
the call. A read-only FD, regular file, appropriate raw length, and initial
offset zero are required. The original descriptor remains caller-owned.

The typed release candidate and returned observation are frozen. The
[descriptor guard](../../src/release_bundle/FILE_DESCRIPTOR.md) runs on actual
host fstat/offset observations, and the read reservation is charged before
the first read. The shared stream implementation feeds actual bounded bytes
to the original RAC1/CCH1, raw SHA-256, and strong SHA-512 HIA entries. It reads
one extra byte to verify EOF, compares the legacy locator, then makes a final
descriptor comparison. The final strongly bound claim can leave the owner
only after all those stages and with no caller-supplied success flags.

This test path caps release fixtures at 64 KiB, requests at 16 per observation,
and each request at 8192 bytes. Its cooperative time allowance can discard an
elapsed result but cannot interrupt a blocked kernel read. The existing
content ledger retains original sticky reservation semantics. Limit,
read/EOF, locator and post-descriptor failures never return a partial claim,
and consuming the owner instance cannot reset the budget or restart the file.
Host read, seek, close and fstat run in Python, not HIA; native code executes
the descriptor predicate and cryptography. Python's OS-level signal retry
rules are not claimed to match original raw Rust interrupt semantics.

The [held-file suite](../../tests/test_release_file_descriptor.py) compares
both pinned HIA emitters against the unchanged Rust observer body on separate
fresh disposable descriptors. The [generic transcript suite](../../tests/test_release_transcript_composition.py)
uses the same streaming implementation but injects reader faults only through
its explicit test fixture. A separately marked boundary double checks that a mismatched post-read record
discards a complete candidate; it is not a real filesystem-race observation.
Neither path claims production custody, an
immutable snapshot against another writer, fresh path identity, release
authorization, production ABI, or a pure HIA OS owner.
