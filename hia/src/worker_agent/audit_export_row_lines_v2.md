# WER2: bounded logical lines for canonical Worker query rows

The original Worker `query-audit --task-id` reads a UTF-8 JSONL audit
export, iterates Rust `str::lines()`, skips spans with empty
`str::trim()`, then deserializes each retained span. Unlike the original
journal reader, the audit artifact reader does not require a terminal LF.

WER2 consumes already-held bytes and extends only the physical line
admission of [WER1](audit_export_row_decode.md). It validates whole-input
UTF-8, recognizes LF and CRLF (removing exactly one CR before LF), accepts
an unterminated final span, and skips wholly blank spans using the same
Rust whitespace helper as [WJF1](journal_line_frame.md). It does not
Unicode-trim nonblank spans. Every retained span must exactly equal one
of the same generated compact 18-field objects, without extra edge or
interior whitespace. An extra CR on a retained span is not ignored,
even though original Serde accepts some noncanonical JSON whitespace.
Canonical escapes, null authority fields, and the audit-only reputation
shape and ranges remain unchanged. Unicode line and paragraph separators
are not LF delimiters.

The same 65,536 raw-byte bound, 64 nonblank-row limit, 102,400 scratch
extent and unchanged WAT1/WJL1 output are enforced. The line iterator
checks each load against the raw extent, advances to the next byte after
LF or to exact EOF, and never copies or rewrites raw data. Native field
validation is complete before any publication. A previous good row does
not publish if a later nonblank span fails. The exact WER1 entrypoint
and published WQS1 named fixture remain unchanged.

Qualification independently runs the unchanged, source-and-lock-bound
Rust binary to export canonical JSONL plus its sidecar. Test-only
fixtures change record separators, insert wholly whitespace lines or
remove the final LF, without parsing/changing the JSON objects. Both
pinned HIA emitters receive the resulting raw bytes unchanged and
produce the same WAT1 as WER1 using canonical data. Native WID1 decodes
the unchanged original sidecar and unchanged WTQ2 emits exactly the
original CLI's full query stdout for the transformed files, including
the 64th compact ordinal. Only the existing native frame envelopes are
transported by the host. Rebuilding the pinned original selfhost WQS1
checks the old strict image, including its guards and adapter.

```sh
python3 -B -m hia.tests.test_worker_audit_export_row_lines_v2 \
  --output /private/new-proof --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```

This is not generic Serde compatibility, a new named artifact,
filesystem custody, security-policy lookup, state modification or
production dispatch.
