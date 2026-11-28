# Offline Worker journal audit library

The versioned Linux x86-64 symbol
`trnm_worker_journal_audit_export_v1` exposes the exact
[WQX1 whole-journal program](../../src/worker_agent/journal_audit_export.md)
to a native caller. The [C declaration](worker_journal_audit.h) defines the
borrowed pointer/length pairs and packed return. Existing WJB3-enabled typed
JSONL library names, ABI and native sources are unchanged.

The caller owns the immutable raw snapshot, output and separate scratch until
return. This interface handles only the two previously admitted WQX1 DTO
profiles and up to 64 KiB / 64 candidates; it does not generalize Serde.
The output capacity is at most 1 MiB, and the scratch region must supply at
least 102,400 bytes within the 1 MiB foreign buffer contract. The low return
word gives the WAO1 packet length or the unchanged WQX1 refusal codes if the
high word is zero. A refused buffer request does not publish output.
The interface is not a validator of arbitrary foreign pointer addresses.
Do not attach file, locking, publication or production routing authority to it.

## Build and qualification

With the pinned HIA toolchain and Linux Rust 1.95.0, use preflight and
select a new child directory of a private owned directory outside the repo:

```sh
python3 -B -m hia.platform.worker_journal_audit.build --backend selfhost --output /private/proof/selfhost
python3 -B -m unittest -v hia.tests.test_worker_journal_audit_owned
python3 -B -m hia.tests.test_worker_journal_audit_owned --output /private/proof/actual \
  --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```

Only the pinned selfhost emitter qualifies this named profile: exact object
`.text` before and after renaming, one dynamic export, no imports or needed
libraries. The existing direct profile allows only its trap symbol `abort`,
whereas direct WQX1 also emits `memcpy`, `memmove` and `memset`. It is rejected
before linking a named artifact; its existing non-packaged WQX1 tests are
unchanged. Nothing is bridged through Rust or C.
The Rust test caller is separate from the library. Its ELF has a direct
dependency on the private library beside it, imports only the named Worker
entry from that library, and uses the original entire held byte buffer in
one call. It validates the input and unused tails without reading rows or
materializing any intermediate representation. Test stdin/stdout are private
fixture transport, not library authority or a production Worker command.

The test compares each resulting WAO1 stream to independent complete JSONL,
Markdown and index files emitted by the unchanged, lock-bound original Worker
CLI from the same synthetic journal. Captures also verify exact output and
scratch capacity, a late original-valid excluded record outside the profile,
terminal LF retention, and a 64-candidate input that retains the
last original ordinal. No files, credentials, locks, public indexes or
production dispatch are handed to the native function.
