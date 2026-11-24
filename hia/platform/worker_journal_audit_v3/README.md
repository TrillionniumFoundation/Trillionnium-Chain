# Private file interoperability for the WQX3 audit candidate

The Linux x86-64 named selfhost library has one exported memory-only symbol,
`trnm_worker_journal_audit_export_v3`. It has no undefined imports or dynamic
dependencies. It preserves the pinned emitted .text through symbol binding and
linking, with no C, Rust or Python supplying native audit semantics. The
[header](worker_journal_audit_v3.h) preserves [WQX3](../../src/worker_agent/journal_audit_export_v3.md)
input, output and scratch caps. The WQX1 named library is unchanged. The
existing direct bare WQX3 qualification remains separate; this builder supports
only the strictly import-free selfhost profile.

The **test-only Rust process** uses these exact fixed names in its freshly
owned disposable directory, with no path arguments:

- input: `ingress.jsonl`
- output: `audit.jsonl`, `audit.md`, `audit.jsonl.index.json`

It reads one bounded regular local file, checks EOF and extent, passes the
whole immutable slice into one native call, and splits the returned WAO1
packet by lengths only. It checks all output paths for existing names
before any write and creates only new private regular files, never replacing
or deleting an earlier output. A malformed or over-cap snapshot and an
already-existing third name leave the fixture unchanged. A fail-stop after
some later file writes may leave a prefix: there is **no** atomic multi-file
publication or general path/snapshot safety guarantee. The private driver
does not implement the original journal locking or write contract.

The checked fixture invokes the genuine unchanged, lock-bound Worker CLI:
both original export modes give byte oracles for all three files; the
original `query-audit --task-id` independently reads the native candidate's
on-disk JSONL and sidecar and emits the exact same hit ordinals and stdout.
Markdown has byte parity only, not query support. This verifies physical
private-file interoperability and actual Rust readback, not native syscall
ownership, production journal or audit custody, path handoff authorization,
or application cutover.

```sh
python3 -B -m hia.platform.worker_journal_audit_v3.build --output /private/new-build
python3 -B -m unittest -v hia.tests.test_worker_journal_audit_owned_files
python3 -B -m hia.tests.test_worker_journal_audit_owned_files --output /private/new-proof \
  --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```

Use the project preflight and pinned HIA/Rust 1.95.0 environment. These
commands work only with source-bound artifacts and disposable synthetic
fixtures; they are not install instructions.
