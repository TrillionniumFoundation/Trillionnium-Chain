# Worker Agent: audit Markdown cell text

`audit_text.hepta` implements the cell-text formatter from
`trillionnium/crates/trnm-worker-agent/src/audit_render.rs`. Missing values
produce `-`; present empty text is empty. Each carriage return and line feed
becomes a space (CRLF becomes two spaces). Each pipe gains a preceding backslash.
All other bytes, including existing backslashes and UTF-8, are preserved.

The private, three-buffer self-host ABI receives a tagged value in buffer 0:
`00` alone for absent or `01 || UTF-8` for present. UTF-8 validity is a
caller contract matching the original `Option<&str>` boundary; the kernel
does not decode or validate text. Buffer 1 receives the result prefix, with
its tail untouched; buffer 2 is unused and stays untouched. A successful
return is the length in bytes. `0xffffffff` denotes invalid framing and
`0xfffffffe` insufficient capacity or unrepresentable length. Either refusal
leaves the entire output unchanged. Counting before emission preserves that
property even when many pipes expand.

After the repository preflight and pinned compiler bootstrap, run:

```sh
python3 -B -m unittest -v hia.tests.test_worker_audit_text
```

The differential test uses the unchanged original Rust source and pinned Rust
version. The stand-alone harness supplies fixtures only. This candidate does
not replace the actual CLI path, the entire table renderer, file/JSON handling,
or any audit, authorization or trust decision. No fallback, production use,
or old-path retirement is implied.
