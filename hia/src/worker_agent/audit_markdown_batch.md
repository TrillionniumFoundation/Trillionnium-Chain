# Active Worker audit Markdown batch

`audit_markdown_batch.hepta` renders the complete 18-column Markdown export
of already-selected, typed [Worker audit rows](audit_jsonl_row.md). It owns
the active header and divider, cell separators, UTF-8 text escaping,
numeric output and row endings. It preserves supplied order and duplicate
rows, including empty-present text versus missing text. This is separate
from the retained historical 11-column WAR1 and from the named JSONL
library; their entry points and semantics are unchanged.

## Private WMA1 ABI

`f0(input: readbuf, output: mutbuf, scratch: mutbuf) -> u32` uses disjoint
borrowed buffers. Input bytes must remain immutable during the call;
scratch is unused. Supply:

- ASCII `WMA1` and a little-endian `u32` count of 0 to 100,000 typed rows.
- In supplied order, a little-endian `u32` byte length followed by the
  complete standard [WJL1 row](audit_jsonl_row.md), with all its ordinary
  presence, width, UTF-8 and exact extent constraints. No trailing bytes.

Input and successful reported lengths must fit `0xfffffffd`. The direct
borrowed-buffer artifact independently has its existing 1 MiB extent
limit. The first pass reuses the admitted WJL validator with writes
disabled and measures all rows. Only when every row and capacity check
pass does the native function write the 446-byte active header and emit
rows in a second pass. No buffer allocation, path or IO is needed. A late
refusal never leaves a header or prefix. Output's unwritten tail and
scratch remain unchanged. `0xffffffff` means a malformed frame or invalid
typed value; `0xfffffffe` means insufficient capacity or a length outside
the private ABI.

Missing option cells render `-`; present empty text stays empty. A pipe
is prefixed with a backslash, each CR or LF becomes one space, and other
UTF-8 bytes are preserved. Numeric columns use original decimal widths
and signedness. An empty batch emits the ordinary header and divider,
not an empty stream.

## Independent original comparison

```sh
python3 -B -m unittest -v hia.tests.test_worker_audit_markdown_batch
python3 -B -m hia.tests.test_worker_audit_markdown_batch --output /private/new-proof \
  --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```

The observation first binds the actual pinned Rust CLI executable to the
six tracked original source/lock identities. For each synthetic journal,
the original binary is invoked independently for `.jsonl` and `.md`.
Its JSONL is only the ordered source of typed values; it is never used to
build expected Markdown. Each real HIA backend makes one complete output
call and must equal the original `.md` file byte for byte. Typed controls
add blank versus absent cells, signed and unsigned limits, exact/short
capacity, and a malformed final row after a valid prefix.

This is a dry typed formatter. It neither normalizes yet-unported
optional fields nor reads journals, selects records, owns identity or
authorization, writes output/index files, or changes production dispatch.
