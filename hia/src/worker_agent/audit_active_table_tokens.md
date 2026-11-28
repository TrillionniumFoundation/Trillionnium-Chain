# Worker active audit Markdown table tokens

The [HIA kernel](audit_active_table_tokens.hepta) emits bounded structural
tokens for the active 18-column Markdown format from the
[Worker Rust owner](../../../trillionnium/crates/trnm-worker-agent/src/audit.rs).
It is separate from the retained 11-column WAR1 profile and the
[active cell fragment](audit_cell_fragment.hepta) used for escaping.

The private ABI is `f0(readbuf, mutbuf, mutbuf) -> u32`. The buffers are
distinct caller-owned regions. Buffer 0 receives exactly one of these frames:

| Tag | Payload | Buffer 1 prefix |
| --- | --- | --- |
| 0 | none | All 18 labels and the 18-cell divider, including both LFs (446 bytes) |
| 1 | none | Row opener, pipe then space (2 bytes) |
| 2 | none | Cell separator, space-pipe-space (3 bytes) |
| 3 | none | Row terminator, space-pipe-LF (3 bytes) |
| 4 | exactly eight little-endian bytes | Unsigned decimal task ID (1 to 20 bytes) |

Return values are prefix length, `0xffffffff` for malformed framing,
or `0xfffffffe` for insufficient output capacity. Framing and needed
capacity are determined before the first write. Neither refusal changes
the output; success leaves the unused suffix unchanged. Scratch is never
written. The caller owns row order, separators, cell contents and report size.

After project preflight and exact compiler setup, run the
[focused differential](../../tests/test_worker_audit_active_table_tokens.py):

```sh
python3 -B -m unittest -v hia.tests.test_worker_audit_active_table_tokens
```

The pinned Rust oracle compiles the active `audit.rs` record, escaping and
renderer bodies and compares emitted bytes from an empty and populated report
against both machine-code HIA backends. Tests also cover widths across the
unsigned range, exact 18-column count and delimiter count, malformed frames,
undersized output, preserved tails and scratch. The narrow component does not
claim 18-column row or whole report integration, CLI or file/index ownership,
production dispatch, parity for other profiles or Rust retirement.
