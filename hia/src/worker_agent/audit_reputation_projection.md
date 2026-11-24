# Worker audit reputation projection
`audit_reputation_projection.hepta` projects the optional ingress
`reputation_delta` into the seven descriptive reputation fields of the
[actual Rust audit export](../../../trillionnium/crates/trnm-worker-agent/src/audit.rs).
This is separate from Markdown cell formatting and from the market
reputation model. It does not change any Worker reputation, rank a market
participant, or authorize a Worker operation.

The [active Worker mapping](../../../trillionnium/crates/trnm-worker-agent/src/main.rs)
recognizes exactly `3, -1, -2, -3`. Other `i32` values and missing input
project all seven fields to null. Tiers are `3, 2, 1, 0`; ranks are
`0, 1, 2, 3`, respectively. Weight is `tier * 10000 / 3`; signed score
is `delta * 10000 / 3` with Rust's truncation toward zero; gap is
`10000 - score`. The native score divides the nonnegative magnitude and
applies the sign afterward; it never negates an unrestricted `i32`.

## Private WJR1 entry

`f0(input: readbuf, output: mutbuf, scratch: mutbuf) -> u32` accepts disjoint
borrowed buffers. Input is exactly nine bytes: ASCII `WJR1`, a presence
byte (`0` or `1`), and a four-byte little-endian signed delta. An absent
value must have a zero payload.

On success without projection, the output is one zero byte. A recognized
input produces a prefix containing these fields in order:

| Offset | Field |
| --- | --- |
| 0 | One-byte non-null tag, always 1 |
| 1 | Delta, little-endian i32 |
| 5 | Tier, u8 |
| 6 | Weight, little-endian u16 |
| 8 | Score, little-endian i32 |
| 12 | Rank, u8 |
| 13 | Gap, little-endian i32 |
| 17 | One-byte label length |
| 18 | Exact original ASCII label, no padding |

Success returns the byte count; a non-null result is at most 41 bytes.
The rest of the output and all scratch stay unchanged.
`0xffffffff` means invalid framing; `0xfffffffe` means insufficient
capacity. Neither refusal writes any output.

## Exact original comparison

After project preflight, pinned HIA bootstrap, and populating the exact
Rust/Cargo 1.95.0 workspace registry cache:

```sh
python3 -B -m unittest -v hia.tests.test_worker_audit_reputation_projection
python3 -B -m hia.tests.test_worker_audit_reputation_projection --output /absolute/private/observation
```

The standalone observation uses a locked build of the unchanged original
Worker and invokes its actual `export-audit` command on a benign local
journal. Each emitter compares seven projected fields against the
original output, then rebuilds each complete JSONL row through WJL using
the native reputation fields and the remaining, untouched original
fields. Cases include the four recognized deltas, missing and explicit
null, present zero, both signed limits and deterministic in-domain
samples outside the four recognized values. Rust retains journal IO,
all other record normalization, index creation and production dispatch.

The WJB2 batch imports the same internal `wr_values` classifier and
arithmetic. WJR1's independent input frame and encoded output are unchanged.
The internal metadata word holds label length (bits 0–4), tier (5–6),
rank (7–8), and weight (9 and above); score and gap are separate results.
This keeps each internal call within the pinned selfhost's three-result
limit. No metadata encoding is part of the external WJR1 or WJB2 frame.
