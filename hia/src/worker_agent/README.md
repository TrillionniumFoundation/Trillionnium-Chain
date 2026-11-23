# Worker Agent: audit Markdown

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

## Retained 11-column report

`audit_report.hepta` emits the retained 11-column report from the admitted record slice,
including the complete heading and separator even for zero records. Table
fields, order, spaces, final newlines, decimal `u64` task IDs and Unicode match
the original renderer. The cell and report implementations share the character
mapping for CR and LF.

This private fixture ABI uses the same three borrowed buffers and returns as
the cell ABI. Buffer 0 begins with ASCII `WAR1` and then zero or more records,
with no count or padding. Each record has a little-endian `u64` task ID
followed by ten length-prefixed cells in this order:

1. request ID
2. status
3. provider request ID
4. provenance schema version
5. provenance fingerprint
6. provider
7. model
8. adapter
9. agent protocol
10. compliance profile

Each cell starts with a little-endian `u32` byte length, followed immediately
by that many UTF-8 bytes; `0xffffffff` indicates absence with no payload.
Only the eight optional cells allow absence. Empty present fields are
distinct from absent fields. UTF-8 validity remains a caller contract.
The input frame must be at most 1 MiB. An output is at most
`244 + 2 * (input_bytes - 4)` bytes (2,097,388 bytes at the limit): the
header is 244 bytes, ≤63 report bytes per row are not supplied by cell
payloads, each row spends at least 48 wire bytes on framing, and escaping can
at most double cell payload bytes. The first pass validates the entire
frame and measures the exact output extent; the second writes only after all
framing and capacity checks pass. This keeps output and scratch unchanged even
when a malformed later record follows valid rows. Input and output must be
separate borrowed regions, as in the standard native invocation harness.
The current foreign-call qualification profile admits at most 1 MiB per
buffer. An otherwise valid frame whose report exceeds that output extent
returns insufficient capacity without publishing a partial report through
this profile. A CLI cutover must support these reports explicitly rather than
truncate them, weaken the bound, or silently fall back to Rust.
The pinned compiler requires the external borrowed entry name `f0`; it is
only a wrapper over `wa_audit_report`. The committed `.hepta` source is
compiled directly; no generator is part of the build.

```sh
python3 -B -m unittest -v hia.tests.test_worker_audit_report hia.tests.test_worker_audit_text
```

The differential tests use the unchanged retained Rust rendering module with
the pinned Rust compiler. The Rust fixture constructs typed records and adds
only framing, not formatting. Initial development Core rejected unsupported
`int.shl.wrap`; the final code uses the supported checked shift for bounded
byte positions.

The reports do not perform record selection, audit validation, authorization,
CLI dispatch, file/JSON handling or production publication. No fallback,
runtime integration or old-path retirement is implied.

The active [Worker Markdown CLI renderer](../../../trillionnium/crates/trnm-worker-agent/src/audit.rs)
has 18 columns: the original 11 plus reputation label, delta, tier, weight,
score, rank and gap. The [active scope test](../../tests/test_worker_audit_active_scope.py)
compiles the exact active rendering functions and the typed record body,
checking missing values and signed/unsigned decimal extremes. The 18-column
format and unbounded report materialization are separate cutover
requirements. Neither is covered by the WAR1 differential.

The [active composition test](../../tests/test_worker_audit_active_composition.py)
separately assembles the native table tokens, streaming text cell fragments
and six numeric reputation columns. Both machine-code backends match the
active Rust renderer byte-for-byte for missing and populated reputation,
and for a report over 2 MiB with a single cell crossing the borrowed-buffer
boundary. The fixture orders typed fields and joins returned prefixes; all
output bytes come from HIA. Production record selection, the assembler
caller, filesystem ordering and the CLI path remain unchanged and unqualified.

The [active table tokens](audit_active_table_tokens.md) provide the exact
18-column header and divider plus row delimiters and unsigned decimal task
IDs. This bounded building block does not take ownership of row composition,
output files, CLI dispatch or the Rust package.
