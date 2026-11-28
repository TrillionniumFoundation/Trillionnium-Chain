# WQS2: sealed Worker task query with original line geometry

`sealed-worker-task-query-lines.elf` is a separate, uninstalled static
Linux x86-64 selfhost candidate. The original
[WQS1 fixture](../worker_audit_sealed_query/README.md) remains exactly
as-is. WQS2 is the new artifact name and profile, not a new wire magic:
the original `WQS1` request header and stdout ABI are retained.

The candidate reads only the parent's private sealed fd 0 and writes
only to its anonymous pipe on fd 1. It reuses byte-identical adapter
instructions, capacity checks and lifetime mapping. The total physical
pair and composed typed request remain at most 65,536 bytes, with
the same 102,400-byte scratch / 1 MiB stdout allocation and 64 rows.
It still requires exact EOF and the old seal, descriptor and cursor
checks. There is no native filename handling or directory, storage,
network, identity, credential, policy or production authority.

The existing WID1/WTQ2 raw kernel texts are unchanged. The row slot
calls strict [WER2](../../src/worker_agent/audit_export_row_lines_v2.md)
at the old entry address. WER2 differs only in UTF-8 logical line
geometry of the compact row profile: LF, CRLF, wholly Unicode-blank
spans and a final span without LF. No generic Serde or whitespace
rewriting of nonblank JSON objects is accepted.

## Build and evidence

The tracked HIA emitter is an exact projection of four WQS1 functions.
It updates three source-side length invariants, two RX segment length
fields and two relative call operands for the later strict WID1/WTQ2
texts. The runtime anonymous map, entrypoint, memory rights, original
adapter and all other thunk instructions are unchanged. The builder
first rebuilds and verifies the exact old WQS1 ELF, then independently
verifies the full byte prefix of the new HIA-emitted artifact against
only the known layout changes and the three pinned native text regions.
No post-emission patching, compiler fallback, new linker path or
runtime relocation is used. Only the pinned selfhost objects with a
single resolved `f0` and no imports or relocations are accepted; this
does not qualify the direct backend for a named executable.

Qualification compares full original `query-audit --task-id` stdout
from the unchanged locked Rust CLI to native output. Only line
separators and blank spans of genuine benign export rows are changed
in private test copies; the independently exported sidecars are
untouched and host code does not parse them into typed inputs. These
physical controls include the 64th compact ordinal, an exact combined
65,536-byte input with genuine sidecar and rows, no read on one extra
byte, bad seal/cursor/sink, late malformed rows, and index/row mismatch.
The checks compare no-output refusal, not pipe-transport atomicity after
a sink failure. Runtime EINTR and independent syscall tracing are not
claimed.

```sh
python3 -B -m hia.platform.worker_audit_sealed_query_lines.build --output NEW_PRIVATE_CHILD
python3 -B -m hia.tests.test_worker_audit_sealed_query_lines \
  --output NEW_PRIVATE_PROOF --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```
