# Worker audit Markdown cell fragments

The [fragment kernel](audit_cell_fragment.hepta) emits bounded pieces of a
single cell whose original `Option<&str>` can be larger than the compiler's
1 MiB borrowed-buffer limit. The private `f0(readbuf, mutbuf, mutbuf) -> u32`
input starts with one tag: 0 for absent (no payload), 1 for the first piece of
a present cell (possibly empty), or 2 for a nonempty continuation. The caller
owns sequence and lifetime, passes each valid string's raw bytes exactly once
and in order, and concatenates output byte prefixes. The kernel does not
track sequence state or validate standalone fragments as UTF-8. A split within
a code point is valid because only ASCII CR, LF and pipe are transformed.
An absent cell yields a single dash, never a continuation.

A packet carries at most 524,288 payload bytes. Each input byte emits at most
two bytes, so the 1 MiB output capacity is sufficient even when the entire
payload is pipes. There is no aggregate accumulator or whole-cell size field.
The two-pass kernel returns a byte length or `0xffffffff` for invalid framing
or `0xfffffffe` for insufficient output capacity. It never writes on refusal
and leaves any unused output suffix and all scratch unchanged. Buffers are
distinct caller-owned regions.

[Tests](../../tests/test_worker_audit_cell_fragment.py) compare machine
code to the unmodified cell helper extracted from the active Rust
[`audit.rs`](../../../trillionnium/crates/trnm-worker-agent/src/audit.rs),
including cuts inside multibyte UTF-8 and between CR and LF, exact capacity,
and single cells several times larger than the ABI limit. This ports only
cell escaping. It does not implement the active 18-column table, the CLI
caller, file/index publication, or a production dispatch change.

The initial Core admission rejected a duplicated SSA value name
(`E_HIA_SSA`, no machine code executed). The final source distinguishes the
packet extent from the one-byte tag size.
