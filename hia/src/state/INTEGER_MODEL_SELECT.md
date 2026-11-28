# Offline integer-model row selection

This pure M06 diagnostic reads the original private `state.export` bytes of
an immutable [Execution State](../../platform/execution_state/README.md)
snapshot. The unchanged owner supports the existing public operations only.
A caller captures one full export of its bounded synthetic State. HIA reads
the same unmodified export bytes, derives both exact ASCII
`linear-model-v2:<lowerhex-id>:` and `linear-model-v3:<lowerhex-id>:`
prefixes, and observes their original map membership and metadata key.

Only the front of original `load_model` in
[`integer_factor_candidate_v2.rs`](../../../trillionnium/crates/trnm-mvcc-fee/src/integer_factor_candidate_v2.rs)
is covered: observe both namespaces, return collision first if both are
nonempty, then missing if the selected namespace has no exact `meta` key.
Keys such as `meta-extra` or a prefix with a different ID do not substitute.
Values are opaque except for their outer JVT1 extent and tag. A present
`null` value is not an absent metadata key. This selector approves neither
metadata nor model integrity; those later operations are separate.

## Private frame and limits

`f0(readbuf request, mutbuf response, mutbuf scratch) -> u32` borrows three
disjoint buffers. Request bytes 0–3 are `IMS1`, bytes 4–7 are zero, bytes
8–39 are the caller-supplied opaque artifact ID, and bytes 40 onward are
the exact State export. That export is a little-endian u64 row count,
followed by sorted unique UTF-8 rows of `u64 key_len`, `u64 encoded_value_len`,
key bytes and complete JVT1 value bytes. This private representation is
not a consensus, persistence or signed format.

The input is at most 64 rows, with each key at most 512 bytes and each
encoded value 9–4,096 bytes, at most 295,984 bytes total. Only the outer
JVT1 magic, node tag and declared extent are checked. All framing,
ordering and extent checks finish before model-semantic selection is
reported. The scan is linear over this strictly bounded export; this does
not claim the scaling behavior of the original native owner's AVL map or
the Rust BTreeMap seek.

| Status | Observation |
| --- | --- |
| 0 | Exactly one namespace has a `meta` row. Write 32 bytes: old count, new count, metadata value offset relative to the State export, and its JVT1 byte length, as four u64s. |
| 1 | Both model prefixes are populated, matching original `FACTOR_MODEL_COLLISION`. |
| 2 | Selected namespace has no exact metadata key, matching original `FACTOR_MODEL_MISSING`. |
| 100 | Private framing, scope or order refused. |
| 102 | A descriptor cannot fit the supplied output. |

Every nonzero return preserves output. Successful output suffix, all
scratch bytes and input remain unchanged. Offsets refer only to the captured
immutable bytes, not process pointers or trusted State handles.

The differential builds the existing sealed State ELF unchanged, creates
typed fixture State through its actual pipe ABI, and exports while a View is
held. The original Rust `State`, `ReadState::scan`, `prefix_rows` and
`load_model` read exactly those same raw bytes using the existing Rust test
transport decoder and pinned prebuilt Serde/Hex dependencies. Both selector
backends compare the actual descriptors and original error precedence. A
separate re-export verifies unchanged State, counts and orderly zeroed close.
Tests include ILM2/ILM3, both prefixes with no metadata, present invalid
metadata, invalid chunks, unrelated near keys, row/length bounds and
no-partial-output cases. Locked original parity is explicit opt-in:
`HIA_M06_ORACLE_PREBUILT` must bind a compatible existing target; skipped
Rust tests confer no original parity. No storage, parent resolution,
publication, adoption, trust, or production integration is covered.
