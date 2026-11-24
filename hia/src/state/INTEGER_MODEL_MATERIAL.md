# Integer model snapshot materialization

This pure entry implements the namespace, metadata and chunk portion of the
[original Rust `load_model`](../../../trillionnium/crates/trnm-mvcc-fee/src/integer_factor_candidate_v2.rs).
The caller supplies two already-scanned immutable maps for one requested
artifact. This component performs no scan itself, accepts no host pointer
or precomputed validity flag, and cannot authenticate the maps, family or
artifact. It writes no state.

The original order is preserved: both namespaces populated is a collision;
otherwise select the populated version, require its `meta` entry, validate
the exact four-field typed object and entry count, and visit chunk keys
`00`–`07` in order. Each of the first seven chunks decodes 1,024 bytes;
the last decodes 588 bytes for ILM2 or 590 for ILM3. Text must use exact
lowercase hexadecimal and exact extent. An invalid late chunk cannot
publish any prefix of the result.

The output is the complete **raw materialized bytes** only. The original
[ILM decode and content-ID computation](INTEGER_MODEL_CODEC.md) and final
requested-ID comparison are later stages, not implemented or implied
by this result. Even a valid chunk map can assemble bytes those stages
reject. No inference, model update, verification or production authority
follows from chunk materialization.

## Private typed frame

The input header is `IMD1`, u8 old and new row counts (each at most 10),
two reserved zero bytes, and the caller's 32-byte family. The two maps
follow in that order. Each row is 2,064 bytes: an eight-byte zero-padded
key suffix, u8 value tag, little-endian u16 byte length, five zero
reserved bytes, and a 2,048-byte payload slot. Row keys for the selected
map must be unique and ascending as raw bytes. Private scope is bounded;
the Rust state map is not intrinsically limited to 10.

This is a projection of **typed JSON values**, not source JSON text.
Only three type classes are needed for this original boundary:
1 string, 2 object, 3 unsigned integer; 0 represents other types.
The object payload for `meta` contains a field count, then 80-byte cells
sorted by key. A cell uses the row header layout with a 64-byte payload.
The expected fields are `bytes`, `chunks`, `family`, `schema`. Integers
carry eight little-endian bytes; strings carry their actual bytes.
Neither JSON whitespace nor property arrival order is part of the
admitted semantic value. A caller is responsible for any conversion
from source JSON to this private typed frame. No JSON parser is claimed.

Statuses 1–4 correspond to original collision, missing metadata, invalid
metadata and invalid chunk. Status 100 is private framing; status 102
is insufficient output. On success output is exactly 7,756/7,758
bytes, with no suffix writes. Input and scratch never change; scratch
is unused.

The [test](../../tests/test_integer_model_material.py) always runs
both native emitters against ordinary synthetic maps and refusal
canaries. Its separate original-method differential requires verified
real Rust/Serde dependencies. A caller can opt in by setting
`HIA_M06_ORACLE_PREBUILT` to a trusted matching Cargo target, or set
`HIA_M06_LOCKED_CARGO_ORACLE=1` with a populated offline cache for the
small source-exact projected Cargo lock. It never falls back to a
stand-in Serde. Merely running the generic suite without one of these
modes does not qualify the original differential.
