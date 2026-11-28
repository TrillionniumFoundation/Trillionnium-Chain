# Offline named integer-model handoff

This is a Linux x86-64 **selfhost-only** fixture library for a local
immutable snapshot. The original Execution State owner and op11 export
remain separate and unchanged. Beginning with the held raw [IMP1
envelope](../../src/state/INTEGER_MODEL_PROJECT.md), a single exported
function, `trnm_integer_model_handoff_v1`, performs the exact existing
projection and then the exact existing native IMD2 load. No host process
interprets or forwards the intermediate frame at runtime.

The ABI is a u64 packed result and three pairs: input pointer and usize
extent, output pointer and usize extent, and scratch pointer and usize
extent, in that order. Input must be readable and immutable throughout the
call; output and scratch must be writable. The pairs must be valid owned
ranges, with nonnull base pointers. The wrapper checks endpoint arithmetic
and rejects overlap without accessing any supplied range. Endpoint and
overlap checks are not a substitute for the caller's memory validity.

The scratch prefix is exactly 37,296 bytes: the first 18,648 receive the
projected IMD2 bytes; the second 18,648 are the projector's transient
workspace. After successful projection only, the loader reuses the first
9,014 bytes of that second region. Scratch may change during a call and
is not a model result; the suffix after 37,296 is untouched. No additional
allocation, syscall, new storage, or callback occurs in the named library.

The wrapper propagates a nonzero packed projector status without calling
the loader. Otherwise it returns the exact packed loader status. Owned
pointer/extent guard refusal is high word 1, low word 0. Input above the
IMP1 frame bound reports 100; scratch shorter than the fixed prefix reports
102. On success the output prefix is the 32-byte content ID followed by
exactly 7,756 or 7,758 model bytes. On every refusal the output stays
unchanged. The library is not a production or storage entry point.

The build uses the pinned compiler for both existing HIA objects and for
the HIA-authored byte emitter. It admits exact stock machine object and
text hashes, one raw `f0` per kernel, no raw relocations or imports, and
retains the bytes unchanged. The emitter supplies an ELF relocatable
carrier and a 282-byte explicit x86-64 SysV thunk. Independent disassembly
checks the two static relative edges and their targets, the failure bypass,
every branch boundary and absence of system instructions. The final GNU
link only packages the byte-authored object; it introduces no text changes,
relocations, dependencies, initializers, search paths or additional exports.
The thunk is explicit machine bytes, not an ordinary HIA Core function
compiled to the ABI; there is no direct-emitter compatibility claim.

`hia/tests/test_integer_model_handoff.py` uses both genuine ordinary ILM2
and ILM3 stock op11 State exports, alongside source-exact Rust projection
and independent Rust load references. The named HIA library is called once
per comparison; Rust runs only as an oracle. Short buffers, actual locally
owned disjoint/adjacent/overlapping spans, atomic output and unchanged
State counters and bytes are checked separately. Real Rust qualification
requires a verified compatible `HIA_M06_ORACLE_PREBUILT`.
