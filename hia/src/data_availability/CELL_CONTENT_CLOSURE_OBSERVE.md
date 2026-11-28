# Detached TCC2 declaration observation

This native owner qualifies the original `CellContentClosureV2::observe_closure`
over the complete canonical TCC2 declaration only. It does not observe the
payload or any of the five declared dependencies.

`f0(readbuf, mutbuf, mutbuf) -> u32` takes one immutable loan:
`CCH1 context prefix (141 bytes) || max reads BE64 || max bytes BE64 || canonical TCC2`.
The context prefix is the literal CCH1 tag plus typed profile, purpose,
instance and generation, with no supplied length, digest, or provenance.
The independently supplied context is not a trusted pin or authority.
The input has no previous budget counters. This one-call projection uses a
fresh, positive synthetic limit pair, and does not create or mutate an
owner's reservation or carry budget state into another call.

The original exact TCC2 declaration parser first checks all canonical
structure. The typed context and positive budget shape must then be valid.
The original observation requires ModelManifest purpose and exact equality
of the context profile, instance and generation with the embedded payload
claim. The declaration alone charges one admission with declared byte length
plus one for the original EOF probe. The finite comparison is time-free;
there is no file, network reader, or EOF operation outside the immutable
declaration supplied by the caller.

On success output is the 213-byte CCH1 claim from native SHA-512 followed
by the successful read-count and byte-count as two BE64 words. The full hash
message is the fixed domain `TRNM/CPQ1/FullContent/SHA512/v1\0` followed by
the exact 149-byte derived claim header and complete canonical TCC2.

Structural error codes retain the [TCC2 parser's meanings](CELL_CONTENT_CLOSURE_VALUE.md).
Codes 30, 31 and 32 are invalid fresh limits, malformed typed context, and
invalid profile/instance, respectively. Codes 33, 34 and 35 identify
wrong manifest purpose, manifest/payload context mismatch, and insufficient
fresh byte allowance. A short context frame returns 100; valid operations
with output under 229 or scratch under 131,232 bytes return 102. Code 103
is an internal hash lifecycle refusal. No refused call exposes output,
including a digest. The original object's saturated budget counters after
denial are checked in Rust qualification, but not exported by this
side-effect-free projection.

The actual locked Rust method, complete 229-byte outputs and rejection
precedence are independently compared with both pinned native backends.
No `verify_readers`, dependency/payload reads, storage, authorization,
custody, timing, or production integration is part of this owner.
