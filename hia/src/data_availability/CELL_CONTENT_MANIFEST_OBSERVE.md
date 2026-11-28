# Detached TCM2 manifest observation

This native value owner matches the original public
`CellContentManifestV2::observe_manifest` over one complete canonical TCM2
declaration. It does not read or verify the declared model payload.

`f0(readbuf, mutbuf, mutbuf) -> u32` receives one immutable loan:
`CCH1 context prefix (141 bytes) || max reads BE64 || max bytes BE64 || canonical TCM2`.
The caller supplies only the CCH1 magic, typed profile, purpose, instance,
and generation in the prefix; no claim length or digest is accepted.
The original TCM2 shape and complete embedded CCH1 declaration are checked
first. The separately supplied ModelManifest context must then match the
embedded payload profile, instance and generation exactly. It is not a
trusted pin, and cannot authorize access. The arithmetic projects one call
against fresh positive synthetic limits, without modifying any user's
budget, owner state, or even a persistent counter.

On success the exact 213-byte claim and two BE64 counts, one observation
and TCM2 length plus one for the original EOF probe, are written to the
229-byte output prefix. The hash is SHA-512 of the original
`TRNM/CPQ1/FullContent/SHA512/v1\0` domain, exact derived 149-byte CCH1 header,
and complete TCM2. All prefix framing, typed context, budget and hash logic
after canonical parsing is shared with the
[TCC2 declaration observation](CELL_CONTENT_CLOSURE_OBSERVE.md).
Codes 1–10 retain [TCM2 meanings](CELL_CONTENT_MANIFEST_VALUE.md);
30–35 and 100/102/103 retain the shared observation meanings.
Failed calls expose no claim, exhausted counters or digest. The scope
includes neither `verify_payload_*` nor any file, network, storage,
ownership, authority or real-content operations.

Qualification compares actual locked Rust, both stock native builds,
the independent digest, and exact successful budget counts. The existing
TCM2 declaration and TCC2 observation are also independently replayed.
