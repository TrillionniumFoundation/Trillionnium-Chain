# Original V0 ordered builder provenance, 256-slot diagnostic

This separate entry computes only `BuilderProvenanceV0::canonical_digest()`
over the exact [typed V0 provenance slots](BUILDER_PROVENANCE.md). It requires
the digest-only (zero) transport mode and a little-endian count of 0–256,
the original 259-byte prefix and exactly that many 578-byte input slots.
The declared digest is ignored, as in the original canonical method.
It does not validate provenance, builder identity, uniqueness, the build,
or any release claim. Exact repeated values remain in the aggregate.

The common 256-slot artifact and SBOM driver has two statically bound
comparators. Rather than change either prior binary's dependencies or
wire contracts, this entry reuses the index-bank accessors and uses a
private bounded max-heap of row indices with the existing typed
provenance comparator. It never copies a row into sorting scratch. There
are at most eight downward moves per sift and at most 6,128 typed
comparisons (2 × 8 × (128 initial sifts + 255 extraction sifts)).
The row order and canonical member hashes use unchanged helpers.
The original transcript includes the five prefix digests, BE u64 count,
all ordered member digests, and then the exact two digest suffix fields.

Largest packet is 148,227 bytes. Output and scratch require disjoint 32
and 14,336 bytes. Private SHA/aggregate use ends by 11,258; the index
bank is [12,288,14,336). Return 0 publishes the exact digest; 100 or
102 refuse wire/capacity without writing output or scratch; 103 is a
private hash failure without output. Original Rust Cargo uses the locked
public API on inert values, including 256 slots, duplicates, independent
prefix/suffix identities and both old 64-slot modes. Direct/Selfhost
execute the actual separate entry. No signature or production routing.
