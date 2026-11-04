# Narrow dependency closure changes

The original workspace source is 89b6ca8b7300dd7f026a073b2ddc79d04df8091a.
UPSTREAM.json binds every original packaged file to its locked registry archive
checksum and upstream VCS identity. Licenses and original package sources are
retained. The following local differences are explicit:

- ark-relations 0.5.1 retains its original R1CS mathematics. The logging dependency
  is pinned to tracing-subscriber 0.3.23 (RUSTSEC-2025-0055 is patched in >=0.3.20),
  with the empty Layer callback renamed to its current on_new_span API. No GR1CS
  or 0.6 mathematical implementation is imported.
- ark-crypto-primitives 0.5.0 makes derivative optional and attaches it to the
  original crh/encryption/signature features that actually use its derives.
  Commitment and Merkle features already imply crh. These original capabilities
  remain available; the RISC Zero std+snark verifier uses none of those macros.
  This removes an unused dependency from that supported closure, not an advisory
  ignore or removal of an implemented verifier.
- paste-compat delegates the full existing paste/item/expr macro surface to the
  maintained pastey 0.2.3 implementation. It retains no old macro parser.
- The workspace transparent proof boundary uses maintained bincode-next 3.1.1
  with explicit legacy fixed-integer encoding, the original allocation-free
  grammar scan, unchanged byte limit and explicit trailing-byte refusal.

The historical standalone guest/host source and old receipts remain separately
versioned; this change does not relabel their dependency closure. No deny policy,
ignore entry, public budget, frozen 78/5b pair, consensus proof or verifier image
parameter is changed. Build, original real proof controls, byte equality, all
feature checks and exact cargo-deny are mandatory before acceptance.

Primary references:
- https://rustsec.org/advisories/RUSTSEC-2025-0055.html
- https://github.com/arkworks-rs/snark/issues/413
- https://github.com/arkworks-rs/crypto-primitives/issues/179
- https://rustsec.org/advisories/RUSTSEC-2024-0388.html
- https://rustsec.org/advisories/RUSTSEC-2024-0436.html
- https://docs.rs/pastey/0.2.3/pastey/
- https://rustsec.org/advisories/RUSTSEC-2025-0141.html
- https://docs.rs/bincode-next/3.1.1/bincode_next/migration_guide/index.html

The original distributed native source inventory includes every local patched crate file, license and provenance record, so its cold build receives the exact Cargo patch inputs. The workspace still has 26 members; new third-party path packages are dependencies, not omitted original workspace members.
