# PQ hardening source review snapshot (unintegrated)

Retained from `Trillionnium_Chain_PQ_Hardening_20261110.zip` in the user's ChatGPT Library on 2026-11-10. These are exact source snippets and patches, *not* a qualified branch or production code. They are intentionally stored under `qualification/` without applying changes to any live protocol, Rust crate, or CI command.

Source basis: `da1374a200022bc14dc2bd325cc9ba29dbcd24ab`. Original three patch groups: complete ML-DSA SPKI binding, STARK helper source pinning, and quantum offline-numeric input validation. `identity/negative-controls-only.patch` is an alternative preliminary negative-control patch **not** to be stacked after the full identity patch. The supplemental STARK patch requires ordering and external pin updates described in `README_ZH.md` and `stark/AFTER_PACK_INTEGRATION.md`.

Status: **RESEARCH_ONLY, HOLD_NO_GO**. The original archive recorded no integrated commit, no successful native Rust/TLS/strict Clippy/rustfmt or hosted CI, and no public chain security qualification. The files here preserve reviewable candidate source; downstream integration, security boundaries, real-world tests, source locks, and adoption require separate auditable evidence. The `stark/stark-integration.tar.gz` includes actual ten complete source files and original scoped review evidence; the second STARK archive has supplemental sources. Secrets and local execution logs are intentionally omitted.

No production adoption or `main` changes are authorized by this archival commit.
