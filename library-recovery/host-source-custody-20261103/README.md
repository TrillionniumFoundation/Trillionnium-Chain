# Desktop source custody — 2026-11-03 capture

This isolated archive preserves 6 source references and 6 distinct Git blobs for `TrillionniumFoundation/Trillionnium-Chain`.

Source bytes are stored under `contexts/`, separated by capture scope and original worktree context. `SOURCE_MANIFEST.json` maps every archived file to its original path, captured revision, byte count, SHA-256, and Git blob SHA-1. The manifest also records the original frozen snapshot and code-only package hashes.

The archive preserves source files, captured source patches, and small explicitly synthetic fixtures. It does not reconstruct the original captured commit history or certify scientific replay, tests, or production readiness. Captured sources were hashed and checked for recognizable credential literals; they were not executed during this recovery.

The archive commit is based on `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0` and adds only this custody directory. No existing development branch was modified.
