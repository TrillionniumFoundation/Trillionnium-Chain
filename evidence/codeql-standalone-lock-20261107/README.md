# Standalone Cargo lock for exact-source CodeQL analysis

The real Rust analyses on candidate `3d1b6507671ec694ce58e86d4063a125c8deeb66`
completed their queries, parsed their SARIF and retained the artifacts, but the
unchanged after-source guard refused a dirty worktree. The new diagnostic records
from the push lane and both PR source lanes identify the same single untracked
file:

`evidence/pon-w1-work-security-20261101/matching-direct-deps/harness/crypto/Cargo.lock`

Their raw NUL-delimited status is 89 bytes with SHA256
`e3de06fa9dca7fad8f48ce973212249f0098deb531896d8944e2182541d05b0a`.
Both tracked diff outputs are empty. The actual observations are in
[the PR run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42366373938)
and [the push run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42366364894).
The generated lockfile body was not retained by those runs; this change does not
claim to have recovered it.

## Fix and dependency boundary

The primitive harness is a standalone Cargo package. Its historical parent
harness has a retained lockfile, but the child package previously had none for an
independent metadata query. This continuation adds an explicit
[standalone lockfile](../pon-w1-work-security-20261101/matching-direct-deps/harness/crypto/Cargo.lock).
It seeds Cargo with the unchanged parent lockfile and lets actual Cargo metadata
resolve and prune the standalone graph offline. Every resulting package's name,
version, registry source and checksum must already match the parent lockfile.
Repeated `--locked --offline` metadata must preserve the new lockfile bytes.

This binds the standalone analysis input without excluding the historical source,
ignoring generated lockfiles, cleaning the checkout after analysis, or weakening
the source verifier. The next exact head and prospective-merge Rust analyses must
still pass that verifier. This local metadata validation does not by itself make
the CodeQL matrix green.

## Historical evidence remains historical

The [original manifest](../pon-w1-work-security-20261101/matching-direct-deps/manifest.json)
enumerates five harness input files. All five original hashes, the original
manifest and the compressed campaign archive are unchanged. The new child
lockfile is a subsequent analysis binding; it is not added to that historical
input list or described as an original campaign input. The original
`original_lockfile_matched=false` and
`original_workspace_graph_verified=false` qualifications remain false.

[Validation details](validation.json) retain the exact parent, original hashes,
new lock hash, package identities, Cargo version and metadata results. No native
campaign was rerun here and no public-service, work-security or production
qualification is inferred.

With the original dependencies available in Cargo's cache, the focused check is:

```bash
cargo metadata --locked --offline --format-version 1 \
  --manifest-path evidence/pon-w1-work-security-20261101/matching-direct-deps/harness/crypto/Cargo.toml
```

The command is run against the tracked lockfile. A missing dependency or a
required lock change remains an error; no fallback dependency graph is accepted.
