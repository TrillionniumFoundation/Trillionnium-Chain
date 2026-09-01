# X230 isolated fuzz lock provenance v1

This record binds the isolated `trillionnium/fuzz/Cargo.lock` refresh and the associated trusted-runner guard synchronization to immutable GitHub objects. It is repository/CI provenance only. It is **not** independent hardware-attestation evidence, multi-host campaign evidence, physical power-loss evidence, security-audit evidence, soak evidence, release authority, or activation authority.

## Source and artifact binding

- X230 generation workflow run: `33492782158`
- X230 generation source commit: `2141faddcb0c3430eec2821e383f301c687937ba`
- GitHub Actions artifact id: `9794890759`
- Artifact ZIP SHA-256: `d9d0e75f7310ba06ea08223c47a0d1aff03e43fc943216f39a5b22a41219060d`
- Applied closure commit: `181134fbaa1e7db0ca42680ee0701c9cba0c4074`

## Exact payload digests

| Path | SHA-256 |
| --- | --- |
| `trillionnium/fuzz/Cargo.lock` | `f856eaedb0fd390f2a7d47c98efbe7f69ba17669257653803068758dbb089a55` |
| `.github/workflows/trnm-cometbft-spike.yml` | `c4a9221922641336265e324f974f79f267c6dbf425afad5c36cd9a2ce874d0b4` |
| `.github/workflows/trnm-gate-quick-check.yml` | `c0c8939df55e3d286d52afd82dba7f44491d1b421165d95d3886566ee29aeef9` |
| `.github/workflows/trnm-merge-gates.yml` | `083ed744e1b1ffa3fb60fbf9bc32a384ed52bfcb2e1e38ad776fb0bc20aac5bd` |
| `.github/workflows/trnm-poco-bft-v0.yml` | `7a3b99140c6ac9934ca7659e53483ac822ed68976af1725bbe1a27a0923f53cc` |

## Reproduction boundary

The lock was generated on the trusted X230 runner with the repository-pinned `nightly-2026-07-27` toolchain and Cargo offline mode:

```bash
cargo +nightly-2026-07-27 generate-lockfile \
  --manifest-path trillionnium/fuzz/Cargo.toml \
  --offline
```

The closure worktree passed the repository runner-policy and offline-Cargo policy checks with five actor-independent hosted baseline jobs, twenty-two privileged X230 jobs, and twenty offline Cargo jobs before the immutable tree was published.

Any future lock refresh must produce a new provenance record and new digests. This record must never be reused to claim external evidence or exact-head qualification for a different commit.
