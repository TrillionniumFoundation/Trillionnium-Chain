# Recovered Dependabot snapshot and C2 dependency mapping

**The seven retained alerts identify one pip dependency at version 41.0.7. C2 already pins that dependency to 50.0.2, outside every one of the seven retained affected ranges.** This is a bounded mapping of specific alerts. It is not a complete vulnerability scan or an installed-runtime assurance.

## Original job recovered without a new API request

The previously unknown job `1a1c8c38b88-135c4-218`, key `pq-qualification-dependabot-c09dbbe992-read-20261111-d4d2-1`, was recovered through its existing H status and two lossless stdout reads. Its authoritative status is `succeeded`, exit 0, output complete and durable, with 24,370 stdout bytes and zero stderr. The job was not restarted.

The original observation occurred at `2026-11-11T04:00:26.860190+00:00`, authenticated as `ProfHepta`, using GET `repos/TrillionniumFoundation/Trillionnium-Chain/dependabot/alerts?state=open&per_page=100`. Its complete seven-alert JSON is 22,148 bytes, SHA-256 `d1bab106d32091dfb5eecbd39a7f17c8b86c9052dba2146738250b61b4d889a9`. The response does not identify an exact default-branch commit; that SHA remains unknown.

All seven records identify `pip / cryptography`, requirement `= 41.0.7`, in `formal/pon-nakamoto-v1/requirements.txt`. The API labels the dependency direct and runtime. Four alerts are high, two medium, and one low, matching the severity totals in the publication warning.

| Alert | Primary GitHub advisory | Severity | Recorded affected range | First patched version |
| --- | --- | --- | --- | --- |
| 21 | [GHSA-537c-gmf6-5ccf](https://github.com/advisories/GHSA-537c-gmf6-5ccf) | High | `>= 0.5.0, < 48.0.1` | 48.0.1 |
| 20 | [GHSA-m959-cc7f-wv43](https://github.com/advisories/GHSA-m959-cc7f-wv43) | Low | `< 46.0.6` | 46.0.6 |
| 19 | [GHSA-r6ph-v2qm-q3c2](https://github.com/advisories/GHSA-r6ph-v2qm-q3c2) | High | `<= 46.0.4` | 46.0.5 |
| 18 | [GHSA-h4gh-qq45-vh27](https://github.com/advisories/GHSA-h4gh-qq45-vh27) | Medium | `>= 37.0.0, < 43.0.1` | 43.0.1 |
| 17 | [GHSA-6vqw-3v5j-54x4](https://github.com/advisories/GHSA-6vqw-3v5j-54x4) | High | `>= 38.0.0, < 42.0.4` | 42.0.4 |
| 16 | [GHSA-9v9h-cgj8-h64p](https://github.com/advisories/GHSA-9v9h-cgj8-h64p) | Medium | `< 42.0.2` | 42.0.2 |
| 15 | [GHSA-3ww4-gg4f-jr7f](https://github.com/advisories/GHSA-3ww4-gg4f-jr7f) | High | `< 42.0.0` | 42.0.0 |

These advisory fields and their full descriptions/primary references come from the retained original API response. This task made no new GitHub or advisory query.

## Exact C2 source evidence

The reviewed candidate is commit `0e554f36ffdde3053a5eb1756eb5e526b1935032`, tree `753cdbad6714f00d8ccb9ddbb47f0fd71280ee62`. Its [formal requirements](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0e554f36ffdde3053a5eb1756eb5e526b1935032/formal/pon-nakamoto-v1/requirements.txt) contain:

```text
# Scientific/conformance environment only; not a runtime dependency or dynamic install hook.
numpy==1.26.4
cryptography==50.0.2
```

That exact file is Git blob `f505bfe105e824248803af99d2865a97dbf3cd8c`, 128 bytes, SHA-256 `ae117e781e1420b46bfc2c4b9a550da3fe3f98ff9cbe868192036d34c342aed5`. The verifier positively checks that 41.0.7 lies in every recorded affected range and that 50.0.2 lies outside each. This conclusion rests on explicit version comparisons, rather than absence of a search result.

The archived C2 continuation workflow, model-runtime requirements, and independent-backend differential test also specify 50.0.2. The source comment calls the formal environment scientific/conformance; that comment does not override the API classification or prove exploit unreachability. No installed environment was inspected by this task, and no dependencies were changed.

## Cargo scope: original C1 graphs, unchanged C2 dependency inputs

The exact C2 main lockfile contains 182 package records; its fuzz lockfile contains 150. Neither has a Cargo package named `cryptography`. This separates the pip alert identity from Cargo package identities; it does not certify Rust dependencies as vulnerability-free.

Three existing C1 `cargo metadata` observations were fully checked, including original command receipts, stdout/stderr hashes, source-before/source-after identities, non-null resolve graphs, and node/edge closure:

| Original observation | Actual executed commit | Resolved packages/nodes | Workspace members |
| --- | --- | --- | --- |
| Default | `c09dbbe9921da12db8bf7240a8a95a0e9a789e50` | 177 | 26 |
| All features | Same C1 | 182 | 26 |
| Fuzz | Same C1 | 150 | 1 |

All three commands used `--locked --offline`, returned zero, and resolved full graphs; none used `--no-deps`. None contains a package identity named `cryptography`. The independently read exact C1-to-C2 Git delta contains only the cross-branch corpus JSON and the two readiness Python files. Cargo manifests, lockfiles, and tracked Cargo configuration are unchanged. These original graphs therefore support a source-based dependency-identity mapping for C2. They remain C1 execution records: no C2 metadata command, native test, or dependency resolution was run here.

The main lock includes Rust crates `openssl` 0.10.81 and `openssl-sys` 0.9.117. Those crate versions do not identify an installed OpenSSL library, and the pip-wheel advisory ranges cannot be applied directly to them. External Python tooling and installed provider provenance remain outside this Cargo-only identity check.

## Interruption, resumption, and retained evidence

An initial stage mkdir failed with ENOSPC. The cloud environment then disconnected during the first attempt to read the existing metadata; its temporary directory was lost when the environment restarted. Before that loss, the original job bytes, terminal status, and completed C2 source observations were preserved in a separate create-only H JSON. That 49,438-byte partial observation, SHA-256 `eac9de969095823b0eef729d6d2c6262dd8deca48e398e0972a14d387add6db5`, is retained unchanged in this archive. Its three metadata fields correctly remained unknown at that point.

After recovery, one bounded local read obtained the three existing graph files and the exact Git delta. `readback.json` records this later completed review separately; it does not rewrite the interrupted snapshot or claim a continuous run.

`dependency-readback-originals.tar.xz` is **92,960 bytes**, SHA-256 **`3e95e8d69ed76d6bcd11ab1a992e51ff703def2fa50ba7d50824a9e0a37038e4`**. It preserves **23 raw files / 2,749,202 bytes**, plus a provenance/hash index. These include the original job output and API JSON, the interrupted snapshot, eight exact C2 source files, original C1 graph stdout/stderr and summary, and the recorded C1-to-C2 delta. The prior frozen cloud, desktop, and publication packets are not modified.

Run `python3 -B verify_readback.py` for portable byte/receipt/range/graph checks. Add `--repo /absolute/path/to/checkout` to verify the C2 Git objects and delta again. The actual verification command and result are in `verification.json`; `DEPENDENCY_SHA256SUMS` covers the delivery files.

The default-branch alerts are not claimed closed. Installed/deployed versions, exploit reachability, other advisories, complete vulnerability coverage, whole-chain PQ qualification, and production activation remain unestablished by this packet.
