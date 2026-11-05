# Exact composed-source validation: 32c3d63c

These checks ran on clean commit `32c3d63c907d0060a5b02cd678c74b01e54ec0f9`,
tree `f35ca28e45ff563aac85164e971b7c1ae4d71def`, before and after execution.
They verify the composed source that also exports the concurrent grouped integer
research module. The 31-case performance campaign remains bound to `eeedfe33`.
No benchmark was rerun or transferred to a later source.

| Check | Result |
|---|---|
| Default-feature crypto library tests | 149 pass; all earlier 138 identities retained |
| Native W1 shared-material example tests | 9 pass |
| Strict Clippy for crypto lib/tests/named W1 example | Pass, `-D warnings` |
| CI contract tests | 98 pass |
| Source-integrity negative tests | 43 pass |
| PQ integration tests | 37 pass |
| Exact-head raw source guard and source inventory | Pass |
| Locked offline Cargo graph | 26 workspace members, 175 resolved packages |
| Workspace formatting | Pass |
| Repository and Markdown local links | Pass, 3,076 links |
| Exact source registry | 505 pins, HOLD_NO_GO |

All tests above have zero skips. All 15 recorded commands exit zero.
[summary.json](summary.json), [rust-validation.json](rust-validation.json) and
[static-validation.json](static-validation.json) retain exact commands, scopes,
source identities, results, UTC times and log hashes. Raw logs are under `logs/`.
The full Cargo metadata output is [deterministically compressed](logs/static/cargo-metadata.json.gz);
its decompressed SHA256 is recorded in the static validation report.

[Publication context](publication-context.json) records the later branch head
used to append this evidence while preserving concurrent work. These checks
certify neither that later descendant nor every workspace package/feature.
The grouped relation is distinct from W1 and receives no W1 performance credit.

The original 0.25 CPU / 2 GiB / four-second / 16-hostile-work / depth-six gate
remains unqualified. No model trial, reward, release, deployment or activation
is performed. The previously delivered raw measurement archive is unchanged;
this receipt was created after that archive and is published separately here.
