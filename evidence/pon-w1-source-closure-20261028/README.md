# Recoverable frozen W1 and hardened-verifier sources

This packet supplies the two actual Git bundles named by `report.json`:

| Bundle | Commit | Tree |
| --- | --- | --- |
| `w1-staged-source-64be7c4ad.bundle` | `64be7c4ad51d432e7736ad135476262e23e968f5` | `4157fb5cec32f74dc0d0fe50a4ad93ee11eafbca` |
| `w1-hardened-source-dd4fb0a65.bundle` | `dd4fb0a65a734bdccac23a061dc0d6c72b69188f` | `1413289f365e41f83cd6b9d65ae441ae1a973f76` |

Both require only commit `ac469237422d43805845e8b9a6839ad14e1028e7`, which
the retained public GitHub commit/compare responses identify as an ancestor of
the published `feature/chain-pure-pon-workpackages-20261027` branch. Fetch that
branch, verify the exact bundle SHA-256 recorded in `report.json`, and follow
the commands recorded there. A shallow clone of default main alone does not
supply the prerequisite.

The report intentionally retains its earlier observation that e25 did not yet
contain these bundles. This candidate adds the recorded byte streams without
rewriting that historical observation. The staged bundle is 24,520 bytes with
SHA-256 `7cbbb40239d23e692e42d51dba3e2b6cfee9e094aa11a876b9eed6b0efed6f7b`;
the hardened bundle is 273,703 bytes with SHA-256
`206271f536ae63b57161eda4ce43ad297860e1c05e3ae3a400c7b8358a420b12`.

Public prerequisite reachability and local bundle verification were observed.
An independent fresh network clone was not executed and is not claimed. Source
availability does not qualify a complete W1 proof, prove useful verifier costs
or establish quantum soundness.
