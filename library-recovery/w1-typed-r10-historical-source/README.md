# W1 R10 historical source bytes (quarantined)

This folder records the **two source-file bytes that differ** between the Library `W1_Typed_Recovery_P1_R10_20261028.zip` source snapshot and the verified earlier Chain commit `74814e17a095f4ad2ce8017fd00a55ac30e08e2b` tree. The other inspected 11 W1 source code/config paths were already exact Git Blob matches to that historical tree (and the additional historical guard/preflight scripts are not asserted to be new).

| Original source path | Git blob from original ZIP | SHA-256 of original ZIP bytes |
| --- | --- | --- |
| `formal/pon-nakamoto-v1/w1_batch/host/Cargo.toml` | `89e630cad70ff015b4449dfc05b5c7e6d815edfa` | `5c82b60f91f52f1b58708d06165cec440eb99db1af87864af45f99297a2f0b6b` |
| `formal/pon-nakamoto-v1/w1_batch/host/src/staged.rs` | `5c2a2582511e9be99d4a3e622143466825b7cd5d` | `bb1889bdd4e8bbd6d210ba5dddcf8e629123b9475a8bb110d41869ca05fbb83c` |

Remote `fetch_file` returned **exact Git Blob IDs** for both original source files after upload. The source was not placed in active `formal/` paths or activated in a live node.

The original `recovery/typed-source.bundle` lists head `29d24d359948d8e3353260aa1007520af141a3aa`, whose GitHub commit lookup returned no commit; its prerequisite `74814e17...` does exist remotely. These two file snapshots do **not** restore that absent commit's exact Git graph and should not be misrepresented as a complete bundle recovery.

Reproducibility checks:

```sh
git hash-object library-recovery/w1-typed-r10-historical-source/host/Cargo.toml
git hash-object library-recovery/w1-typed-r10-historical-source/host/src/staged.rs
```

The above values must equal the manifest Git Blob column. TOML syntax parsing passed via Python 3 `tomllib`. No full Rust project build, typed W1 cryptographic acceptance, or production promotion is claimed. Code may be superseded by later work; merge into active paths only after an independent semantic diff and compatibility tests.
