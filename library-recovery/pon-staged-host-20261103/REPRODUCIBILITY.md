# Original Chain W1 staged host: inactive source custody

This directory preserves two exact ASCII Library root files captured as original staged research source on 2026-11-03. Both source files are copied without normalizing or modifying any byte. This directory is **research-only / not activated / not consensus code**.

| Original Library filename | Bytes | SHA-256 | Git blob SHA-1 |
|---|---:|---|---|
| `_sync_stage_chain_w1_host_staged_20261103.rs` | 14,969 | `bb1889bdd4e8bbd6d210ba5dddcf8e629123b9475a8bb110d41869ca05fbb83c` | `5c2a2582511e9be99d4a3e622143466825b7cd5d` |
| `_sync_stage_chain_w1_host_Cargo_20261103.toml` | 534 | `5c82b60f91f52f1b58708d06165cec440eb99db1af87864af45f99297a2f0b6b` | `89e630cad70ff015b4449dfc05b5c7e6d815edfa` |

Recheck source byte identity in a cloned checkout at this exact commit:

```sh
sha256sum library-recovery/pon-staged-host-20261103/source/*
git hash-object library-recovery/pon-staged-host-20261103/source/*
```

This fragment imports private parent symbols through `use super::` and has a Cargo manifest referring to sibling `../methods` and `../statement`. These two files **do not constitute a standalone build** and their archival checks do not claim an actual recursive proof, a successful host evaluation, honest-work economics, or W1/PQ protocol qualification. A future owner must map this fragment to the exact original package and complete dependencies before running native tests; no silent production installation or downstream activation is permitted.

The source-object presence in GitHub was separately confirmed before archival path creation, but an existing object without an audited reachable path was insufficient to certify complete Library custody. Neither the original Library source files nor other Library records have been deleted.
