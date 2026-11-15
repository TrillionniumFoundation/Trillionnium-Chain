# Transport and preflight observations

The isolated worktree was created from published `cc836dfc13ef0006eb0878abd8cb5eca9a76bec0`. Its first detached-head preflight refused the branch state. A new isolated `fix/chain-selected-bank-r4-f16ac5` branch then passed preflight before any edits or builds. The parent checkout was not edited.

One first native-evidence transfer request was rejected as an oversized shell source. Its embedded payload had also been truncated by the local command-output budget. No verifier result was claimed from that request. The transfer was replaced with three bounded chunks of a smaller explicit native input set; their concatenated length and SHA-256 were checked before decoding. Native acceptance ran only after successful extraction and a fresh preflight. Temporary transport payloads are not evidence of computation or part of the delivered source package.

The fresh native build/check durable job was `1a1b9840551-12894-14d2`; its observed exit summary was build 0, tests 0, Clippy 0, formatting 0, dependency tree 0. The native acceptance job was `1a1b98fbcc0-12894-1526`; it reported 18 accepts, 2 typed negative controls and 13 unique accepted witnesses. Exact source, lockfile, compiler, stdout, stderr and binary pins are retained separately.

No new resource-pressure experiment was performed. Local evidence validation is read-only with respect to the captured campaigns and remote production/shared checkouts.
