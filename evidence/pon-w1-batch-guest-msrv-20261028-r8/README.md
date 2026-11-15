# Exact offline guest-lock repair after Phase0 attempt3

**Status: resolver and source checks pass; actual compilation has not been
rerun.** This packet records the minimal compatibility repair proposed for a
new, separately budgeted Phase0 attempt. It does not erase the previous build
failures or establish a valid batch proof.

The official RISC0 guest compiler restored in attempt2 is Rust `1.88.0-dev`.
Attempt3 correctly refused three packages requiring newer compilers. The
[failure packet](../pon-w1-batch-phase0-20261028-r8/README.md) preserves that
refusal and all prior resource costs.

## Actual resolver changes

All three commands used the fixed native Cargo binary, `CARGO_NET_OFFLINE=true`,
the existing checksum-bound Cargo cache, and a 30-second timeout per command.
No Rust compilation or proof was invoked. Cargo itself wrote the lockfile; it
was not edited by hand.

```sh
cargo update --offline --manifest-path formal/pon-nakamoto-v1/w1_batch/methods/guest/Cargo.toml -p ruint@1.21.1 --precise 1.15.0
cargo update --offline --manifest-path formal/pon-nakamoto-v1/w1_batch/methods/guest/Cargo.toml -p enum-ordinalize@4.4.2 --precise 4.3.0
cargo update --offline --manifest-path formal/pon-nakamoto-v1/w1_batch/methods/guest/Cargo.toml -p enum-ordinalize-derive@4.4.2 --precise 4.3.0
```

[commands.jsonl](commands.jsonl) records absolute Cargo paths, full arguments,
exit status, unrounded wall/child-CPU measurements, intermediate lock hashes,
and stdout/stderr hashes. All three resolver calls returned zero, totaling
0.493771 wall seconds and 0.405463 child CPU seconds.

| Package | Previous version | Exact compatible version | Declared Rust minimum |
| --- | --- | --- | --- |
| `ruint` | 1.21.1 | 1.15.0 | 1.65 |
| `enum-ordinalize` | 4.4.2 | 4.3.0 | 1.60 |
| `enum-ordinalize-derive` | 4.4.2 | 4.3.0 | 1.60 |

All compatible versions were already cached, appear in the original complete
W1 guest lock, and satisfy the existing upstream version requirements. Their
official archive checksums and the parent dependency constraints are retained
in [upstream-constraints-and-candidates.json](upstream-constraints-and-candidates.json).
The generated [lock diff archive](../pon-r8-evidence-transport-20261028/original-records.zip) also records the resulting dependency
edges: the older derive crate uses `syn 2.0.119`; the older `ruint` removes its
`rand 0.10.3` edge and uses `serde` instead of `serde_core` directly. The package
count remains 155.

## Frozen identities

- Previous guest lock SHA-256:
  `018423c898d09d0be7a7fbe207e4a1672c5b6f36202dda765a81da852c044d18`.
- New guest lock SHA-256:
  `6de3cb567deb89569bdabe5c224e44b6fd5232ae9a91d9074e55bd4f9b43a993`.
- Unchanged native workspace lock SHA-256:
  `32953cbb86bb56186137507ee9e9bf59827bd8325c6e28c12b40d5c166fbfa4d`.

The packet includes original/new guest lockfiles and the unchanged native lock.
The [result](result.json) verifies that non-lock batch source and all original
complete-W1 source/locks stayed byte-identical. The new batch guest still uses
`risc0-zkvm = 3.0.6`, the builder and host remain 3.0.6, and the frozen complete
leaf image, full work relation, and all version checks are unchanged.

## Checks and their limits

- All 152 registry package archives in the repaired guest lock matched their
  locked SHA-256 checksums.
- No cached package manifest in that guest lock declares a Rust minimum above
  1.88. This is a metadata check, not a successful compilation.
- The existing 12 independent public-binding controls passed.
- Rust formatting/parsing checks and both offline locked metadata checks passed.
- No native/guest compilation, receipt verification, or proof generation ran.

See [registry-integrity-and-msrv.json](registry-integrity-and-msrv.json) and
[static-review/result.json](static-review/result.json). The unchanged Rust
version check and a real bounded build must still validate this candidate.
No `--ignore-rust-version`, fake image, SDK downgrade, or fallback was used.
