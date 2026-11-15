# Security correction: reject vulnerable MSRV downgrade

**Current status: dependency graph restored; official compiler upgrade and
actual build remain pending.** The `ruint 1.15.0` candidate in commit
`3a3191748f79675f18670163afe6c50e8fe43858` was never built. Its proposed Phase0
attempt4 was not authorized or started. The successful offline resolver checks
in that historical candidate established a dependency graph and declared
minimum Rust versions; they did not establish dependency security.

## Advisory findings

| Official advisory | Affected concern | Patched range |
| --- | --- | --- |
| [RUSTSEC-2025-0137](https://rustsec.org/advisories/RUSTSEC-2025-0137.html) | A release-mode reciprocal input can reach unchecked indexing after a debug-only safety assertion disappears | `>=1.17.1` |
| [RUSTSEC-2026-0220](https://rustsec.org/advisories/RUSTSEC-2026-0220.html) | Incorrect overflow flags and truncated shift amounts affect shift-dependent arithmetic and some formatting paths | `>=1.20.0` |

The first advisory's affected-function label says `<1.17.0`, while its patched
range says `>=1.17.1`. The patched field governs the candidate selection; choosing
1.17.0 from the function label would be incorrect. Version 1.17.2 meets the old
compiler's declared MSRV but still does not resolve the second advisory.

Cached official registry metadata records Rust 1.90 as the minimum for
`ruint 1.20.0`, `1.21.0`, and `1.21.1`; `1.21.0` is yanked. The cached
`1.21.1` archive and initial lock checksum agree. The upstream
[release notes](https://github.com/alloy-rs/ruint/releases) also document the
Rust 1.90 increase in 1.18.0 and the subsequent shift fixes in 1.20.0.
These facts support a compiler upgrade, not a disabled MSRV check.

## Actual feature and source-path review

The retained [Cargo feature-tree command](feature-tree-receipt.json) was a
read-only `cargo tree --offline --locked` for
`riscv32im-risc0-zkvm-elf`. It returned zero and did not change the lock or
compile code. `ruint` has `alloc`, `serde` and `borsh` enabled through
`risc0-binfmt 3.0.5`.

Source inspection found `ruint` in that library's PoVW identifier/nonce code,
including `U160`/`U256` encoding and constant 32/96-bit shifts. Library PoVW
types are not a Trillionnium consensus mechanism. No direct `ruint` or PoVW
call was found in the batch guest or the original full-W1 guest. The selected
`alloc` feature also differs from the advisory's specific no-allocation
formatting-loop condition.

These are scoped source observations. They are **not** a whole-program call
graph, an ELF reachability proof, or a demonstration of non-exploitability.
They do not justify keeping a known-vulnerable package. No existing proof was
recomputed or invalidated merely by this dependency review. The complete
original work relation and frozen leaf image remain unchanged.

## Actual restoration of the fixed dependency graph

The [resolver receipt](restore-fixed-lock/result.json) retains three genuine
offline Cargo updates restoring `enum-ordinalize 4.4.2`, its derive crate
`4.4.2`, and `ruint 1.21.1`. The final guest lock is byte-identical to the
initial batch lock from commit `b3f3fa57a4ed928a1eae61a97aecc4a9d90df467`:

`018423c898d09d0be7a7fbe207e4a1672c5b6f36202dda765a81da852c044d18`

The native lock remains:

`32953cbb86bb56186137507ee9e9bf59827bd8325c6e28c12b40d5c166fbfa4d`

All resolver commands returned zero, totaling 0.384882 wall seconds and
0.382374 child CPU seconds. No manual lock edit, advisory exception, version
check bypass, SDK downgrade, local patch, or Rust compilation was used.
Restoring a package within these two patched ranges is not a claim that every
dependency has received a complete security audit.

The [cancelled declaration](attempt4-cancellation.json) preserves the proposed
attempt4 identity and explicitly marks it `NOT_AUTHORIZED_NOT_STARTED_SUPERSEDED`.
The previous lock candidate and all three failed builds remain in history.

## Official compiler upgrade candidate

A separately reviewed public metadata GET fetched the first ten releases from
the [official RISC Zero Rust repository](https://api.github.com/repos/risc0/rust/releases?per_page=10).
The request was bounded to 512 KiB and returned 50,774 bytes with HTTP 200.
It downloaded only JSON and did not install or execute a compiler. The
[raw response](official-risc0-rust-releases/response.json) and
[resource receipt](official-risc0-rust-releases/result.json) are retained.

The release list contains non-prerelease `r0.1.91.1`, `r0.1.94.1` and
`r0.1.97.0`. The parent review selected **`r0.1.91.1` as the minimum official
upgrade meeting the fixed package's MSRV**:

- Exact archive:
  `https://github.com/risc0/rust/releases/download/r0.1.91.1/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz`
- Official asset size: `515330687` bytes.
- Official SHA-256:
  `e082a1dc44abdef1d95460295a70218eb294ab999b834570ec932d05641cce5d`.

SDK 3.0.6 already selects an installed official compiler through
`rzup::get_default_version(RustToolchain)`. The exact new target specification,
ABI compatibility, isolated selection settings, space requirement, and real
build must still be reviewed. A release label and MSRV match do not establish
that the future batch ELF executes correctly in the pinned local prover.

## Reclaimed own compiler copy and disk boundary

The parent explicitly authorized reclaiming only the reconstructible 1.88
compiler tree restored by this branch's attempt2. Before deletion, the review
verified the exact real path, the retained official archive SHA-256, the
compiler binary hash, internally resolving symlinks, completed known PID/birth
identities, and absence of process executables under that directory.

The [reclaim receipt](reclaim-own-restored-188/result.json) records free disk
increasing from `1072054272` to `2591051776` bytes, an observed increase of
`1518997504` bytes. The removed regular files accounted for `1518985216`
allocated bytes. Concurrent disk activity can affect the observed free-space
delta.

The 490,849,318-byte original compiler archive remains preserved with SHA-256
`222651797ba58f0bafd959191a48d23b35b3266d9e082fc49fb4d84733064fce`.
No other target, cache, source, proof, evidence, or compiler was deleted. The
new compiler has not been downloaded or extracted. Its actual unpacked size
is unknown, so sufficient capacity under the existing 1 GiB free-disk floor
must be established before extraction. No old failed-attempt budget is reused.
