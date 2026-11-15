# Official Rust 1.91.1 acquisition and isolated metadata checks

**Status: the fixed official compiler archive was acquired once, completely
inspected and extracted, and its version/target metadata checks passed. No
Cargo build, guest execution, receipt verification, or proving occurred in this
stage.** The batch guest has no compiled image yet. The original complete W1
proof and its failed single-work practical-benefit result remain unchanged.

This follows the [security correction](../pon-w1-batch-ruint-security-20261028-r8/README.md):
the vulnerable `ruint 1.15.0` compatibility candidate was rejected before a
build. The current guest graph is restored to the original `ruint 1.21.1` and
`enum-ordinalize 4.4.2` versions. This stage raises the official guest compiler
to meet those declared minimum Rust versions; it disables no MSRV or SDK check.

## Fixed official identities

| Item | Identity |
| --- | --- |
| Official release | [`r0.1.91.1`](https://github.com/risc0/rust/releases/tag/r0.1.91.1) |
| Exact archive | `https://github.com/risc0/rust/releases/download/r0.1.91.1/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz` |
| Archive bytes | `515330687` |
| Archive SHA-256 | `e082a1dc44abdef1d95460295a70218eb294ab999b834570ec932d05641cce5d` |
| Observed compiler | `rustc 1.91.1-dev (30e2186d0 2025-11-25)` |
| Compiler source commit | `30e2186d00badadc7c66ee5e72a38d0b767491b9` |
| Installed `bin/rustc` SHA-256 | `207d5fd3164e7e45393e1bac2513f41760af3b48facbe879f52e9af31c696823` |
| Observed LLVM | `21.1.2` |

The official [release metadata and retrieval receipt](../pon-w1-batch-ruint-security-20261028-r8/official-risc0-rust-releases/result.json)
predate the binary request. The actual [fetch receipt](fetch/acquisition-result.json)
matches both the byte count and SHA-256. The separate scoped network review
approved this public archive request. There was no retry, resume, alternate
mirror, installer, or system-wide toolchain modification.

The retained archive lives at
`/tmp/w1-risc0-1911-resources-r8/rust-1.91.1.tar.gz`. The complete new compiler is
isolated at
`/tmp/w1-risc0-1911-resources-r8/home/toolchains/v1.91.1-rust-x86_64-unknown-linux-gnu`.
These large reproducible binaries are not duplicated into Git. Their identities,
complete member inventory, installed file hashes and raw observations are kept
here. The original 1.88 archive and complete original W1 leaf artifacts remain
preserved separately.

## Actual archive and filesystem measurements

The initial free-space estimate required `3333902975` bytes: the exact archive,
a conservatively estimated `1744830464`-byte full extraction, and the original
`1073741824`-byte free-disk floor. An earlier insufficient-capacity check is
retained in [source-review/preflights.jsonl](source-review/preflights.jsonl);
it did not start a download or create a compiler. The final pre-download
measurement was `3441549312` bytes. The projected extraction was an estimate,
not a measured size of the new compiler.

After the authenticated download, a second supervised local stage read the
**entire** archive before creating the compiler tree. It recorded all 344
members, then separately checked actual available space against the full header
allocation estimate plus a 16 MiB overhead reserve and the original 1 GiB floor.
The complete [member inventory](install/archive-member-inventory.json) is
retained even if that second capacity check were to fail.

| Measurement | Bytes | Meaning |
| --- | ---: | --- |
| Regular file logical bytes in all archive headers | 1,580,625,805 | Complete uncompressed content length |
| Rounded allocation estimate from all headers | 1,581,359,104 | Capacity estimate before extraction, not actual filesystem allocation |
| Observed unique regular file allocation | 1,581,355,008 | Actual `st_blocks`, with hardlinks counted once |
| Observed complete compiler tree allocation | 1,581,420,544 | Regular files, directories and symlinks |
| Observed installation target growth | 1,581,441,024 | Includes isolated parent directories and settings |
| Free bytes at the final install supervisor sample | 1,675,296,768 | Above the original 1 GiB floor |

The [installed-tree inventory](install/installed-tree.json) records every
regular file's SHA-256 and each link/directory entry. No selective extraction,
library deletion, hardlink conversion, or compressed-only compiler layout was
used to fit the budget. The shared filesystem can change after these snapshots;
every later build needs its own fresh disk check.

## Path checks and supervision

The exact [acquisition source](scripts/official-acquire.py) has SHA-256
`05354a8f2450572ef38b585e5eda3c1ff9a90df791638bae2bc25c9173492180`.
It binds the official HTTPS origin, size and digest; refuses prior archives,
partials and installation homes; rejects escaping/duplicate archive paths,
escaping links and special files; and uses Python's `data_filter` during each
member extraction. Complete-member space checks run before extraction writes.
The final pass resolves all installed symlinks inside the declared compiler
tree and measures actual allocation. The archive identity is rechecked across
inspection and extraction.

The [independent source review](source-review/independent-review-record.json)
found no blocking path/link escape for this fixed official digest and newly
owned destination. The [21 helper controls](source-review/reproduced-controls.json)
also passed. These are scoped source/helper checks, not a general hostile-tar
denial-of-service proof or an independent WAN attestation. Header traversal,
digesting and a single large member require the external supervisor; the inner
100-second extraction check is insufficient by itself.

Both stages used the previously reviewed namespace-safe
[supervisor](../pon-w1-batch-phase0-20261028-r8/scripts/guard9981c3.py), SHA-256
`9981c3a138c4aefb6c4662f1e2c4c05cf5ef26e302c46763a42a2366a6334217`.
It maps local PIDs to `/proc` identities and validates pidfds; it does not assume
that a local numeric PID is the same `/proc` PID. The [predeclaration](acquisition-predeclaration.json)
retains the exact commands and limits, including independent GNU timeouts,
sampled CPU/RSS/target growth, and the 1 GiB disk floor. Sampled resource stops
are not kernel cgroup hard limits, and cleanup can extend the observed duration.

| Stage | Supervisor wall seconds | Child CPU seconds | Sampled aggregate RSS peak | `wait4` single-process RSS peak |
| --- | ---: | ---: | ---: | ---: |
| Official fetch | 8.505442487 | 1.328648 | 20,971,520 B | 20,185,088 B |
| Full local installation and metadata | 14.510658654 | 14.181003 | 20,758,528 B | 72,896,512 B |

Both [fetch](fetch/result.json) and [install](install/result.json) supervisor
receipts terminated with command status zero, no recorded errors and no owned
processes left alive. The single-process peak catches a short compiler metadata
process that the aggregate RSS samples did not observe. Neither RSS field is
represented as the other.

The [cumulative ledger](cumulative-cost-ledger.json) preserves all three real
failed Phase0 attempts, the rejected lock resolution and its restoration,
dependency and compiler acquisition, source metadata requests and the owned
compiler reclaim. Named measured wall time totals `58.591399552` seconds;
captured CPU totals `36.349681` seconds. Missing supervisor/review/reclaim CPU
measurements are explicit and are not zero. The acquisition process CPU lies
inside the corresponding supervisor child total and is not added twice.
Original complete-leaf proving and old guard development controls remain
separate historical evidence. Attempt4 was never run.

## Source compatibility and supported compiler selection

The official `r0.1.88.0` and `r0.1.91.1` tags resolve to the source commits
recorded in [official-target-specs/result.json](official-target-specs/result.json).
Their `riscv32im_risc0_zkvm_elf.rs` files are byte-identical: 1,547 bytes,
SHA-256 `26a5cdf1813f117cec590d529f537e916f0a39e921b872e5dd0e8c53ed8bda8e`.
This preserves the declared RV32IM target, 32-bit pointers, little-endian
layout and ilp32 ABI. The installed compiler's
[version](install/rustc-version-verbose.stdout),
[target list](install/rustc-target-list.stdout) and
[target configuration](install/rustc-target-cfg.stdout) were then checked by
real metadata commands. Those facts support the upgrade path; they do not
establish that a new ELF runs correctly in the pinned prover.

The pinned [SDK selection source review](source-review/sdk-selection-source-review.json)
confirms that `risc0-build 3.0.6` uses `rzup 0.5.2` to select the installed
Rust toolchain. Its supported `RISC0_HOME` and `settings.toml` mechanism is used
without modifying `HOME`, SDK source, system Rustup, or compatibility checks:

```toml
[default_versions]
rust = "1.91.1"
```

The registry implementation can choose the highest installed version when a
requested default is missing. The later build must therefore verify the exact
settings and sole expected compiler directory before calling the SDK; a config
string alone is insufficient. The guest/native lock hashes remain respectively
`018423c898d09d0be7a7fbe207e4a1672c5b6f36202dda765a81da852c044d18` and
`32953cbb86bb56186137507ee9e9bf59827bd8325c6e28c12b40d5c166fbfa4d`.

## Remaining acceptance boundaries

The next step requires a newly declared Phase0 attempt5 with the authenticated
compiler and unchanged source/locks, after the parent releases the native CPU
slot. Earlier attempts and deadlines are not resumed. The existing build
envelope remains 900 wall seconds, 3,600 child CPU seconds, 2.5 GiB sampled RSS,
768 MiB target growth and a 1 GiB free-disk floor.

A successful build alone would not pass the complete-W1 proof experiment. The
real one-leaf conditional-receipt negative and resolve calibration still need
execution under a separate approved proof budget. They still represent only
one distinct work identity. Actual benefit needs independently valid different
works and complete remaining chain checks in the cost denominator; copying the
same existing leaf cannot provide an amortization result. Quantum and
independent 72-hour WAN gates remain unchanged.
