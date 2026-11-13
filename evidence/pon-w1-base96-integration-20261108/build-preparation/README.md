# C7 build preparation and strict owner import

This package records successful preparation and source-bound build inputs for C7 `40a3a45d6b8afc5c4706c5235fec47634f4aabbe` / tree `4b25e3194a0682adff40bb476f2e7c0a395639fe`. It does **not** establish completion of the C7 costly-operation lifecycle. The later launch remains Unknown; see [the lifecycle record](../lifecycle-c7/README.md).

## Copies and build origins

The backend copy `1a1ba251f9f-12894-189e` and native copy `1a1ba265585-12894-18a5` each had a separate original 1800-second bound and completed with authoritative exit 0, complete durable output. They ran sequentially. The source targets and three C6 ELF pins were checked before and after copying; full regular-file metadata remained unchanged.

| Copy | Regular entries | Bytes counting each directory entry | Shared source inodes | Destination hardlinks / duplicate inodes |
|---|---:|---:|---:|---:|
| Backend | 3894 | 1683319194 | 0 | 0 / 0 |
| Native | 1974 | 864041323 | 0 | 0 / 0 |

Original Cargo ELF aliases retained their original nlink 2. Destination files had independent inodes and nlink 1. The explicit copy used `cp -a --reflink=auto --no-preserve=links`; copy-on-write extents may be shared, never source inodes.

Backend and native C7 targets are copied caches with `fresh_cargo_target=false`. Their source qualification manifests retain C6 provenance, including the backend's earlier failed C6 build attempt and subsequent successful C6 qualification. This copy does not replace those historical outcomes. The root-owned C7 owner qualification began from a separate empty target, with registry and toolchain reuse. None of these are independent cleanroom builds.

## Actual source qualification

Backend job `1a1ba2c4819-12894-18cb` completed seven commands. The runtime source-only probe intentionally returned exit 1 with `Error: unknown stage`, verified exact C7 commit/tree, and created no proof checkpoint. The other six commands returned 0.

Native job `1a1ba2df8dc-12894-18d2` completed ten commands, all exit 0, including two native example tests and two verifier tests. Historical native 243 tests are not counted as rerun. Both sets preserve locked/offline metadata, absolute Rust 1.95 compiler paths, actual Cargo artifacts for the current checkout, ELF hashes and clean source before/after. Their new Cargo artifact `fresh=false` means these artifacts were rebuilt during this qualification; it does not mean the whole target started empty.

The seven C7 gate inputs later bound by prepare total 69 commands, 655 passed methods and four ignored tests. The History release compile/list gate contributes five commands and **zero executed test methods**. Backend's expected probe exit 1 is explicit. These counts describe the completed qualification inputs, not the later Unknown operation.

## Owner extraction and schema mapping

Owner import job `1a1ba426182-12894-1950` completed with authoritative exit 0. It verified the exact original 19-command owner contract, hashed and copied 38 original stdout/stderr logs, and independently reparsed 37 passed, zero failed and four ignored results. The unique actual Cargo test artifact identifies the current C7 manifest, library source and package path. The actual owner ELF is 467950280 bytes, SHA256 `ae9ebf85ec7b76ea38c0ca1649d5a5e16f0015c915653eeea486c5090c3ce3c7`, nlink 1. Presence of the C7 compiled-checkout path inside that ELF is corroborating evidence; it does not replace Cargo, source and build provenance.

[The extracted binding](owner-artifact.json) is explicitly derived from the original qualification and Cargo JSON. It is not presented as a pre-existing root-produced binding. [The compatible owner manifest](owner-import.json) retains all original commands and their provenance. Import executes no Cargo, Node, new tests, Native transaction or operation. The six C3 native/backend source prefixes were checked unchanged, and C7 remained clean.

## Primary records and archive

- [Summary](summary.json)
- [Backend copy receipt](copy-backend.json)
- [Native copy receipt](copy-native.json)
- [Owner import](owner-import.json)
- [Extracted owner artifact](owner-artifact.json)
- [File inventory](manifest.json)
- [Exact allowlisted raw archive](raw.tar.gz)

The raw directory contains the safe external tools and declarations, copy records, component manifests, owner import with all 38 logs, captured API records, and original child/started/exit/exit-witness records for six preparation/qualification jobs. Packaging preflight is separate from the 69 source-qualification commands. Private SQLite databases, ELF binaries, inherited environments and original job request.json files are excluded. Source/target/operation/deadline records from C5 and C6 are unchanged.
