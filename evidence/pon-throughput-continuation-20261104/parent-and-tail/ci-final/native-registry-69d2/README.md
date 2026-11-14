# Final 69d2 selected-control registration and execution

The **58 selected workspace controls are actually registered and passed** on the
final dirty composed source based on `69d2e06c48bbbd1e22432f9b557727b140aba361`.
This is a selection-coverage result, not a complete Node suite or public-service
acceptance result.

| Scope | Registry | Actual execution used here |
|---|---:|---|
| Node | 1,019 registered; 27 ignored | 40 selected controls passed: 31 in the root's original logs plus 9 exact supplementary runs |
| M06 | 120 registered; 7 ignored | All 18 selected controls passed within the complete ordinary library run: 113 passed, 7 ignored |
| Original SQLite transaction scopes | Separate selection | 13 passed; not counted in the workspace 58 |

All original b811 workflow selections and counts remain. Removing only the two
DirectAppend declarations recovers the entire original workspace workflow byte
for byte. Every prefix is expanded against the actual libtest registry, each
exact name exists, no selected name is ignored, and each of the 58 names maps to
a successful original native transcript in [check-output.json](check-output.json).

## Exact source and execution boundary

All six source receipts (Node, components and supplementary runs, before and
after) are equal. They contain **1,190 native inputs**, with the independently
recomputed manifest digest:
`ccc0b180a702aa012bb24ca0541c9d91592239083c141e3a289f0345acf9df8c`.

The matching before/after ELF hashes are:

- Node: `5349b31b55279a52dd75b679c5c3a12cb0c0d784dc259098409bb376f056045d`.
- M06: `4e411e4057438162f4cc333c384f23931399e0493e86c3d4ed90d1cc6207c43a`.

The original Node batch has 118 distinct passed names. Its selected-workspace
coverage was 31: postwrite 23, reorg 6 and DirectAppend 2. Only the nine remaining
names were subsequently executed: account root digest 3, growth 2, current SQL
root 1 and history 3. Those nine do not overlap the earlier 118 passed names.
Each supplementary native invocation and its unchanged required-test reader
returned zero; the source, ELF, wrapper and reader guards were stable before and
after every invocation. There are 127 distinct Node passes across these batches,
not a claim that all 1,019 registered Node controls ran.

The supplementary native/reader interval was
**2026-11-04 09:00:48.878758–09:01:05.124633 UTC**. The runner used the already
built final ELF; it did not invoke Cargo or edit native code. Its elapsed times
are execution observations, not an ABBA throughput experiment.

These observations belong to the dirty composed input inventory and ELF. They
must not be relabelled as clean 69d2, a later commit, hosted CI, F0 or campaign
success. Prior failed performance experiments and hosted service observations
retain their own evidence and conclusions.

## Reproduce the offline check

From this directory, using Python 3 with its standard library:

```sh
python3 check_selection_execution.py
sha256sum -c SHA256SUMS
```

The reader checks every referenced artifact's stored and uncompressed digest,
command exits, stdout/stderr bindings, registry counts, complete source receipts,
per-selector execution identity, original required-reader outputs and preserved
workflow bytes. It launches no native executable. The relative source paths in
[summary.json](summary.json) refer to the separately preserved final-native raw
package; logs are not duplicated in this directory.

## Records

- [Exact 58-selector registry and execution mapping](check-output.json)
- [Artifact identities and source bindings](summary.json)
- [Offline checker](check_selection_execution.py)
- [Supplementary nine original native and reader observations](../../final-native/69d2/workspace-nine/result.json)
- [Supplementary nine selection and prior-log identities](../../final-native/69d2/workspace-nine/selection.json)
- [Supplementary runner source](../../final-native/69d2/workspace-nine/run-workspace-nine.py)
- [Root original Node native observation](../../final-native/69d2/native/result.json)
- [Root M06/SQLite component observation](../../final-native/69d2/components/result.json)
- [Frozen final workspace workflow, gzip](../pon-original-workspace-large-state-cpu.yml.gz)
- [Earlier b811 registry record, with its explicit M06 gap](../native-registry-b811/README.md)
- [Package checksums](SHA256SUMS)

This directory has independent checksums. The parent ci-final checksum list,
parent README and historical b811 registry package remain unchanged.
