# Latest concurrent composition — 2026-11-05

The architecture work is integrated into the existing Draft PR #688. The final
recorded native combination is `cb8ed84404977320fdb09d75284f99149654107d`; the published source anchor is
`cf8c88acc026bd36a00aedb40e09aa380ddbc0eb`. This supplement retains the later Growth, public-request
observation and runtime-release changes. Earlier records keep their original
commit identities and are not relabeled as new executions.

## Concrete results

| Control | Actual result | Source |
| --- | --- | --- |
| Architecture native release target | Compiled; 12 component tests PASS | `cb8ed844` |
| Strict target Clippy, formatting, inventory and repository checks | PASS | `cb8ed844` |
| Architecture reader / Host adapter | 22 / 17 PASS | `cb8ed844`; rerun because the phase-reader dependency changed |
| Phase reader / CI contract / PQ source controls | 51 / 98 / 35 PASS | `cb8ed844` |
| Original full-business selector | Exit 101; all 18 samples fail with `PUBLIC_HOST_KERNEL_PARENT` | `cb8ed844`; original settings retained |
| Complete business execution owner | Exit 2, passed=false | Complete raw report retained |
| Source identity before/after | PASS | Both `cb8ed844` and published `cf8c88ac`, separately recorded |
| Published-source locked build freshness | PASS; byte-identical tested native ELF | `cf8c88ac` |
| Exact source registry | 490 blobs at `cb8ed844`; 492 at `cf8c88ac`, all match; HOLD_NO_GO | The later input registers two runtime-release scripts; source identity only |

The current ELF SHA-256 is
`5b8981f22b5bc5fc9c30871164b924273f630fa14bce193e3ae5ee62339b0073`.
The complete Rust workspace and formal-source subtrees are identical between
`cb8ed844` and `cf8c88ac`. All 17 actual loaded architecture Python modules also
have identical Git blobs. The last merge preserves two unrelated runtime-release
scripts and their registrations; those scripts are not among the loaded modules.
The locked build explicitly confirms binary equality instead of assuming it.

## Preservation and source registration

The Growth/request-accounting input contributes 16 changed paths. Its direct
intersection with the architecture line is only the development plan and
generated inventory; both merge by additions, with no original lines removed.
The inventory contains the exact 1,228-path union. The reader and adapter are
rerun because their real import closure includes the updated phase reader.

Nine existing registry values required synchronization in `cb8ed844`: eight
exactly match the concurrent remote source changes and one binds the combined
inventory. The next registration merge preserves the remote runtime-release
updates and changes only the existing CI and combined-inventory pin values
relative to that remote. Original guard failures and exact diffs remain in the
archive; no required path, activation flag, admission limit or safety predicate
is removed.

## Records and limits

- [latest-composition.json](latest-composition.json) binds commands, results,
  commit/tree identities, native binary and remaining HOLD flags.
- [latest-records-index.json](latest-records-index.json) records the byte count
  and SHA-256 of each of the 96 retained records.
- [latest-records.tar.gz](latest-records.tar.gz) contains the original logs,
  complete failed native report, strict source guards, composition reviews and
  capture scripts. It omits native executables, caches and generated databases.

The original [GHOSTDAG campaign](ghostdag-order-max6.json) and
[exact replay](ghostdag-replay.json) remain bound to their recorded `d992451c`
source and unchanged kernel/oracle/campaign bytes. The OHIE red/green and standard
scenario controls likewise retain their original scope. No test executions are
added together to inflate distinct coverage.

The full-business refusal remains an actual failed acceptance result. The
original no-attack, four-second/16 hostile-W1, depth-and-required-work confirmation,
4,105-block History, full PQ/state/recovery, WAN and independent-operator gates
remain open. This supplement declares no performance winner, complete alternative
consensus implementation, security theorem or production activation.
