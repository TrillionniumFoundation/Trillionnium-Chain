# Frozen b811 dirty Node registry readback

This is an independent, offline readback of the Node registry supplied with the
root agent's `final-b811-native` observation. It performs no build and executes no
native test. Its source is the **dirty composed checkout based on
`b8116f65789a85148254f870c678a44f895316de`**, not clean b811 and not the later
69d2 checkout that existed when this evidence was packaged.

## What this establishes

| Observation | Actual scope |
|---|---|
| Node registry | 1,019 distinct registered names; 27 ignored |
| Final workspace Node selections | All 40 names registered, none ignored, no duplicates |
| Original b811 controls | All 56 declared selections and their counts preserved |
| Additional workspace controls | Only the two DirectAppend controls |
| M06 selections | 18 statically retained; no M06 registry observed in this package |
| Total declared workspace selections | 58; only the Node 40 have registry evidence here |

Removing the two DirectAppend declarations from the frozen final workflow
recovers the entire b811 workflow byte for byte. This covers the preservation of
its original commands, readers, budgets and steps, as well as selectors.
The checker expands the two Node prefixes against the actual registry and checks
each exact selection against it; it does not infer registration from Rust source.

The before and after source receipts are byte-identical: **1,190 native inputs**,
manifest `27920633e57be739926218c370ecfbdfea624df71d84b89c2f9e3fc6f48605d2`.
The supplied native receipt records the same before/after ELF SHA-256:
`7cef941c2174339125cbc43d56ed6b79976466ec225388860e1b20415ff889c3`.
Only one copy of the identical source JSON is stored. Registry command stdout
and stderr hashes were recomputed and matched their original command receipts.

Registration is not a test success verdict. The supplied observation explicitly
records that the complete Node suite was not executed and public confirmation
was not measured. The root agent separately owns the selected native execution
record; this readback does not turn that into a full-suite claim. Later source
and ELF observations require separate evidence.

## Reproduce this readback

From this directory, using Python 3 with its standard library:

```sh
python3 check_registry.py
sha256sum -c SHA256SUMS
```

The reader consumes only the packaged files and the unchanged parent workflow
snapshot. It neither invokes Cargo nor launches the native ELF. Its expected
result is `PASS_WITH_EXPLICIT_M06_REGISTRY_GAP`. The complete selected names and
per-group expansion are in [check-output.json](check-output.json).

## Evidence

- [Summary and exact identities](summary.json)
- [Independent registry checker](check_registry.py)
- [Copy and deduplication checks](copy-verification.json)
- [Original all-registry stdout, gzip](raw/registry-all.stdout.gz) and
  [command receipt](raw/registry-all.json)
- [Original ignored-registry stdout, gzip](raw/registry-ignored.stdout.gz) and
  [command receipt](raw/registry-ignored.json)
- [One identical before/after native source receipt, gzip](raw/source-before.json.gz)
- [Original root native observation](raw/native-result.json)
- [Original b811 workspace workflow, gzip](raw/workspace-b811.yml.gz)
- [Frozen final 58-selection workflow, gzip](../pon-original-workspace-large-state-cpu.yml.gz)
- [Earlier static 58-selection report](../final-58-static-validation.json)
- [Independent package checksum list](SHA256SUMS)

The parent `ci-final/SHA256SUMS`, parent README and all older snapshots are left
unchanged. This child directory has its own checksum list.
