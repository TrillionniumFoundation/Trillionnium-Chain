# D4: failed cache preparation and independent empty-target origins

This archive preserves build-preparation outcomes for the prospective C6
qualification of commit `2bdd252aa6c300b7431b9ee897b254b7953cf562`, tree
`ac3cb7171c429fa5e12e29ee16839fa6f49f1b81`. It does not itself qualify that source,
record a new proof, or turn copied C5 executables into C6 outputs.

The archive was assembled in an independent external directory by reading an
explicit file allowlist and retained tool responses. No source worktree, partial
target, active qualification target, Cargo process, or owner operation was
modified by this archival step.

## Keep these outcomes separate

| Preparation | Supported outcome | Limit |
| --- | --- | --- |
| Owner cache copy, job `1a1b9bd043d-12894-167b` | Confirmed cancellation, exit -15; not timed out | Full cache copy did not complete. Its partial output remains a failed preparation, not a reusable qualified target. |
| Combined backend/native copy, job `1a1b9bc6a15-12894-1677` | Confirmed whole-job timeout, exit 124, under its original 300-second runtime limit | The earlier backend component record succeeded; the native component remained partial. Whole-job failure does not erase the completed component, and the component does not make the whole job successful. |
| Native empty setup 02, job `1a1b9c7ff2c-12894-16d7` | Launch and terminal outcome remain Unknown | Same-key reconciliation did not relaunch. Missing remote job files do not prove that no process ever started or that all processes terminated. |
| Owner empty target preparation, job `1a1b9c851ec-12894-16da` | Confirmed exit 0; unique directory was absent before creation and had zero entries at preparation | This is a historical origin observation. A separate owner qualification subsequently uses that target; the archive makes no current-emptiness or qualification-result claim. |
| Native empty target 03 | Distinct namespace, prepared through file APIs and observed empty | There is no preparation-process job ID or measured creation monotonic timestamp. Setup 03 does not resolve setup 02's Unknown outcome. |

## Owner cancellation and empty origin

The retained original owner-copy helper used an inner rsync timeout of 1,800
seconds and an outer runtime timeout of 2,100 seconds. The copy was explicitly
cancelled before timeout after observed disk throughput made full-cache copying
impractical. The original declaration and helper are preserved unchanged.

The runtime exit file and its publication witness bind the cancelled job.
Before cancellation, the supervisor, Python helper and three rsync processes
were bound to one boot ID, their individual birth ticks and the job's private
cgroup. Two later observations found all five original identities absent from
`/proc` and the original cgroup absent. The retained partial contained 2,320
files and 4,017,461,806 logical bytes. Two metadata digests, about 2.24 seconds
apart, were identical. These observations establish the bounded shutdown and
stability observations recorded here; they are not a complete historical
wait/reap ledger or a perpetual no-write guarantee.

The replacement owner target was a different path:

`/home/qian-qi/work/chain-w1-base62-owner-empty-target-20261108-ec265b`

At its recorded creation it had zero entries, device 2050 and inode 56126602.
The old partial directory was neither continued nor cleared. The original C5
owner ELF retained 468,126,952 bytes and SHA256
`41c2d70d80282414bef23a90f22130e5da26e1ac30c8fddc8c5aec6e9de54d24`
before copying and after cancellation/empty-target preparation.

See [owner preparation](owner-empty/preparation.json),
[original helper](owner-empty/original-copy-helper.py),
[owner runtime exit](owner-copy/runtime/exit.json), and
[publication witness](owner-copy/runtime/exit.witness.json).

## Backend component, native partial, whole-job timeout

The combined-copy helper was retrieved as data from its original runtime
request. Only the executable, script, command context and resource/time limits
were extracted. The original request hash is recorded; its environment mapping
is not published.

The helper's actual order is significant: it calls
`subprocess.run(argv, check=True)`, verifies the source ELF before/after,
checks the copied ELF, checks every destination regular file for source-inode
sharing and hard links, writes the backend component record, and only then
moves to the native component. The retained backend record reports 3,867
regular files checked, zero shared source inodes and zero hard links. Its
recorded staged-prover ELF has SHA256
`499b9e67297907cc5a2ab1062b17c57c60bb5a022240f27526451c1d9ff6ae91`.
These are copy-time C5 artifact facts. There is no separately retained direct
`cp` return-code field, so the archive does not fabricate one; successful
completion of that component is supported by the helper's checked control flow
and the resulting pinned record.

The original whole-job terminal is nevertheless exit 124 / timed out. A
separate retained read-only size observation reports the native partial at
376,579,857 bytes and backend destination at 1,619,497,625 bytes. Current-scope
evidence found the original cgroup absent, two known PIDs absent and no exact
matching copy process, while expressly retaining
`all_historical_child_births_captured=false` and
`all_historical_wait_reaped=null`.

See [component record](backend-native-copy/backend-cache-copy.json),
[extracted original helper](backend-native-copy/original-copy-helper.py),
[whole-job terminal](backend-native-copy/runtime/exit.json),
[partial observation](backend-native-copy/partial-observation.stdout.log), and
[scope limit](backend-native-copy/first-copy-current-scope.json).

## Unknown setup 02 and distinct setup 03

Setup 02 retained `launch_unknown`, `status_authoritative=false`,
`reused=true` and `retried_launch=false`. The independent readback archived
here returned a remote-helper FileNotFoundError for that job directory, not an
authoritative process terminal. Its namespace was not reused by this archival
task.

Setup 03 used a new native target path ending in `-03`. Its file-API sequence
created a unique marker, checked that marker's digest, removed only that marker,
and observed an empty directory including hidden entries. The preparation
record leaves `created_monotonic_ns=null`. A separate immutable C6 qualification
declaration binds this target and records an emptiness assertion before Cargo.
That declaration is included as context only; no running qualification result is
classified in this package.

See [02 Unknown](native-02/empty-setup-02-launch-unknown.json),
[independent failed readback](native-02/status-readback-error.txt),
[03 preparation](native-03/native-empty-preparation-03.json), and
[separate qualification declaration](native-03/qualification-declaration.json).

## Scope and verification

[summary.json](summary.json) records the distinct outcomes and limits.
[manifest.json](manifest.json) binds every retained file except itself to its
SHA256, byte count, source path or captured-tool provenance. Terminal witness
hashes are checked against their unchanged exit files. Raw files are copied
byte-for-byte; the extracted helper is never executed by the archiver.

Only selected JSON, text logs and scripts are published. No full private
environment, credential file, SQLite database, Cargo cache, ELF or other binary
payload is included. Existing registry caches and installed toolchains remain
shared preparation inputs; empty target origins do not establish an independent
cleanroom or reproducible build.

No full historical descendant-reaping qualification, resource billing,
production/security qualification, provider payment, proof-deadline change or
owner-operation change is inferred from these build-preparation records.
