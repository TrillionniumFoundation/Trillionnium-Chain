# Frozen Chain source evidence — 2026-11-05

Status: **HOLD / NO-GO for all seven system acceptance gates**.

## Exact source and fresh checks

This receipt belongs to published code commit `619c5f80856fb15bb6896d8008df91f58c215229` and tree `501607a6f76d4e5fc4e31a79bfdbff00c4bb007f`. The local checkout was materialized from exact Git blobs and the exact uploaded corpus bytes. The incoming tree, frozen tree, and raw commit identities were checked before the local HEAD moved with an expected-old compare. The original clean-source verifier then read all **10,034 tracked entries / 965,549,861 bytes**.

On this clean frozen source, the original PQ corpus checker verified **505 exact pins** and retained `HOLD_NO_GO`; the distributed inventory and repository checks passed; the original source-integrity Python suite passed **37/37 with 0 skipped**. Each command records its actual argv, exit code, log hash, and stable before/after HEAD, tree, index, and clean status. The identity verifier itself executes no business tests.

## Historical coverage evidence

`raw.zip` includes exactly the 13 previously allowlisted Growth coverage files without changing their bytes. They remain attached to base `2a8fee974b41fab6e2c4e662dcce1807fcd19bdd`: the original checker produced six real omission failures, and its patched fixture suite passed 37 tests. The separate earlier manual composition `ba8dba6eec9426381bc7d489103030a955d274a0` had 124 Python tests; those results are retained in their original records and are **not reassigned to this frozen source**. The earlier static Growth review concerns incoming `657bf2a462ff13a6101ebcb4fbe0fb91c515c972`, not every later runtime change in 619.

## Materialization and resource record

The temporary index first reproduced incoming tree `7f1b7af0351d87032950e01858ea767074c0d032`, then the exact frozen tree. The final corpus used the API-uploaded bytes without reordering JSON; its blob is `ae5ef9f99d7a9b785f846f93f5115c8b1743fc0b`. Both `619` and its guard commit serialize author/committer timezones as `-0500` and omit a trailing message newline. Reconstructed bytes were accepted only when their full Git SHA matched, and they were also compared byte-for-byte with the local raw objects.

An initial local capacity guard treated `f_bavail=0` as the effective writable capacity. The process was UID 0 and `f_bfree` was 2,871,058,432 bytes. The guard was corrected to record both counters and use the effective identity's available capacity while retaining more than 1 GiB plus 20 MiB before materialization. The first attempt stopped before changing source. This adjustment changed no repository checker, test threshold, or source verifier.

One initial object-availability lookup in a partial clone triggered Git's implicit lazy fetch. A termination was attempted but the batch ultimately returned exit 0. The records therefore make no zero-network-read or universal pre-existing-locality claim. All subsequent exact-object reads disabled lazy fetch; no remote ref was changed by this materialization task.

## Scope and archive

No Cargo build or native runtime test was run on this frozen source in this task. Original four-second / sixteen-hostile confirmation, independent F0, complete PQ effect authorization, production activation, and independent administrative system acceptance remain unqualified. These source receipts do not upgrade prior binaries or runtime results.

`index.json` lists every archived file and its SHA-256; `raw.zip` contains the immutable coverage history, frozen-source receipts and logs, exact materialization inputs, and the two local recording scripts. The scripts document the local workflow and retain absolute workspace paths. Uploading these three files creates Git blobs only; the root task attaches them to the evidence tree.
