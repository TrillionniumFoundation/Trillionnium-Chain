# Frozen 0959 full Node regression — phase 2 delta

Status: **HOLD / whole-chain UNQUALIFIED**.

This separate evidence-only delta records the completed four-lane full Node library and strict Clippy runs for candidate `0959b694539b2e6427c6bfc2422b45c23b63cde4`. The tested base was `64cb26b53ed82be14049000387040ba119f00e1e`; the actual tested merge was `2c1235118b4962c00efc7a774dbb0532cf46cf24`. Head and merge share tested tree `49ffbac079b5c549050b5e876b02f70ce5b37d14`.

These observations do not test the later base `456d23a7…`, combined commit `473a7b9b…`, or any subsequent candidate. The evidence branch's own source tree is not an execution source identity.

## Completed results

| Lane | Exact PQ controls retained | Complete Node final result | Node process exit | Strict Clippy exit |
| --- | --- | --- | ---: | ---: |
| x64 head | 37/37 | 879 passed; 2 failed; 22 ignored | 101 | 0 |
| x64 actual merge | 37/37 | 879 passed; 2 failed; 22 ignored | 101 | 0 |
| ARM head | 37/37 | 879 passed; 2 failed; 22 ignored | 101 | 0 |
| ARM actual merge | 37/37 | 879 passed; 2 failed; 22 ignored | 101 | 0 |

The two failures in every lane are the unchanged original selectors:

```text
store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner
store::detached_admission::tests::authenticated_large_parent_original_schedule_supplementary_denominator
```

Both report `PUBLIC_MUTATION_CPU_BUDGET`. The earlier slow-drip write failure is absent from these corrected full-suite failures. Earlier successful child-harness summaries inside `node-lib.log` are retained; the result above is the final main-suite summary together with the recorded process exit. The 22 ignored tests remain ignored. Neither all-green Node regression nor whole-workflow success is claimed.

Compilation/profile evidence remains in the byte-identical early files referenced from phase 1: actual Node `opt_level=3`, debug assertions and overflow checks enabled, native PQ features, and the recorded executable/source identities. The delta retains each new command's source before/after, arguments, actual exit, log length and log SHA256.

## Deduplication without losing source files

Each completed artifact contains 146 raw files. All 142 files from its early artifact are byte-for-byte identical. The actual set difference is **four files per lane**, not three:

```text
node-lib.json
node-lib.log
clippy.json
clippy.log
```

This package stores those 16 new raw files, the four independently verified lane indexes, the final four-lane index, the complete reference map, and reconstruction/verification material. It references the other **568 files** by exact phase-1 raw path, byte length and SHA256. The reference map was checked against both the phase-1 raw manifest and the actual early/full file bytes. No ZIP or ELF body is duplicated.

Required phase 1:

- Evidence commit: [c8bc6391409704d6243868d184fa7a2712d25886](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/c8bc6391409704d6243868d184fa7a2712d25886/evidence/pon-pq-system-continuation-20261101/final0959-phase1).
- Publication tree: `7c634e30f7ff17238cb3aa67597bf92b61487b39`.
- Published manifest SHA256: `290493a19cc8188315c6ce5ecbe10ea9032e067b978ea1034f9c978696151c62`.
- Restored `RAW_FILES.json` SHA256: `703d5ec9f26f0efcc83fbbf4dafcbde998101480e8e312227e383900bf443663`.

The phase-1 package remains unchanged. This delta does not replace any old `d2` failure, any `0959` original workspace failure, or the original four-second business confirmation failure preserved there.

## Restore and reconstruct

First restore this delta with the standard-library-only archive reader:

```sh
python3 restore.py --output /tmp/chain-pq-phase2-delta
```

Then supply an already restored, matching phase-1 package:

```sh
python3 /tmp/chain-pq-phase2-delta/tools/reconstruct_full.py \
  --phase1 /tmp/chain-pq-phase1-restored \
  --phase2 /tmp/chain-pq-phase2-delta \
  --output /tmp/chain-pq-0959-full-artifacts
```

The reconstruction checks the exact phase-1 raw-manifest SHA, every referenced file's size/hash, every new raw file's manifest entry, canonical paths, unique output names, and the final 146-file count per lane. It creates a new destination containing all **584 original raw artifact files** plus the preserved indexes. It executes no native code, tests, SQL or recorded commands.

The archive itself uses the same deterministic sorted PAX tar, fixed metadata, gzip parameters and bounded Base64 segments as phase 1. Its own `manifest.json` binds every encoded and decoded part, the complete archive and raw file manifest. The collector restores the delta, reconstructs the four full directories, and compares every reconstructed raw file with its original bytes. `VALIDATION.json` records those packaging observations separately from application execution.

## Limits

There are 37 distinct PQ controls, exercised four times in the hosted matrix. The complete Node count is a literal Rust harness outcome and is not a count of independently accepted security properties. The complete Node suite and the original capacity/business gates remain red. All eight qualification assertions remain false; all six whole-chain qualification gates remain open. This evidence does not establish production activation, an independently deployed rollback anchor, full-owner rollback resistance, normal legacy-asset migration, quantum work/fork-choice security, WAN acceptance, or complete Hepta integration.
