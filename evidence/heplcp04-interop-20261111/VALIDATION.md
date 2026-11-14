# Fixed-source validation record

## Result and source identities

The structural reader passed its 65 local test methods at local commit
`843934e3c377f7344a48b4b462a3672cf4b3f00d`. The published commit
`6bf73a220ec147dba333da2404bd6c3ce7f4b1f8` has the identical source tree,
`6c004b08b87daa4a225a8728363b21f3fe08ab4a`. Both descend from fixed
`297bb40798ca1b4e4a987ef00582067282cda4e9`. API publication changed commit
metadata, not tracked source bytes. The [source export manifest](PUBLICATION_MANIFEST.json)
records all 62 new paths and their exact content hashes.

The original source guard refused the local sparse checkout. This refusal
remains in the [unmodified local result](frozen-validation/RESULT.json).
Full-checkout GitHub Actions subsequently verified source integrity before and
after each of the following two runs:

| Lane | Actual tested commit | Actual tested tree | Structural methods | Tracked entries / bytes |
| --- | --- | --- | ---: | --- |
| Head | `6bf73a220ec147dba333da2404bd6c3ce7f4b1f8` | `6c004b08b87daa4a225a8728363b21f3fe08ab4a` | 14 passed | 28,869 / 2,615,627,576 |
| Prospective merge | `1698cf9d02dc88da96d2db4e0641a9011cc3bb2b` | `df0baad8f8629e3195f80417b7bfc53a02e33af9` | 14 passed | 28,870 / 2,615,651,172 |

The prospective merge used candidate `6bf73a220ec147dba333da2404bd6c3ce7f4b1f8`
and base `c84162378f34b9284e90587df4c466dfee3e193b`.
Both lanes passed the original `verify_ci_source.py` before and after testing.
Their source observations are byte-for-byte equal within each lane.
The lanes repeat the same 14 test methods; they do not add 28 unique tests to
the 65 local methods. This is not an all-workflows-green claim.

[Original hosted run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43029319486)
and [machine-readable hosted result](hosted-validation/RESULT.json) retain
the exact tested identities. A later evidence-only child commit does not
retroactively become the source tested by this run.

## Retained original evidence

- [Local final RESULT](frozen-validation/RESULT.json) and [FROZEN identities](frozen-validation/FROZEN.json).
- [Complete local validation archive](frozen-validation/frozen-validation-3.tar.xz):
  336,108 bytes; SHA256 `5aee11abd71da780a6a6da1deb56a3ab70cfa19fa96e959a0990cd01c94c935b`.
- [Archive index](frozen-validation/VALIDATION_ARCHIVE_XZ.json): 47 retained files,
  including complete before/after inventories, original test output, and the
  original sparse-source guard failures. No log was shortened or normalized.
- [Hosted head job log](hosted-validation/head-job-log.json): decoded UTF-8
  171,114 bytes; SHA256 `5d2821eeca92669d41726696e0d471c0a3fa1b6c30c11bee5b530f9c931a5a65`.
- [Hosted prospective-merge job log](hosted-validation/prospective-merge-job-log.json):
  decoded UTF-8 172,111 bytes; SHA256
  `18ee47643d399cc575789129b027057ccfc64673c1c12771c96b8f31c29b2a16`.
- [Original GitHub job metadata](hosted-validation/github-jobs.json).

The hosted log JSON files use an explicit base64 field to preserve the exact
decoded log bytes, including meaningful trailing whitespace. Verify
`decoded_bytes` and `decoded_sha256` after decoding `data_base64`.
This container does not turn a failed execution into a passing execution.

## Acceptance boundary

The original Rust codec/coordinator replay remains pinned to Hepta
`afd2c91b3b9ef75ab9a174e3af772ad322118f7a`: 89 unchanged original source files,
94 complete reproduction inputs, and three synthetic local-policy cases.
It demonstrates wire and coordinator structure, not an ordinary task campaign.

The reader does not authenticate original signer custody or signatures, grant
runtime permissions, adopt a model, switch CURRENT, execute a successor's
FinalUse, or prove daemon/Root cold restart. Local defer/retain is a local
policy decision and is not relabeled as a training/evaluation NoUpdate.

New ordinary complete-chain, positive-adoption, and NoUpdate/rollback-chain
counts are all **0**. Independent B/C, owner-authenticated FinalUse, and
production qualification remain unaccepted. Authority remains **DENY_ALL**.
