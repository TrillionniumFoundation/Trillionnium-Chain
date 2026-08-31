# PoCO migration boundary evidence — 2026-08-27

Status: candidate-only, offline/type-state evidence. This record does not
claim a Comet reader, source finality quorum, target JMT writer, dual quorum,
node start, or production cutover.

## Boundary now pinned

`trnm-consensus-types` now exposes the additive
`PocoFreshGenesisImportV1` composition boundary. Its constructor requires a
`VerifiedPocoTargetProjectionV1`, so source identity/finality/mapping checks
and an importer-owned native-root recomputation have already produced the
source/target type-state token. It then rechecks the exact `PocoGenesisV1`
descriptor and typed `PocoTargetGenesisManifestV1` before retaining them.

The envelope carries two explicit, inert storage identities:

- `LegacyStorageRejectionV1` records source data-directory, WAL, and validator
  key-set commitments. Its canonical disposition tags are fixed to
  `not-imported` and have no path, file, key, or database access API.
- `PocoFreshDataDirectoryV1` records a nonzero target directory identity and
  fresh target chain/genesis coordinates. The composition rejects a directory
  identity equal to any legacy data-directory, WAL, or validator-key-set
  identity and has no in-place/reopen operation.

The envelope canonical bytes include independent descriptor/manifest/projection
commitments, the migration-instance digest, nested storage records, and three
zero policy tags (`in_place`, `old_wal`, `old_keys`). The exact bounded decoder
rejects nonzero policy/freshness tags, nested commitment drift, trailing bytes,
and any source/target context substitution. The type has no conversion back to
legacy state, no node-start capability, and no activation capability.

## Reproducible evidence

- Vector: `docs/protocol/poco-bft-v0/vectors/migration-boundary-v1.json`
- Independent checker: `scripts/ci/check_poco_bft_v0_migration_boundary_v1.py`
- Wrapper: `scripts/ci/check_poco_bft_v0_migration_boundary_v1.sh`
- Gate output:
  `poco_migration_boundary_v1=passed candidate_only=true source_token=true`
  `target_root_recompute=true legacy_wal_rejected=true`
  `legacy_keys_rejected=true legacy_data_dir_rejected=true`
  `in_place_import=false deterministic_vectors=true exact_nested_replay=true`
  `production_activation=false cross_peer_cutover=false`

The vector pins descriptor, target-manifest, legacy-rejection and fresh-
directory canonical bytes, all nested commitments, the migration-instance
digest, and eight deterministic negative mutations (trailing byte, each
legacy-reuse policy, stale fresh marker, commitment substitution, and target
root substitution). The Python checker reimplements framing and domain hashes
without importing Rust code.

Focused Rust evidence:

```text
cargo test -p trnm-consensus-types \
  fresh_genesis_import_boundary_is_one_way_and_exactly_decodable --lib
1 passed
```

## Still open (deliberately unchanged)

`MIG-ROOT-001` remains open. The following are not implemented or implied by
this boundary:

1. a trusted, read-only Comet DB/blockstore reader and independently verified
   finalized source anchor/finality quorum;
2. a concrete mapping replay and target JMT writer that recomputes the native
   root from source values rather than accepting a claim;
3. dual source/target quorum and cross-peer GenesisQC ceremony evidence;
4. physical old WAL/key/data-directory quarantine and node-start cutover
   enforcement (the types only attest the required rejection policy);
5. fresh-node SafetyState/signer-journal/watermark generation, first-block
   replay, rollback asymmetry, and signed C0 rehearsal.

All migration and production activation flags therefore remain `false`.
