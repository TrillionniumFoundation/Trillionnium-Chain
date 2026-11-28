# Original-owner PFT wrapper controls

These four frozen controls call the real `inspect_selected_pft` wrapper using
the original `CellAdoptionOwnerV1` and SQLite catalog. They use the existing
public 2×2 candidate, without an input-feature packet or prediction call.
No Cargo dependency, lockfile, production profile or acceptance rule changes.

`build_fixture.py` independently frames the published TCM1/TCR1/TCD1/TMR1/TCV1
byte formats in Python. It fixes four complete version manifests before the
Rust run, including wire SHA-256, TCV1 SHA-512 commitment and model-root digest.
Rust decodes these bytes through the original `CellVersionManifestV1` parser
and checks the frozen identities. Model and environment manifests have their
actual payload/chunk digests; the environment is explicitly synthetic metadata,
not a real executable inventory or host attestation.

The selected fixture has generation 2. A generation-3 successor retains the
same public candidate and fixed interface while explicitly naming the first
model root as its parent. This tests a changed durable selection, not learning
progress. Separate fresh owners select an unknown loader profile or a candidate
whose weight contains a Boolean with its payload hash correctly rebound; the
wrapper must still refuse. No old int257/TMT1 profile is reinterpreted.

Frozen control names under `pft_selected_inspection_v1::owner_tests::`:

1. `selected_catalog_wrapper_returns_frozen_descriptor_and_cold_reopen_agrees`
2. `original_owner_refuses_empty_stale_and_changed_execution_before_model_parse`
3. `selected_catalog_payload_and_profile_refuse_without_changing_selection`
4. `selected_catalog_repinned_invalid_pft_is_refused_by_original_parser`

The first checks every returned descriptor field, exact selected commitment,
revision/generation and original cold-open behavior. The next uses malformed
model bytes to confirm empty/stale/changed-execution failures remain owner
errors before parsing. The last two check payload length/hash, unknown profile
and an invalid numeric value despite matching selected payload pins. Refusals
must preserve the original selection and release its guard.

The planned actual-crate command is `cargo test --offline --locked -p
trnm-pon-node --lib pft_selected_inspection_v1::owner_tests:: --
--test-threads=1`, with original profiles, two jobs and `-D warnings`. Only the
four exact named controls may execute. Earlier 9/11/6 controls and the earlier
two SQLite tests are filtered, not rerun. A separate explicitly allocated gate
must retain first failure, original stdout/stderr, source hashes and actual
outer elapsed time; this protocol itself records no execution success.

The tests deliberately make real local catalog decisions in disposable
synthetic namespaces. Their comparison pins are test constants and provide no
host authorization, current user permission, production adoption, FinalUse,
availability proof, useful-work reward or payment. Successful inspection
returns metadata only. No private weights/features, historical test split,
normal-equation calculation, numeric inference or scientific gate is used.
