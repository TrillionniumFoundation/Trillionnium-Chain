# DAA cross-owner semantic review

Reviewed immutable tips `7621af958bf0e2ed9f0ae0f1761f0723536dbaee` and `84a0c697a3178eaee31ff9f60851a42c479b73f9` against their common base `c96022b897c1235fdbdbfcfa32764403511c6aab`, and selected source `11a2cba1953f4aaee97e8ed169fcfd9a1517da23`. Their requested cross-owner patch bytes are identical (SHA-256 in companion JSON).

## Compatible additions

- `operator_continuous_lease.rs::forecast_q4_renewal_window`: a future signed window can already have insufficient remaining lifetime for the assumed queue delay plus margin. Evaluate `AtRisk` before `AwaitSignedWindow`; `Expired` remains first. This changes advisory status only; it must not alter pinned PQ/Classical lease authentication, signed domains, admission, or dispatch. Existing selected helper still had the opposite ordering. The original added test fragment checks the five-block window with a twenty-block budget, and expired precedence.
- `store.rs::forecast_q4_renewal_from_active`: additive read-only helper was absent. It limits itself to the two existing classical overlap/continuity task profiles, reads actual active state and eligible lifecycle lease, checks next-height arithmetic, and confirms unchanged active tip/generation before returning advisory information. It grants no inclusion, signing, dispatch, retry, or mining authority. The proposed narrow patch contains this helper only, without the older store implementation.

`compatible-q4-only.patch` is generated against selected source above, retaining every unrelated byte. It has not been applied to the shared checkout and has not been executed; root must apply and format/check it as part of final composition.

## Preserve current selected source

| Incoming cross-owner area | Actual delta and disposition |
| --- | --- |
| `pon_commitment.rs` | No DAA rule belongs to this module. Selected source has bounded `FullRootArithmetic`, `CheckedExecutionParent`, and `CheckedTransactionPrefix` with current exact-state comparison/cancellation controls. Preserve the selected implementation. The incoming diff from its own base also removes that base's single-successor-root optimization; that base-only detail is not claimed as a current-source feature. |
| `store.rs`, `store/public_reader.rs` | Selected source uses ordinary authenticated storage with `post_write_schema`, `legacy_admission_schema`, current readback scopes, reorg-owner context, and fallible profile-aware `ancestry_context()`. The incoming source was authored on a separate shared-snapshot-layout line and drops that line's schema domain. Shared layout is not selected here; neither introducing nor deleting it is a DAA requirement. Preserve current store/readback APIs; add only the isolated Q4 helper above. |
| SQLite `build.rs`, `build_loader_paths.rs/tests`, `unix_abi.rs` | Incoming build fence is `sqlite-3.51.3-normal-native-linux-layout-v2`; selected source is `sqlite-3.54.1-normal-native-linux-layout-v4` with held target identity and current emitted ABI witness. Incoming also deletes its own base's held-target alias checks. Preserve selected v4 and all current Cargo path checks. |
| SQLite `transaction_scope.rs/tests`, `sql.rs`, `lib.rs` | Incoming deletes the observer entirely. Selected source retains connection-owned monotone executed-transaction and write counters plus current installation. Preserve the selected observer and controls; no formal DAA component depends on removal. |
| `scripts/run_pon_native_io_component.py` | File is absent from selected source. The incoming legacy experiment uses PREPARED v1 and a different frozen SQLite build contract; its own base had v3 with native ABI event verification. Archive this historical campaign in original Git history, without treating it as validation for current SQLite v4. |
| `scripts/run_pon_identity_churn.py` | File and its former factored `pon_identity_outer_owner` module are absent from selected source. Incoming re-inlines an old finite V2Writer campaign; no current DAA authority/consumer depends on this harness. Retain as a historical alternative experiment, without claiming current-source equivalence or fresh execution. |
| Current DAA ancestry accessor | Preserve parent fix propagating `self.ancestry_context()?`; older call shape is incompatible with the selected fallible, PQ-profile-aware context API. |

Formal DAA oracle/conditional-risk components remain root-owned isolated research with original HOLD flags. Their preservation does not require any of the unrelated native/storage downgrades.

## Comparison scope correction

The first draft contrasted the incoming tip with its own merge base; it was corrected before delivery by reading every claimed selected-source path at `11a2cba...`. Base-only shared-layout and factored harness features are explicitly distinguished above from actual selected-source behavior. This prevents older branch ancestry from being mistaken for current authority.
