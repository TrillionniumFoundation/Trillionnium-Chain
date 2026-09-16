//! Real SQLite owners; the external service is deliberately a test double.
//! These tests qualify original-custody binding, not full native/Safety activation.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use trnm_consensus_signer_journal::{
    ExternalWatermarkErrorV0, SignerRetirementRecordV1, SignerWatermarkV0,
};
use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_checkpoint_finality_proof_v0_exact,
    decode_consensus_parameters_v0_exact, decode_handoff_descriptor_v0_exact,
    decode_next_epoch_commitment_v0_exact, decode_validator_set_v0_exact, ValidatorId,
    ValidatorSet,
};

type WatermarkState = (
    Option<SignerWatermarkV0>,
    Option<SignerRetirementRecordV1>,
    u64,
);
#[derive(Clone, Default)]
struct Watermark(Arc<Mutex<WatermarkState>>);
impl ExternalMonotonicWatermarkV0 for Watermark {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        let s = self.0.lock().unwrap();
        if s.1.is_some() || s.0.is_some_and(|w| w.scope() != scope) {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        Ok(s.0)
    }
    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        let mut s = self.0.lock().unwrap();
        s.2 += 1;
        if s.1.is_some() || s.0 != expected {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        s.0 = Some(target);
        Ok(())
    }
}
impl ExternalSignerRetirementV1 for Watermark {
    fn load_signer_retirement_v1(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerRetirementRecordV1>, ExternalWatermarkErrorV0> {
        let s = self.0.lock().unwrap();
        if s.0.is_some_and(|w| w.scope() != scope) {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        Ok(s.1)
    }
    fn retire_signer_exact_v1(
        &mut self,
        record: &SignerRetirementRecordV1,
    ) -> Result<SignerWatermarkV0, ExternalWatermarkErrorV0> {
        let mut s = self.0.lock().unwrap();
        s.2 += 1;
        if s.1 == Some(*record) {
            return Ok(record.terminal_watermark_v1());
        }
        if s.1.is_some() || s.0 != Some(record.source_v1()) {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        s.1 = Some(*record);
        Ok(record.terminal_watermark_v1())
    }
}
struct Fixture {
    context: StrictPreHandoffContextV1,
    intent: CanonicalHandoffSignIntentV1,
    set: ValidatorSet,
    author: ValidatorId,
}
fn fixture() -> Fixture {
    let root:serde_json::Value=serde_json::from_str(include_str!("../../../../docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json")).unwrap();
    let case = &root["positive"];
    let p = &case["preheader"];
    fn raw(v: &serde_json::Value, name: &str) -> Vec<u8> {
        let s = v[name].as_str().unwrap();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let old = decode_consensus_parameters_v0_exact(&raw(p, "old_parameters_cev0_hex")).unwrap();
    let new = decode_consensus_parameters_v0_exact(&raw(p, "new_parameters_cev0_hex")).unwrap();
    let set = decode_validator_set_v0_exact(&raw(p, "old_validator_set_cev0_hex")).unwrap();
    let next = decode_validator_set_v0_exact(&raw(p, "new_validator_set_cev0_hex")).unwrap();
    let commitment = decode_next_epoch_commitment_v0_exact(&raw(p, "commitment_cev0_hex")).unwrap();
    let parent =
        decode_block_header_v0_exact(&raw(p, "checkpoint_parent_header_cev0_hex")).unwrap();
    let finality = decode_checkpoint_finality_proof_v0_exact(
        &raw(&case["checkpoint_finality"], "raw_finality_proof_cev0_hex"),
        &set,
        &old,
        &commitment,
        parent.timestamp_ms(),
    )
    .unwrap();
    let descriptor =
        decode_handoff_descriptor_v0_exact(&raw(&case["handoff"], "descriptor_cev0_hex")).unwrap();
    let context = verify_pre_handoff_context_strict_v1(
        &finality,
        &commitment,
        &descriptor,
        &set,
        &old,
        &next,
        &new,
        &parent,
    )
    .unwrap();
    let author = ValidatorId::from_bytes(b"validator-a").unwrap();
    let intent =
        CanonicalHandoffSignIntentV1::old_set(&descriptor, &set, &next, &old, &new, author)
            .unwrap();
    Fixture {
        context,
        intent,
        set,
        author,
    }
}
fn profile(f: &Fixture, scope: u8) -> SignerJournalProfileV0 {
    SignerJournalProfileV0::new(
        f.set.clone(),
        f.author,
        [81; 32],
        [scope; 32],
        64,
        4096,
        32 * 1024 * 1024,
    )
    .unwrap()
}
fn host() -> SignerRetirementHostCutV1 {
    SignerRetirementHostCutV1 {
        owner_generation: 1,
        native_committed_cut: [11; 32],
        safety_revision: 10,
        safety_record_checksum: [12; 32],
    }
}

#[test]
fn original_binding_rejects_second_real_same_key_journal_and_retired_scope_substitution() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let original_path = dir.path().join("original.sqlite3");
    let other_path = dir.path().join("other.sqlite3");
    let original_watermark = Watermark::default();
    let other_watermark = Watermark::default();
    let mut original = SqliteSignerJournalV0::initialize_new(
        &original_path,
        profile(&f, 1),
        original_watermark.clone(),
    )
    .unwrap();
    let mut other =
        SqliteSignerJournalV0::initialize_new(&other_path, profile(&f, 2), other_watermark.clone())
            .unwrap();
    assert_eq!(
        original.profile().validator_set(),
        other.profile().validator_set()
    );
    assert_eq!(original.profile().author(), other.profile().author());
    assert_eq!(
        original.profile().signer_profile_ref(),
        other.profile().signer_profile_ref()
    );
    assert_ne!(
        original.profile().external_watermark_scope(),
        other.profile().external_watermark_scope()
    );
    let mixed = original.confirm_node_checkpoint_head_exact_v0().unwrap();
    assert!(OriginalOrdinaryCustodyV1::commission(&mut other, mixed).is_err());
    let selected = original.confirm_node_checkpoint_head_exact_v0().unwrap();
    let binding = OriginalOrdinaryCustodyV1::commission(&mut original, selected).unwrap();
    let calls = other_watermark.0.lock().unwrap().2;
    assert!(binding.require_operational(&mut other).is_err());
    assert_eq!(
        other_watermark.0.lock().unwrap().2,
        calls,
        "wrong owner must not reach external CAS"
    );
    binding.require_operational(&mut original).unwrap();
    let mut other_retired = other
        .retire_for_handoff_v1(&f.context, &f.intent, host())
        .unwrap();
    let other_receipt = other_retired.confirm_retirement_v1().unwrap();
    assert!(other_receipt.belongs_to_owner_v1(&mut other_retired));
    assert!(binding.require_retired(&other_retired).is_err());
    let _ = original.confirm_node_checkpoint_head_exact_v0().unwrap();
    let mut retired = original
        .retire_for_handoff_v1(&f.context, &f.intent, host())
        .unwrap();
    let receipt = retired.confirm_retirement_v1().unwrap();
    assert!(receipt.belongs_to_owner_v1(&mut retired));
    binding.require_retired(&retired).unwrap();
    let record = *retired.record_v1();
    drop(retired);
    let reopened = RetiredSqliteSignerJournalV1::open_existing_v1(
        &original_path,
        profile(&f, 1),
        original_watermark,
        record,
        &f.context,
        &f.intent,
    )
    .unwrap();
    assert!(
        binding.require_retired(&reopened).is_err(),
        "scalar-identical reopen cannot recreate original live affinity"
    );
}

#[test]
fn live_original_binding_is_not_reissued_by_reopening_the_same_journal() {
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("original.sqlite3");
    let watermark = Watermark::default();
    let mut original =
        SqliteSignerJournalV0::initialize_new(&path, profile(&f, 3), watermark.clone()).unwrap();
    let facts = original.confirm_node_checkpoint_head_exact_v0().unwrap();
    let selected = OriginalOrdinaryCustodyV1::commission(&mut original, facts).unwrap();
    drop(original);
    let mut reopened =
        SqliteSignerJournalV0::open_existing(&path, profile(&f, 3), watermark).unwrap();
    assert!(selected.require_operational(&mut reopened).is_err());
}
