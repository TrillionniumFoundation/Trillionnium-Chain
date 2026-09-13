//! Producer/consumer regression using the real native store and schema1 signer
//! journal. The injected key and in-memory anchor are explicitly test fixtures,
//! not hardware custody, a multi-process campaign or live epoch activation.

use super::{
    native_authorization_tests::{
        config, execute_prepared_checkpoint, key, open, ordinary_prefix, preparation,
        two_seal_finality,
    },
    ConfirmedNativePreHandoffCheckpointV0,
};
use ed25519_dalek::{Signer, SigningKey};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use trnm_consensus_signer_journal::{
    ExternalMonotonicWatermarkV0, ExternalWatermarkErrorV0, HandoffSignatureProducerV1,
    HandoffSignatureRequestV1, HandoffSignerJournalProfileV1, SignatureProducerErrorV0,
    SignerWatermarkV0, SqliteHandoffSignerJournalV1, StrictOldSetHandoffAdmissionV1,
};
use trnm_consensus_types::{
    CanonicalHandoffSignIntentV1, HandoffDescriptorV0, HandoffDescriptorV0Fields, SignatureBytes,
    SignatureVerifier, ValidatorId, View,
};
use trnm_native_application::{NativeApplicationCommitRequestV0, NativeApplicationV0};

#[derive(Clone, Default)]
struct TestAnchor(Arc<Mutex<Option<SignerWatermarkV0>>>);

impl ExternalMonotonicWatermarkV0 for TestAnchor {
    fn load(
        &mut self,
        scope: [u8; 32],
    ) -> Result<Option<SignerWatermarkV0>, ExternalWatermarkErrorV0> {
        let value = *self.0.lock().unwrap();
        if value.is_some_and(|value| value.scope() != scope) {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        Ok(value)
    }

    fn compare_and_advance(
        &mut self,
        expected: Option<SignerWatermarkV0>,
        target: SignerWatermarkV0,
    ) -> Result<(), ExternalWatermarkErrorV0> {
        let mut current = self.0.lock().unwrap();
        if *current != expected {
            return Err(ExternalWatermarkErrorV0::CompareFailed);
        }
        let successor = match expected {
            None => target.sequence() == 0,
            Some(prior) => {
                prior.scope() == target.scope()
                    && prior.journal_id() == target.journal_id()
                    && prior.sequence().checked_add(1) == Some(target.sequence())
            }
        };
        if !successor {
            return Err(ExternalWatermarkErrorV0::InvalidPersistedState);
        }
        *current = Some(target);
        Ok(())
    }
}

struct ObservingTestSigner {
    key: SigningKey,
    journal_path: PathBuf,
    anchor: TestAnchor,
    calls: usize,
    lose_response_once: bool,
}

impl HandoffSignatureProducerV1 for ObservingTestSigner {
    fn sign_handoff(
        &mut self,
        request: HandoffSignatureRequestV1<'_>,
    ) -> Result<SignatureBytes, SignatureProducerErrorV0> {
        self.calls += 1;
        assert_eq!(request.signer_profile_ref(), [0x61; 32]);
        assert_eq!(
            self.anchor.0.lock().unwrap().unwrap().sequence(),
            1,
            "signer ran before the prepare event reached its anchor"
        );
        // A separate connection, not the owner's cache, must see the exact
        // PREPARED intent before the signer releases any bytes.
        let connection = rusqlite::Connection::open_with_flags(
            &self.journal_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let (raw, prepared_events, signed_events): (Vec<u8>,i64,i64) = connection.query_row(
            "SELECT canonical_intent, (SELECT count(*) FROM signer_events_v1 WHERE event_kind=0), \
             (SELECT count(*) FROM signer_events_v1 WHERE event_kind=1) FROM signer_intents_v1",
            [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).unwrap();
        assert_eq!(raw, request.intent().canonical_bytes().unwrap());
        assert_eq!((prepared_events, signed_events), (1, 0));
        connection.close().unwrap();
        let signature =
            SignatureBytes::from_array(self.key.sign(request.signing_root().as_bytes()).to_bytes());
        if std::mem::take(&mut self.lose_response_once) {
            return Err(SignatureProducerErrorV0::Unavailable);
        }
        Ok(signature)
    }
}

fn old_intent(
    receipt: &ConfirmedNativePreHandoffCheckpointV0,
    author: ValidatorId,
) -> CanonicalHandoffSignIntentV1 {
    let old = receipt.old_validator_set();
    let new = receipt.new_validator_set();
    let checkpoint = receipt.header();
    let terminal = receipt.checkpoint_finality().grandchild();
    let descriptor = HandoffDescriptorV0::new(HandoffDescriptorV0Fields {
        genesis_hash: old.genesis_hash(),
        chain_id: old.chain_id(),
        old_epoch: old.epoch(),
        new_epoch: new.epoch(),
        old_protocol_version: old.protocol_version(),
        new_protocol_version: new.protocol_version(),
        old_validator_set_hash: old.id(),
        new_validator_set_hash: new.id(),
        old_consensus_parameters_hash: receipt.old_consensus_parameters().hash(),
        new_consensus_parameters_hash: receipt.new_consensus_parameters().hash(),
        checkpoint_height: checkpoint.height(),
        checkpoint_block_id: checkpoint.id(),
        checkpoint_state_root: checkpoint.state_root(),
        next_epoch_commitment_digest: receipt.next_epoch_commitment().id(),
        terminal_old_height: terminal.header().height(),
        terminal_old_block_id: terminal.header().id(),
        terminal_old_qc_digest: terminal.certifying_qc().id(),
        terminal_old_view: terminal.header().view(),
        activation_height: receipt.next_epoch_commitment().fields().activation_height,
        initial_new_view: View::new(1),
    })
    .unwrap();
    CanonicalHandoffSignIntentV1::old_set(
        &descriptor,
        old,
        new,
        receipt.old_consensus_parameters(),
        receipt.new_consensus_parameters(),
        author,
    )
    .unwrap()
}

fn run_native_to_old_journal(lose_response: bool) {
    let application_dir = tempfile::tempdir().unwrap();
    let app = open(
        &application_dir.path().join("application.sqlite3"),
        config(),
    );
    // The caller's old set is independently commissioned in this real native
    // fixture; it is not learned from the untrusted finality proof itself.
    let old_trust = app.config_v0().validator_set_v0().clone();
    let headers = ordinary_prefix(&app);
    let prepared = preparation(&app, &headers);
    let proof = two_seal_finality(&prepared).try_cev0_bytes().unwrap();
    let executed = execute_prepared_checkpoint(&app, &prepared);
    app.commit_block(NativeApplicationCommitRequestV0::new(executed))
        .unwrap();
    let native = app
        .confirm_poco_checkpoint_before_handoff_v0(prepared, &proof)
        .unwrap();
    assert_eq!(native.old_validator_set(), &old_trust);
    let author = old_trust.validators()[0].id();
    let intent = old_intent(&native, author);
    let profile = HandoffSignerJournalProfileV1::new(
        old_trust.clone(),
        native.new_validator_set().clone(),
        *native.old_consensus_parameters(),
        *native.new_consensus_parameters(),
        author,
        [0x61; 32],
        [0x62; 32],
        8,
        16 * 1024,
        32 * 1024 * 1024,
    )
    .unwrap();
    let admission = StrictOldSetHandoffAdmissionV1::verify(
        &intent,
        native.checkpoint_finality(),
        &native.next_epoch_commitment(),
        &old_trust,
        native.old_consensus_parameters(),
        native.new_validator_set(),
        native.new_consensus_parameters(),
        native.checkpoint_parent_header(),
    )
    .unwrap();
    let signing_dir = tempfile::tempdir().unwrap();
    let path = signing_dir.path().join("handoff.sqlite3");
    let anchor = TestAnchor::default();
    let mut journal =
        SqliteHandoffSignerJournalV1::create_new(&path, profile.clone(), anchor.clone()).unwrap();
    let mut signer = ObservingTestSigner {
        key: key(0),
        journal_path: path.clone(),
        anchor: anchor.clone(),
        calls: 0,
        lose_response_once: lose_response,
    };
    app.revalidate_poco_pre_handoff_checkpoint_v0(&native)
        .unwrap();
    if lose_response {
        assert!(journal
            .sign_old_set_handoff_exact_v1(&intent, &admission, &mut signer)
            .is_err());
        assert_eq!(signer.calls, 1);
        assert_eq!(anchor.0.lock().unwrap().unwrap().sequence(), 1);
    }
    let signature = journal
        .sign_old_set_handoff_exact_v1(&intent, &admission, &mut signer)
        .unwrap();
    assert_eq!(signer.calls, if lose_response { 2 } else { 1 });
    assert!(trnm_consensus_crypto::StrictEd25519Verifier.verify(
        old_trust.validator(author).unwrap(),
        &intent.signing_root(),
        &signature
    ));
    assert_eq!(anchor.0.lock().unwrap().unwrap().sequence(), 2);
    // Exact retry after reopening uses signed durable bytes and does not invoke
    // the producer, even when it previously lost a response.
    drop(journal);
    let mut reopened = SqliteHandoffSignerJournalV1::open_existing(&path, profile, anchor).unwrap();
    let calls = signer.calls;
    assert_eq!(
        reopened
            .sign_old_set_handoff_exact_v1(&intent, &admission, &mut signer)
            .unwrap(),
        signature
    );
    assert_eq!(signer.calls, calls);
    assert_eq!(app.confirmed_committed_head_v0().unwrap().height().get(), 8);
    assert!(!reopened.profile().production_activation());
}

#[test]
fn native_pre_handoff_receipt_drives_real_old_role_journal_without_joint_certificate() {
    run_native_to_old_journal(false);
}

#[test]
fn native_pre_handoff_old_role_lost_reply_retries_one_intent_and_reopens_exactly() {
    run_native_to_old_journal(true);
}
