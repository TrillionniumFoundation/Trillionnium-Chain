use std::path::PathBuf;

use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{params, Connection};
use tempfile::TempDir;

use crate::{
    error::DaErrorCodeV1,
    retrieval::{complete_response_v1, prepare_full_range_response_v1},
    store::{AttestationPreparationOutcomeV1, BatchAdmissionOutcomeV1},
    AttestorEquivocationEvidenceV1, AvailabilityCertificateIdV1, AvailabilityCertificateV1,
    BatchAvailabilityStateV1, DaAttestationBodyV1, DaAttestationV1, DaAuthorAuthorityV1,
    DaBatchAuthorV1, DaCommitteeDescriptorV1, DaMemberV1, DaNamespaceV1, DaPolicyV1,
    DaStoreConfigV1, Hash32V1, PocoDaStoreV1, ProtocolContextV1, RetrievalProofV1,
    RetrievalRequestBodyV1, RetrievalRequestV1, RetrievalRequesterAuthorityV1,
    UnsignedTransactionBatchV1,
};

struct Fixture {
    directory: TempDir,
    committee: DaCommitteeDescriptorV1,
    policy: DaPolicyV1,
    author_key: SigningKey,
    author_id: Vec<u8>,
    attestors: Vec<(Hash32V1, SigningKey)>,
    scope_id: Hash32V1,
}

impl Fixture {
    fn new(max_queue_batches: u32, max_queue_bytes: u64) -> Self {
        let context =
            ProtocolContextV1::new(hash(1), "trnm-da-candidate-test", hash(2)).expect("context");
        let mut members_and_keys = (10u8..14)
            .map(|seed| {
                let key = SigningKey::from_bytes(&[seed; 32]);
                let member = DaMemberV1::new(
                    key.verifying_key().to_bytes(),
                    1,
                    Some(vec![seed]),
                    hash(seed.wrapping_add(20)),
                    hash(seed.wrapping_add(40)),
                )
                .expect("member");
                (member, key)
            })
            .collect::<Vec<_>>();
        members_and_keys.sort_by_key(|(member, _)| member.definition_hash());
        let members = members_and_keys
            .iter()
            .map(|(member, _)| member.clone())
            .collect::<Vec<_>>();
        let attestors = members_and_keys
            .into_iter()
            .map(|(member, key)| (member.definition_hash(), key))
            .collect::<Vec<_>>();
        let committee = DaCommitteeDescriptorV1::new_transaction_batch(
            context, 7, members, 2, 8_192, 4_096, 32, 4,
        )
        .expect("committee");
        let author_key = SigningKey::from_bytes(&[77; 32]);
        let author_id = b"agent:alice/session:3".to_vec();
        let authority = DaAuthorAuthorityV1::new(
            author_id.clone(),
            author_key.verifying_key().to_bytes(),
            1,
            16,
            8_192,
            4,
        )
        .expect("authority");
        let policy = DaPolicyV1::new_transaction_batch(
            &committee,
            vec![authority],
            32,
            256,
            max_queue_batches,
            max_queue_bytes,
            50,
            20,
        )
        .expect("policy");
        Self {
            directory: tempfile::tempdir().expect("tempdir"),
            committee,
            policy,
            author_key,
            author_id,
            attestors,
            scope_id: hash(90),
        }
    }

    fn batch(&self, sequence: u64, marker: u8) -> (UnsignedTransactionBatchV1, DaBatchAuthorV1) {
        self.batch_with_transactions(
            sequence,
            vec![
                vec![marker, 0, 1, 2],
                vec![marker, 3, 4, 5, 6],
                vec![marker, 7, 8],
            ],
        )
    }

    fn multi_chunk_batch(
        &self,
        sequence: u64,
        marker: u8,
    ) -> (UnsignedTransactionBatchV1, DaBatchAuthorV1) {
        let batch = self.batch_with_transactions(
            sequence,
            vec![
                vec![marker; 65],
                vec![marker.wrapping_add(1); 37],
                vec![marker.wrapping_add(2); 19],
            ],
        );
        assert!(batch.0.chunks().len() > 2, "multi-chunk retrieval fixture");
        batch
    }

    fn batch_with_transactions(
        &self,
        sequence: u64,
        transactions: Vec<Vec<u8>>,
    ) -> (UnsignedTransactionBatchV1, DaBatchAuthorV1) {
        let batch = UnsignedTransactionBatchV1::build(
            &self.committee,
            &self.policy,
            self.author_id.clone(),
            sequence,
            transactions,
        )
        .expect("batch");
        let root = DaBatchAuthorV1::signing_root(batch.envelope()).expect("author root");
        let signature = self.author_key.sign(root.as_bytes()).to_bytes().to_vec();
        let author = DaBatchAuthorV1::from_signature(
            batch.envelope(),
            self.author_key.verifying_key().to_bytes(),
            signature,
        )
        .expect("author signature");
        (batch, author)
    }

    fn path(&self, index: usize) -> PathBuf {
        self.directory.path().join(format!("da-{index}.sqlite"))
    }

    fn config(&self, index: usize) -> DaStoreConfigV1 {
        DaStoreConfigV1::new(
            self.path(index),
            self.scope_id,
            hash(u8::try_from(index).expect("test index").wrapping_add(100)),
            self.committee.clone(),
            self.policy.clone(),
            self.attestors[index].0,
        )
        .expect("store config")
    }

    fn store(&self, index: usize) -> PocoDaStoreV1 {
        PocoDaStoreV1::open(self.config(index)).expect("store")
    }

    fn signed_attestation(
        &self,
        index: usize,
        batch: &UnsignedTransactionBatchV1,
        author: &DaBatchAuthorV1,
    ) -> DaAttestationV1 {
        let store = self.store(index);
        assert_eq!(
            store.admit_batch(batch, author).expect("admit"),
            BatchAdmissionOutcomeV1::Inserted
        );
        let intent = match store
            .prepare_attestation(batch.batch_id(), 1)
            .expect("prepare")
        {
            AttestationPreparationOutcomeV1::Prepared(intent) => intent,
            AttestationPreparationOutcomeV1::Existing(_) => panic!("unexpected signed row"),
        };
        let signature = self.attestors[index]
            .1
            .sign(intent.signing_root().expect("root").as_bytes())
            .to_bytes()
            .to_vec();
        store
            .complete_attestation(intent, signature)
            .expect("complete")
    }

    fn certificate(
        &self,
        batch: &UnsignedTransactionBatchV1,
        author: &DaBatchAuthorV1,
    ) -> AvailabilityCertificateV1 {
        let mut attestations = (0..3)
            .map(|index| self.signed_attestation(index, batch, author))
            .collect::<Vec<_>>();
        attestations.sort_by_key(|attestation| attestation.body().attestor_id());
        AvailabilityCertificateV1::build(
            &self.committee,
            batch.envelope().clone(),
            author.clone(),
            attestations,
        )
        .expect("certificate")
    }
}

fn hash(value: u8) -> Hash32V1 {
    Hash32V1::new([value; 32])
}

fn retrieval_requester() -> (SigningKey, RetrievalRequesterAuthorityV1) {
    let key = SigningKey::from_bytes(&[88; 32]);
    let authority = RetrievalRequesterAuthorityV1::new(
        b"validator-repair-requester".to_vec(),
        key.verifying_key().to_bytes(),
        256,
        8_192,
        50,
    )
    .expect("retrieval requester authority");
    (key, authority)
}

fn signed_full_range_request(
    fixture: &Fixture,
    certificate: &AvailabilityCertificateV1,
    key: &SigningKey,
    authority: &RetrievalRequesterAuthorityV1,
) -> RetrievalRequestV1 {
    signed_full_range_request_with_window(fixture, certificate, key, authority, hash(200), 100, 120)
}

#[allow(clippy::too_many_arguments)]
fn signed_full_range_request_with_window(
    fixture: &Fixture,
    certificate: &AvailabilityCertificateV1,
    key: &SigningKey,
    authority: &RetrievalRequesterAuthorityV1,
    nonce: Hash32V1,
    request_height: u64,
    request_expiry_height: u64,
) -> RetrievalRequestV1 {
    let body = RetrievalRequestBodyV1::new_full_range(
        certificate,
        authority.requester_id().to_vec(),
        nonce,
        request_height,
        request_expiry_height,
        &fixture.policy,
    )
    .expect("full-range request body");
    let signature = key
        .sign(body.signing_root().expect("request root").as_bytes())
        .to_bytes()
        .to_vec();
    RetrievalRequestV1::from_signature(body, authority, signature)
        .expect("signed full-range request")
}

fn signed_full_range_proof(
    fixture: &Fixture,
    source: &PocoDaStoreV1,
    certificate: &AvailabilityCertificateV1,
    requester_key: &SigningKey,
    requester_authority: &RetrievalRequesterAuthorityV1,
    source_index: usize,
) -> RetrievalProofV1 {
    let request =
        signed_full_range_request(fixture, certificate, requester_key, requester_authority);
    signed_full_range_proof_for_request(
        fixture,
        source,
        certificate,
        requester_authority,
        source_index,
        request,
        105,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_full_range_proof_for_request(
    fixture: &Fixture,
    source: &PocoDaStoreV1,
    certificate: &AvailabilityCertificateV1,
    requester_authority: &RetrievalRequesterAuthorityV1,
    source_index: usize,
    request: RetrievalRequestV1,
    response_height: u64,
) -> RetrievalProofV1 {
    let intent = source
        .prepare_full_range_retrieval_response_v1(&request, requester_authority, response_height)
        .expect("prepare signed full-range response");
    let signature = fixture.attestors[source_index]
        .1
        .sign(intent.signing_root().expect("response root").as_bytes())
        .to_bytes()
        .to_vec();
    let response = source
        .complete_full_range_retrieval_response_v1(intent, signature)
        .expect("complete signed full-range response");
    RetrievalProofV1::new(
        request,
        response,
        certificate.clone(),
        fixture.policy.clone(),
    )
}

#[test]
fn signed_full_range_retrieval_proof_repairs_exact_certified_bytes_and_reopens() {
    let fixture = Fixture::new(4, 16_384);
    let (batch, author) = fixture.multi_chunk_batch(1, 31);
    let certificate = fixture.certificate(&batch, &author);
    let source = fixture.store(1);
    let target = fixture.store(0);
    source
        .admit_certificate(&certificate)
        .expect("source certificate");
    target
        .admit_certificate(&certificate)
        .expect("target certificate");
    let (requester_key, requester_authority) = retrieval_requester();
    let proof = signed_full_range_proof(
        &fixture,
        &source,
        &certificate,
        &requester_key,
        &requester_authority,
        1,
    );

    target
        .corrupt_content_for_test(batch.batch_id())
        .expect("target corruption");
    assert_eq!(
        target
            .audit_batch(batch.batch_id())
            .expect("latch unavailable"),
        BatchAvailabilityStateV1::Unavailable
    );
    let verified = target
        .verify_full_range_retrieval_proof_v1(&proof, &requester_authority, 110)
        .expect("verified repair proof");
    assert_eq!(verified.batch_id(), batch.batch_id());
    assert_eq!(verified.certificate_id(), certificate.certificate_id());
    assert_eq!(verified.verified_at_height(), 110);
    assert_eq!(verified.fresh_until_height(), 120);
    assert_eq!(
        target
            .repair_from_verified_retrieval_v1(verified, 110)
            .expect("proof-driven exact repair"),
        BatchAvailabilityStateV1::Certified
    );
    drop(target);

    let reopened = fixture.store(0);
    let retrieval = reopened
        .retrieve(batch.batch_id(), 0, batch.envelope().uncompressed_bytes())
        .expect("full retrieval after reopen");
    assert_eq!(retrieval.bytes(), batch.content_bytes());
    assert_eq!(retrieval.certificate(), &certificate);
}

#[test]
fn signed_full_range_retrieval_signatures_and_fresh_readback_fail_closed() {
    let fixture = Fixture::new(4, 16_384);
    let (batch, author) = fixture.multi_chunk_batch(1, 32);
    let certificate = fixture.certificate(&batch, &author);
    let source = fixture.store(1);
    let other = fixture.store(0);
    source
        .admit_certificate(&certificate)
        .expect("source certificate");
    other
        .admit_certificate(&certificate)
        .expect("other certificate");
    let (requester_key, requester_authority) = retrieval_requester();
    let body = RetrievalRequestBodyV1::new_full_range(
        &certificate,
        requester_authority.requester_id().to_vec(),
        hash(201),
        100,
        120,
        &fixture.policy,
    )
    .expect("request body");
    assert_eq!(
        RetrievalRequestV1::from_signature(body, &requester_authority, vec![0; 64])
            .expect_err("bad requester signature")
            .code(),
        DaErrorCodeV1::InvalidSignature
    );

    let request =
        signed_full_range_request(&fixture, &certificate, &requester_key, &requester_authority);
    let bad_signature_intent = source
        .prepare_full_range_retrieval_response_v1(&request, &requester_authority, 105)
        .expect("response intent");
    assert_eq!(
        source
            .complete_full_range_retrieval_response_v1(bad_signature_intent, vec![0; 64])
            .expect_err("bad responder signature")
            .code(),
        DaErrorCodeV1::InvalidSignature
    );

    let cross_store_intent = source
        .prepare_full_range_retrieval_response_v1(&request, &requester_authority, 105)
        .expect("cross-store intent");
    let cross_store_signature = fixture.attestors[1]
        .1
        .sign(
            cross_store_intent
                .signing_root()
                .expect("cross-store root")
                .as_bytes(),
        )
        .to_bytes()
        .to_vec();
    assert_eq!(
        other
            .complete_full_range_retrieval_response_v1(cross_store_intent, cross_store_signature,)
            .expect_err("cross-store response intent")
            .code(),
        DaErrorCodeV1::Conflict
    );

    let stale_intent = source
        .prepare_full_range_retrieval_response_v1(&request, &requester_authority, 105)
        .expect("fresh-readback intent");
    let stale_signature = fixture.attestors[1]
        .1
        .sign(stale_intent.signing_root().expect("stale root").as_bytes())
        .to_bytes()
        .to_vec();
    source
        .corrupt_content_for_test(batch.batch_id())
        .expect("post-prepare corruption");
    assert_eq!(
        source
            .complete_full_range_retrieval_response_v1(stale_intent, stale_signature)
            .expect_err("fresh readback must catch source drift")
            .code(),
        DaErrorCodeV1::TamperDetected
    );
}

#[test]
fn signed_full_range_retrieval_proof_time_chunk_and_store_binding_fail_closed() {
    let fixture = Fixture::new(4, 16_384);
    let (batch, author) = fixture.multi_chunk_batch(1, 33);
    let certificate = fixture.certificate(&batch, &author);
    let source = fixture.store(1);
    let target = fixture.store(0);
    source
        .admit_certificate(&certificate)
        .expect("source certificate");
    target
        .admit_certificate(&certificate)
        .expect("target certificate");
    let (requester_key, requester_authority) = retrieval_requester();
    let proof = signed_full_range_proof(
        &fixture,
        &source,
        &certificate,
        &requester_key,
        &requester_authority,
        1,
    );
    assert_eq!(
        target
            .verify_full_range_retrieval_proof_v1(&proof, &requester_authority, 104)
            .expect_err("future-dated proof")
            .code(),
        DaErrorCodeV1::InvalidRange
    );
    assert_eq!(
        target
            .verify_full_range_retrieval_proof_v1(&proof, &requester_authority, 121)
            .expect_err("stale proof")
            .code(),
        DaErrorCodeV1::InvalidRange
    );
    let repair_window_request = signed_full_range_request_with_window(
        &fixture,
        &certificate,
        &requester_key,
        &requester_authority,
        hash(203),
        100,
        150,
    );
    let repair_window_proof = signed_full_range_proof_for_request(
        &fixture,
        &source,
        &certificate,
        &requester_authority,
        1,
        repair_window_request,
        105,
    );
    assert_eq!(
        target
            .verify_full_range_retrieval_proof_v1(&repair_window_proof, &requester_authority, 126,)
            .expect_err("repair window is narrower than retrieval window")
            .code(),
        DaErrorCodeV1::InvalidRange
    );
    let stale_at_repair = target
        .verify_full_range_retrieval_proof_v1(&repair_window_proof, &requester_authority, 125)
        .expect("proof at final repair-window height");
    assert_eq!(stale_at_repair.fresh_until_height(), 125);
    assert_eq!(
        target
            .repair_from_verified_retrieval_v1(stale_at_repair, 126)
            .expect_err("verified carrier cannot outlive its repair window")
            .code(),
        DaErrorCodeV1::InvalidRange
    );
    let future_at_repair = target
        .verify_full_range_retrieval_proof_v1(&proof, &requester_authority, 110)
        .expect("proof verified at height 110");
    assert_eq!(
        target
            .repair_from_verified_retrieval_v1(future_at_repair, 109)
            .expect_err("repair height cannot precede verification height")
            .code(),
        DaErrorCodeV1::InvalidRange
    );
    let mut corrupted = proof.clone();
    corrupted.corrupt_first_chunk_for_test();
    assert_eq!(
        target
            .verify_full_range_retrieval_proof_v1(&corrupted, &requester_authority, 110)
            .expect_err("corrupt returned chunk")
            .code(),
        DaErrorCodeV1::InvalidRange
    );
    let mut noncanonical_path = proof.clone();
    noncanonical_path.corrupt_first_merkle_step_for_test();
    assert_eq!(
        target
            .verify_full_range_retrieval_proof_v1(&noncanonical_path, &requester_authority, 110,)
            .expect_err("non-canonical Merkle path")
            .code(),
        DaErrorCodeV1::InvalidRange
    );

    target
        .corrupt_content_for_test(batch.batch_id())
        .expect("target corruption");
    assert_eq!(
        target
            .audit_batch(batch.batch_id())
            .expect("latch unavailable"),
        BatchAvailabilityStateV1::Unavailable
    );
    let source_bound = source
        .verify_full_range_retrieval_proof_v1(&proof, &requester_authority, 110)
        .expect("source-bound carrier");
    assert_eq!(
        target
            .repair_from_verified_retrieval_v1(source_bound, 110)
            .expect_err("cross-store repair carrier")
            .code(),
        DaErrorCodeV1::InvalidRepair
    );
    let mut wrong_certificate = target
        .verify_full_range_retrieval_proof_v1(&proof, &requester_authority, 110)
        .expect("target-bound carrier");
    wrong_certificate.certificate_id = AvailabilityCertificateIdV1::from_hash(hash(202));
    assert_eq!(
        target
            .repair_from_verified_retrieval_v1(wrong_certificate, 110)
            .expect_err("certificate-spliced repair carrier")
            .code(),
        DaErrorCodeV1::InvalidRepair
    );
}

#[test]
fn signed_full_range_retrieval_rejects_certificate_author_key_outside_policy() {
    let fixture = Fixture::new(4, 16_384);
    let (batch, author) = fixture.multi_chunk_batch(1, 34);
    let certificate = fixture.certificate(&batch, &author);
    let alternate_key = SigningKey::from_bytes(&[89; 32]);
    let alternate_root =
        DaBatchAuthorV1::signing_root(batch.envelope()).expect("alternate author root");
    let alternate_author = DaBatchAuthorV1::from_signature(
        batch.envelope(),
        alternate_key.verifying_key().to_bytes(),
        alternate_key
            .sign(alternate_root.as_bytes())
            .to_bytes()
            .to_vec(),
    )
    .expect("alternate envelope author");
    let alternate_certificate = AvailabilityCertificateV1::build(
        &fixture.committee,
        batch.envelope().clone(),
        alternate_author,
        certificate.attestations().to_vec(),
    )
    .expect("certificate type permits a self-authenticating envelope author");
    alternate_certificate
        .verify(&fixture.committee)
        .expect("certificate remains committee-valid before policy binding");

    let (requester_key, requester_authority) = retrieval_requester();
    let request = signed_full_range_request(
        &fixture,
        &alternate_certificate,
        &requester_key,
        &requester_authority,
    );
    let intent = prepare_full_range_response_v1(
        fixture.scope_id,
        hash(210),
        hash(211),
        &request,
        &requester_authority,
        105,
        &batch,
        &alternate_certificate,
        &fixture.committee.members()[1],
    )
    .expect("construct independently verifiable malicious-source response");
    let response_signature = fixture.attestors[1]
        .1
        .sign(intent.signing_root().expect("response root").as_bytes())
        .to_bytes()
        .to_vec();
    let response =
        complete_response_v1(intent, response_signature).expect("signed malicious response");
    let proof = RetrievalProofV1::new(
        request,
        response,
        alternate_certificate,
        fixture.policy.clone(),
    );
    assert_eq!(
        fixture
            .store(0)
            .verify_full_range_retrieval_proof_v1(&proof, &requester_authority, 110)
            .expect_err("remote proof must independently enforce policy author key")
            .code(),
        DaErrorCodeV1::UnauthorizedAuthor
    );
}

#[test]
fn typed_namespace_and_batch_derivation_are_deterministic() {
    let fixture = Fixture::new(4, 16_384);
    let (left, _) = fixture.batch(1, 5);
    let (right, _) = fixture.batch(1, 5);
    assert_eq!(left, right);
    assert_eq!(
        left.envelope().namespace(),
        DaNamespaceV1::TRANSACTION_BATCH
    );
    assert_eq!(left.envelope().item_count(), 3);
    assert!(!left.chunks().is_empty());
    assert_eq!(
        DaNamespaceV1::transaction_batch_only(1)
            .expect_err("artifact namespace is outside tranche")
            .code(),
        DaErrorCodeV1::UnsupportedNamespace
    );
}

#[test]
fn admission_is_atomic_replay_safe_and_bounded() {
    let fixture = Fixture::new(2, 16_384);
    let store = fixture.store(0);
    let (first, first_author) = fixture.batch(1, 1);
    store
        .rollback_submission_for_test(&first)
        .expect("rollback injection");
    assert_eq!(
        store.admit_batch(&first, &first_author).expect("first"),
        BatchAdmissionOutcomeV1::Inserted
    );
    drop(store);

    let reopened = fixture.store(0);
    assert_eq!(
        reopened
            .admit_batch(&first, &first_author)
            .expect("applied but ack-lost replay"),
        BatchAdmissionOutcomeV1::Existing
    );
    let (conflict, conflict_author) = fixture.batch(1, 2);
    assert_eq!(
        reopened
            .admit_batch(&conflict, &conflict_author)
            .expect_err("same author sequence must conflict")
            .code(),
        DaErrorCodeV1::SequenceConflict
    );
    let (second, second_author) = fixture.batch(2, 3);
    reopened
        .admit_batch(&second, &second_author)
        .expect("second");
    let (third, third_author) = fixture.batch(3, 4);
    assert_eq!(
        reopened
            .admit_batch(&third, &third_author)
            .expect_err("bounded queue must reject third")
            .code(),
        DaErrorCodeV1::QueueFull
    );
}

#[test]
fn durable_before_attest_survives_reopen_and_rejects_bad_signature() {
    let fixture = Fixture::new(4, 16_384);
    let (batch, author) = fixture.batch(1, 9);
    let store = fixture.store(0);
    store.admit_batch(&batch, &author).expect("admit");
    let intent = match store
        .prepare_attestation(batch.batch_id(), 1)
        .expect("prepare")
    {
        AttestationPreparationOutcomeV1::Prepared(intent) => intent,
        AttestationPreparationOutcomeV1::Existing(_) => panic!("unexpected existing"),
    };
    assert_eq!(
        store
            .prepare_attestation(batch.batch_id(), 2)
            .expect_err("one conflict coordinate cannot bind a second preimage")
            .code(),
        DaErrorCodeV1::Conflict
    );
    drop(store);

    let reopened = fixture.store(0);
    let duplicate_intent = match reopened
        .prepare_attestation(batch.batch_id(), 1)
        .expect("durable prepare replay")
    {
        AttestationPreparationOutcomeV1::Prepared(intent) => intent,
        AttestationPreparationOutcomeV1::Existing(_) => panic!("not signed yet"),
    };
    assert_eq!(intent.body(), duplicate_intent.body());
    assert_eq!(
        reopened
            .complete_attestation(duplicate_intent, vec![0; 64])
            .expect_err("bad signature")
            .code(),
        DaErrorCodeV1::InvalidSignature
    );
    let signature = fixture.attestors[0]
        .1
        .sign(intent.signing_root().expect("root").as_bytes())
        .to_bytes()
        .to_vec();
    let signed = reopened
        .complete_attestation(intent, signature)
        .expect("complete after reopen");
    drop(reopened);
    let final_reopen = fixture.store(0);
    match final_reopen
        .prepare_attestation(batch.batch_id(), 1)
        .expect("signed ack-lost replay")
    {
        AttestationPreparationOutcomeV1::Existing(existing) => assert_eq!(existing, signed),
        AttestationPreparationOutcomeV1::Prepared(_) => panic!("signature was not durable"),
    }

    let loss_store = fixture.store(1);
    loss_store
        .admit_batch(&batch, &author)
        .expect("loss-control admission");
    let loss_intent = match loss_store
        .prepare_attestation(batch.batch_id(), 1)
        .expect("loss-control prepare")
    {
        AttestationPreparationOutcomeV1::Prepared(intent) => intent,
        AttestationPreparationOutcomeV1::Existing(_) => panic!("unexpected signed row"),
    };
    let loss_signature = fixture.attestors[1]
        .1
        .sign(loss_intent.signing_root().expect("loss root").as_bytes())
        .to_bytes()
        .to_vec();
    loss_store
        .corrupt_content_for_test(batch.batch_id())
        .expect("loss corruption");
    assert_eq!(
        loss_store
            .audit_batch(batch.batch_id())
            .expect("loss latch"),
        BatchAvailabilityStateV1::Unavailable
    );
    assert_eq!(
        loss_store
            .complete_attestation(loss_intent, loss_signature)
            .expect_err("unavailable bytes cannot complete an attestation")
            .code(),
        DaErrorCodeV1::TamperDetected
    );
}

#[test]
fn weighted_certificate_retrieval_retention_and_gc_close() {
    let fixture = Fixture::new(4, 16_384);
    let (batch, author) = fixture.batch(1, 11);
    let certificate = fixture.certificate(&batch, &author);
    let store = fixture.store(0);
    let certified = store
        .admit_certificate(&certificate)
        .expect("admit certificate");
    assert_eq!(certified.batch_id(), batch.batch_id());
    assert_eq!(
        store
            .admit_certificate(&certificate)
            .expect("certificate ack-lost replay")
            .certificate(),
        &certificate
    );
    let retrieval = store
        .retrieve(batch.batch_id(), 1, 7)
        .expect("bounded retrieval");
    assert_eq!(retrieval.offset(), 1);
    assert_eq!(retrieval.bytes(), &batch.content_bytes()[1..8]);
    assert_eq!(
        store
            .retrieve(batch.batch_id(), 0, 0)
            .expect_err("zero range")
            .code(),
        DaErrorCodeV1::InvalidRange
    );
    let active_permit = store
        .issue_gc_permit_for_test(batch.batch_id(), 10, 100)
        .expect("test-only active permit");
    assert_eq!(
        store
            .garbage_collect(active_permit)
            .expect_err("active obligation")
            .code(),
        DaErrorCodeV1::EarlyGarbageCollection
    );
    let extended = store
        .extend_retention(batch.batch_id(), 12, 70)
        .expect("extend");
    assert_eq!(extended.retain_until_epoch(), 12);
    assert_eq!(
        store
            .release_retention(batch.batch_id(), 12, 71)
            .expect_err("epoch equality is not expiry")
            .code(),
        DaErrorCodeV1::RetentionViolation
    );
    store
        .release_retention(batch.batch_id(), 13, 71)
        .expect("release");
    let foreign_permit = store
        .issue_gc_permit_for_test(batch.batch_id(), 13, 72)
        .expect("foreign permit source");
    let foreign_store = fixture.store(1);
    foreign_store
        .admit_certificate(&certificate)
        .expect("foreign certificate admission");
    foreign_store
        .release_retention(batch.batch_id(), 10, 1)
        .expect("foreign release");
    assert_eq!(
        foreign_store
            .garbage_collect(foreign_permit)
            .expect_err("cross-store GC permit")
            .code(),
        DaErrorCodeV1::Conflict
    );
    let permit = store
        .issue_gc_permit_for_test(batch.batch_id(), 13, 72)
        .expect("test-only finalized permit");
    let collected = store
        .garbage_collect(permit)
        .expect("GC with durable tombstone");
    assert_eq!(collected.status(), 2);
    drop(store);
    let reopened = fixture.store(0);
    assert_eq!(
        reopened.state(batch.batch_id()).expect("state"),
        BatchAvailabilityStateV1::GarbageCollected
    );
    assert_eq!(
        reopened
            .retrieve(batch.batch_id(), 0, 1)
            .expect_err("GC bytes are unavailable")
            .code(),
        DaErrorCodeV1::InvalidState
    );
}

#[test]
fn certified_batch_and_da_head_share_one_fresh_sqlite_snapshot() {
    let fixture = Fixture::new(4, 16_384);
    let (batch, author) = fixture.batch(1, 12);
    let certificate = fixture.certificate(&batch, &author);
    let config = fixture.config(0);
    let expected_store_id = config.store_id();
    let store = PocoDaStoreV1::open(config).expect("store");
    let certified = store
        .admit_certificate(&certificate)
        .expect("certificate admission");

    let readback = store
        .fresh_certified_batch_readback(batch.batch_id())
        .expect("single-snapshot head and certificate readback");
    assert_eq!(readback.head().store_id(), expected_store_id);
    assert!(readback.head().sequence() > 0);
    assert_eq!(readback.batch(), certified.facts());
}

#[test]
fn attestation_high_watermark_rejects_deleted_rows_and_sequence_reuse() {
    let fixture = Fixture::new(4, 16_384);
    let (batch, author) = fixture.batch(1, 61);
    let config = fixture.config(0);
    let store = PocoDaStoreV1::open(config.clone()).expect("store");
    store.admit_batch(&batch, &author).expect("admit");
    match store
        .prepare_attestation(batch.batch_id(), 1)
        .expect("prepare")
    {
        AttestationPreparationOutcomeV1::Prepared(_) => {}
        AttestationPreparationOutcomeV1::Existing(_) => panic!("unexpected existing"),
    }
    let connection = Connection::open(config.path()).expect("raw connection");
    connection
        .execute("DELETE FROM da_attestations_v1", [])
        .expect("delete journal row");
    drop(connection);
    assert_eq!(
        store
            .prepare_attestation(batch.batch_id(), 1)
            .expect_err("durable high-watermark forbids sequence reuse")
            .code(),
        DaErrorCodeV1::TamperDetected
    );
    drop(store);
    assert_eq!(
        PocoDaStoreV1::open(config)
            .expect_err("deleted attestation row must fail reopen")
            .code(),
        DaErrorCodeV1::TamperDetected
    );

    let (second, second_author) = fixture.batch(1, 62);
    let second_config = fixture.config(1);
    let second_store = PocoDaStoreV1::open(second_config.clone()).expect("second store");
    second_store
        .admit_batch(&second, &second_author)
        .expect("second admit");
    second_store
        .prepare_attestation(second.batch_id(), 1)
        .expect("second prepare");
    drop(second_store);
    let connection = Connection::open(second_config.path()).expect("raw second connection");
    connection
        .execute(
            "UPDATE da_metadata_v1 SET attestation_high_watermark=?1 WHERE singleton=1",
            params![0u64.to_le_bytes()],
        )
        .expect("tamper high-watermark");
    drop(connection);
    assert_eq!(
        PocoDaStoreV1::open(second_config)
            .expect_err("high-watermark checksum tamper")
            .code(),
        DaErrorCodeV1::TamperDetected
    );
}

#[test]
fn attestation_manifest_is_stable_across_certificate_retention_and_repair() {
    let fixture = Fixture::new(4, 16_384);
    let (batch, author) = fixture.batch(1, 63);
    let certificate = fixture.certificate(&batch, &author);
    let store = fixture.store(0);
    store
        .admit_certificate(&certificate)
        .expect("certificate admission");
    let original = match store
        .prepare_attestation(batch.batch_id(), 1)
        .expect("existing signed attestation")
    {
        AttestationPreparationOutcomeV1::Existing(value) => value,
        AttestationPreparationOutcomeV1::Prepared(_) => panic!("signature must be durable"),
    };
    let manifest = original.body().storage_record_checksum();
    store
        .extend_retention(batch.batch_id(), 12, 70)
        .expect("retention extension");
    let after_retention = match store
        .prepare_attestation(batch.batch_id(), 1)
        .expect("attestation replay after retention")
    {
        AttestationPreparationOutcomeV1::Existing(value) => value,
        AttestationPreparationOutcomeV1::Prepared(_) => panic!("signature must remain durable"),
    };
    assert_eq!(after_retention.body().storage_record_checksum(), manifest);
    store
        .corrupt_content_for_test(batch.batch_id())
        .expect("corrupt content");
    assert_eq!(
        store
            .audit_batch(batch.batch_id())
            .expect("latch unavailable"),
        BatchAvailabilityStateV1::Unavailable
    );
    assert_eq!(
        store.repair_batch(&batch, &author).expect("exact repair"),
        BatchAvailabilityStateV1::Certified
    );
    let after_repair = match store
        .prepare_attestation(batch.batch_id(), 1)
        .expect("attestation replay after repair")
    {
        AttestationPreparationOutcomeV1::Existing(value) => value,
        AttestationPreparationOutcomeV1::Prepared(_) => panic!("signature must remain durable"),
    };
    assert_eq!(after_repair.body().storage_record_checksum(), manifest);
    assert_eq!(after_repair, original);
}

#[test]
fn tamper_latches_unavailable_and_exact_repair_recovers() {
    let fixture = Fixture::new(4, 16_384);
    let (batch, author) = fixture.batch(1, 13);
    let certificate = fixture.certificate(&batch, &author);
    let store = fixture.store(0);
    store.admit_certificate(&certificate).expect("certificate");
    store
        .corrupt_content_for_test(batch.batch_id())
        .expect("corrupt");
    assert_eq!(
        store.audit_batch(batch.batch_id()).expect("audit/latch"),
        BatchAvailabilityStateV1::Unavailable
    );
    drop(store);
    let reopened = fixture.store(0);
    assert_eq!(
        reopened.state(batch.batch_id()).expect("latched state"),
        BatchAvailabilityStateV1::Unavailable
    );
    let (wrong, wrong_author) = fixture.batch(1, 14);
    assert_eq!(
        reopened
            .repair_batch(&wrong, &wrong_author)
            .expect_err("wrong batch identity")
            .code(),
        DaErrorCodeV1::NotFound
    );
    assert_eq!(
        reopened.repair_batch(&batch, &author).expect("repair"),
        BatchAvailabilityStateV1::Certified
    );
    assert_eq!(
        reopened
            .retrieve(batch.batch_id(), 0, 3)
            .expect("retrieval after repair")
            .bytes(),
        &batch.content_bytes()[0..3]
    );
}

#[test]
fn under_quorum_and_signed_equivocation_are_distinct() {
    let fixture = Fixture::new(4, 16_384);
    let (left_batch, author) = fixture.batch(1, 21);
    let mut attestations = (0..2)
        .map(|index| fixture.signed_attestation(index, &left_batch, &author))
        .collect::<Vec<_>>();
    attestations.sort_by_key(|attestation| attestation.body().attestor_id());
    assert_eq!(
        AvailabilityCertificateV1::build(
            &fixture.committee,
            left_batch.envelope().clone(),
            author.clone(),
            attestations.clone(),
        )
        .expect_err("two of four is below threshold")
        .code(),
        DaErrorCodeV1::InsufficientWeight
    );

    let left = fixture.signed_attestation(2, &left_batch, &author);
    let mut quorum = attestations;
    quorum.push(left.clone());
    quorum.sort_by_key(|attestation| attestation.body().attestor_id());
    let mut reversed = quorum.clone();
    reversed.reverse();
    assert_eq!(
        AvailabilityCertificateV1::build(
            &fixture.committee,
            left_batch.envelope().clone(),
            author.clone(),
            reversed,
        )
        .expect_err("certificate signer order is canonical")
        .code(),
        DaErrorCodeV1::Conflict
    );
    let duplicate = vec![quorum[0].clone(), quorum[0].clone(), quorum[1].clone()];
    assert_eq!(
        AvailabilityCertificateV1::build(
            &fixture.committee,
            left_batch.envelope().clone(),
            author.clone(),
            duplicate,
        )
        .expect_err("duplicate signer is rejected before weight")
        .code(),
        DaErrorCodeV1::Conflict
    );

    let (right_batch, _) = fixture.batch(1, 22);
    let right_body = DaAttestationBodyV1::new(
        right_batch.envelope(),
        right_batch.batch_id(),
        left.body().attestor_id(),
        left.body().attestation_sequence(),
        hash(201),
    );
    let right_signature = fixture.attestors[2]
        .1
        .sign(
            DaAttestationV1::signing_root(&right_body)
                .expect("root")
                .as_bytes(),
        )
        .to_bytes()
        .to_vec();
    let right = DaAttestationV1::from_signature(&fixture.committee, right_body, right_signature)
        .expect("conflicting signed attestation");
    let evidence = AttestorEquivocationEvidenceV1::new(&fixture.committee, left, right)
        .expect("objective signed conflict evidence");
    assert_ne!(evidence.evidence_id().as_bytes(), &[0; 32]);
}

#[test]
fn attestation_and_certificate_reject_foreign_committed_context() {
    let fixture = Fixture::new(4, 16_384);
    let (batch, author) = fixture.batch(1, 41);
    let attestation = fixture.signed_attestation(0, &batch, &author);

    let alternate_context = ProtocolContextV1::new(hash(42), "trnm-da-foreign-context", hash(43))
        .expect("alternate context");
    let alternate_committee = DaCommitteeDescriptorV1::new_transaction_batch(
        alternate_context,
        fixture.committee.epoch(),
        fixture.committee.members().to_vec(),
        fixture.committee.retention_epochs(),
        fixture.committee.max_author_bytes(),
        fixture.committee.max_batch_bytes(),
        fixture.committee.max_batch_items(),
        fixture.committee.max_outstanding_sequences(),
    )
    .expect("alternate committee");
    assert_eq!(
        attestation
            .verify(&alternate_committee)
            .expect_err("attestation context substitution")
            .code(),
        DaErrorCodeV1::InvalidContext
    );
    assert_eq!(
        AvailabilityCertificateV1::build(
            &alternate_committee,
            batch.envelope().clone(),
            author,
            vec![attestation],
        )
        .expect_err("certificate envelope context substitution")
        .code(),
        DaErrorCodeV1::InvalidContext
    );
}

#[test]
fn schema_drift_and_sidecar_are_fail_closed_without_migration() {
    let fixture = Fixture::new(4, 16_384);
    let config = fixture.config(0);
    let store = PocoDaStoreV1::open(config.clone()).expect("store");
    drop(store);
    let connection = Connection::open(config.path()).expect("raw connection");
    connection
        .execute("CREATE TABLE unexpected_v2 (value INTEGER)", [])
        .expect("schema mutation");
    drop(connection);
    let drifted_bytes = std::fs::read(config.path()).expect("drifted bytes");
    assert_eq!(
        PocoDaStoreV1::open(config.clone())
            .expect_err("schema drift")
            .code(),
        DaErrorCodeV1::SchemaMismatch
    );
    assert_eq!(
        std::fs::read(config.path()).expect("post-rejection bytes"),
        drifted_bytes,
        "existing schema rejection must be immutable"
    );

    let missing_config = fixture.config(2);
    let missing_store = PocoDaStoreV1::open(missing_config.clone()).expect("missing-table store");
    drop(missing_store);
    let connection = Connection::open(missing_config.path()).expect("missing-table connection");
    connection
        .execute("DROP TABLE da_attestations_v1", [])
        .expect("drop expected table");
    drop(connection);
    let missing_bytes = std::fs::read(missing_config.path()).expect("missing-table bytes");
    assert_eq!(
        PocoDaStoreV1::open(missing_config.clone())
            .expect_err("missing table must not be rebuilt")
            .code(),
        DaErrorCodeV1::SchemaMismatch
    );
    assert_eq!(
        std::fs::read(missing_config.path()).expect("post-missing rejection bytes"),
        missing_bytes,
        "missing table rejection must not mutate or rebuild the store"
    );

    let sidecar_config = fixture.config(1);
    let sidecar_store = PocoDaStoreV1::open(sidecar_config.clone()).expect("second store");
    drop(sidecar_store);
    let sidecar_path = PathBuf::from(format!("{}-wal", sidecar_config.path().display()));
    std::fs::write(&sidecar_path, b"unresolved").expect("sidecar");
    assert_eq!(
        PocoDaStoreV1::open(sidecar_config)
            .expect_err("unresolved sidecar")
            .code(),
        DaErrorCodeV1::StoreFailure
    );
}

#[test]
fn row_tamper_is_rejected_on_reopen() {
    let fixture = Fixture::new(4, 16_384);
    let (batch, author) = fixture.batch(1, 31);
    let config = fixture.config(0);
    let store = PocoDaStoreV1::open(config.clone()).expect("store");
    store.admit_batch(&batch, &author).expect("admit");
    drop(store);
    let connection = Connection::open(config.path()).expect("raw connection");
    connection
        .execute(
            "UPDATE da_batches_v1 SET content_len=?1 WHERE batch_id=?2",
            params![
                9_999u64.to_le_bytes(),
                batch.batch_id().as_bytes().as_slice()
            ],
        )
        .expect("tamper");
    drop(connection);
    assert_eq!(
        PocoDaStoreV1::open(config)
            .expect_err("tamper on reopen")
            .code(),
        DaErrorCodeV1::TamperDetected
    );

    let accounting_config = fixture.config(1);
    let accounting_store = PocoDaStoreV1::open(accounting_config.clone()).expect("store");
    let (accounting_batch, accounting_author) = fixture.batch(1, 32);
    accounting_store
        .admit_batch(&accounting_batch, &accounting_author)
        .expect("accounting batch");
    drop(accounting_store);
    let connection = Connection::open(accounting_config.path()).expect("raw connection");
    connection
        .execute(
            "UPDATE da_metadata_v1 SET queue_bytes=?1 WHERE singleton=1",
            params![9_999u64.to_le_bytes()],
        )
        .expect("accounting tamper");
    drop(connection);
    assert_eq!(
        PocoDaStoreV1::open(accounting_config)
            .expect_err("queue accounting tamper on reopen")
            .code(),
        DaErrorCodeV1::TamperDetected
    );
}

#[test]
fn open_existing_requires_precreated_regular_nonsymlink_store() {
    let fixture = Fixture::new(4, 16_384);
    let config = fixture.config(0);
    let config_at = |path: PathBuf| {
        DaStoreConfigV1::new(
            path,
            config.scope_id(),
            config.store_id(),
            config.committee().clone(),
            config.policy().clone(),
            config.local_attestor_id(),
        )
        .expect("alternate DA store config")
    };

    assert_eq!(
        PocoDaStoreV1::open_existing(config.clone())
            .expect_err("missing store")
            .code(),
        DaErrorCodeV1::StoreFailure
    );
    assert!(
        !config.path().exists(),
        "strict open must not create a store"
    );

    drop(PocoDaStoreV1::open(config.clone()).expect("create store"));
    drop(PocoDaStoreV1::open_existing(config.clone()).expect("strict reopen"));

    let directory_path = fixture.directory.path().join("not-a-store-file");
    std::fs::create_dir(&directory_path).expect("directory object");
    assert_eq!(
        PocoDaStoreV1::open_existing(config_at(directory_path))
            .expect_err("directory store path")
            .code(),
        DaErrorCodeV1::StoreFailure
    );

    #[cfg(unix)]
    {
        let symlink_path = fixture.directory.path().join("store-link.sqlite");
        std::os::unix::fs::symlink(config.path(), &symlink_path).expect("store symlink");
        assert_eq!(
            PocoDaStoreV1::open_existing(config_at(symlink_path))
                .expect_err("symlink store path")
                .code(),
            DaErrorCodeV1::StoreFailure
        );
    }
}
