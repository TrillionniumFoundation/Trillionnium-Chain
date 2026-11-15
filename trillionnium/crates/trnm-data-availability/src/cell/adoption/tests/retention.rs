use super::*;

fn observed(f: &mut Fixture, evidence: u8) -> CellCandidateObservationV1 {
    f.owner
        .observe_candidate(
            &f.candidate,
            Some(f.anchor.commitment()),
            CellCandidateEvidenceV1 {
                evaluation: Some([evidence; 64]),
                ..Default::default()
            },
        )
        .unwrap()
}

#[test]
fn proposal_retention_preserves_v1_target_and_binds_the_separate_proposal() {
    let mut f = setup();
    let before = bootstrap(&mut f);
    let proposal = observed(&mut f, 11);

    // A raw V1 Retain still targets the selected parent, never the new proposal.
    assert!(f
        .owner
        .decide(
            [2; 32],
            &before,
            CellAdoptionActionV1::Retain,
            proposal.candidate,
            [72; 64],
        )
        .is_err());
    assert_eq!(f.owner.snapshot().unwrap(), before);
    let retained = f
        .owner
        .retain_proposal([2; 32], &before, &proposal, [72; 64])
        .unwrap();
    let inner = retained.retention_receipt();
    assert_eq!(retained.proposal(), &proposal);
    assert_eq!(retained.local_review_commitment(), [72; 64]);
    assert_ne!(inner.review_commitment(), [72; 64]);
    assert_eq!(inner.action(), CellAdoptionActionV1::Retain);
    assert_eq!(inner.candidate(), f.anchor.commitment());
    assert_eq!(inner.before(), &before);
    assert_eq!(inner.after().selected(), before.selected());
    assert_eq!(inner.after().revision(), before.revision() + 1);
    assert_ne!(inner.after().history_digest(), before.history_digest());

    let called = Cell::new(false);
    assert!(f
        .owner
        .with_selected_guard(inner.after(), &f.candidate, &execution(), || {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
    f.owner
        .with_selected_guard(inner.after(), &f.anchor, &execution(), || {
            called.set(true);
            Ok(())
        })
        .unwrap();
    assert!(called.get());
}

#[test]
fn proposal_retention_exact_retry_survives_new_evidence_cold_open_and_later_choice() {
    let mut f = setup();
    let before = bootstrap(&mut f);
    let proposal = observed(&mut f, 11);
    let retained = f
        .owner
        .retain_proposal([2; 32], &before, &proposal, [72; 64])
        .unwrap();
    let floor = retained.retention_receipt().after().clone();
    let additional = observed(&mut f, 12);
    assert_ne!(additional.evidence, proposal.evidence);
    drop(f.owner);
    let mut owner = CellAdoptionOwnerV1::open(&f.path, &f.policy, &floor).unwrap();
    assert_eq!(
        owner
            .retain_proposal([2; 32], &before, &proposal, [72; 64])
            .unwrap(),
        retained
    );
    assert_eq!(owner.snapshot().unwrap(), floor);
    let adopted = owner
        .decide(
            [3; 32],
            &floor,
            CellAdoptionActionV1::Adopt,
            f.candidate.commitment(),
            [73; 64],
        )
        .unwrap();
    assert_eq!(
        owner
            .retain_proposal([2; 32], &before, &proposal, [72; 64])
            .unwrap(),
        retained
    );
    assert_eq!(owner.snapshot().unwrap(), *adopted.after());
    let called = Cell::new(false);
    assert!(owner
        .with_selected_guard(&floor, &f.anchor, &execution(), || {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
}

#[test]
fn proposal_retention_rejects_unknown_unobserved_current_and_wrong_parent() {
    let mut f = setup();
    let before = bootstrap(&mut f);
    let proposal = observed(&mut f, 11);
    let grandchild = successor(&f.store, &f.candidate, 82);
    let grandchild = f
        .owner
        .observe_candidate(
            &grandchild,
            Some(f.candidate.commitment()),
            CellCandidateEvidenceV1::default(),
        )
        .unwrap();
    for bad in [
        CellCandidateObservationV1 {
            candidate: [99; 64],
            ..proposal.clone()
        },
        CellCandidateObservationV1 {
            evidence: [99; 64],
            ..proposal.clone()
        },
        CellCandidateObservationV1 {
            parent: None,
            ..proposal.clone()
        },
        CellCandidateObservationV1 {
            candidate: f.anchor.commitment(),
            ..proposal.clone()
        },
        // Even a real retained grandchild is not a proposal from current A.
        grandchild.clone(),
        CellCandidateObservationV1 {
            parent: Some(f.anchor.commitment()),
            ..grandchild
        },
    ] {
        assert!(f
            .owner
            .retain_proposal([2; 32], &before, &bad, [72; 64])
            .is_err());
        assert_eq!(f.owner.snapshot().unwrap(), before);
    }
    let deferred = f
        .owner
        .decide(
            [3; 32],
            &before,
            CellAdoptionActionV1::Defer,
            proposal.candidate,
            [73; 64],
        )
        .unwrap();
    assert!(f
        .owner
        .retain_proposal([2; 32], &before, &proposal, [72; 64])
        .is_err());
    assert_eq!(f.owner.snapshot().unwrap(), *deferred.after());
}

#[test]
fn proposal_retention_idempotence_binds_proposal_evidence_review_and_snapshot() {
    let mut f = setup();
    let before = bootstrap(&mut f);
    let proposal = observed(&mut f, 11);
    let retained = f
        .owner
        .retain_proposal([2; 32], &before, &proposal, [72; 64])
        .unwrap();
    let changed_evidence = observed(&mut f, 12);
    let other = successor(&f.store, &f.anchor, 82);
    let other = f
        .owner
        .observe_candidate(
            &other,
            Some(f.anchor.commitment()),
            CellCandidateEvidenceV1::default(),
        )
        .unwrap();
    // Both alternatives are real retained observations; only operation identity
    // checking, not a missing-candidate/evidence refusal, distinguishes them.
    for changed in [changed_evidence, other] {
        let error = f
            .owner
            .retain_proposal([2; 32], &before, &changed, [72; 64])
            .unwrap_err();
        assert!(error.to_string().contains("request identity conflict"));
    }
    for (snapshot, review) in [
        (&before, [73; 64]),
        (retained.retention_receipt().after(), [72; 64]),
    ] {
        let error = f
            .owner
            .retain_proposal([2; 32], snapshot, &proposal, review)
            .unwrap_err();
        assert!(error.to_string().contains("request identity conflict"));
    }
    for (request, review) in [([0; 32], [72; 64]), ([3; 32], [0; 64])] {
        assert!(f
            .owner
            .retain_proposal(request, &before, &proposal, review)
            .is_err());
    }
    let mut foreign = before.clone();
    foreign.policy = [99; 64];
    assert!(f
        .owner
        .retain_proposal([3; 32], &foreign, &proposal, [72; 64])
        .is_err());
    assert_eq!(
        f.owner.snapshot().unwrap(),
        *retained.retention_receipt().after()
    );
}

#[test]
fn proposal_retention_keeps_original_atomicity_and_lost_reply_reconciliation() {
    let mut f = setup();
    let before = bootstrap(&mut f);
    let proposal = observed(&mut f, 11);
    BEFORE_COMMIT.set(true);
    assert!(f
        .owner
        .retain_proposal([2; 32], &before, &proposal, [72; 64])
        .is_err());
    assert_eq!(f.owner.snapshot().unwrap(), before);
    let first = f
        .owner
        .retain_proposal([2; 32], &before, &proposal, [72; 64])
        .unwrap();
    let before = first.retention_receipt().after().clone();
    AFTER_COMMIT.set(true);
    assert!(f
        .owner
        .retain_proposal([3; 32], &before, &proposal, [73; 64])
        .is_err());
    let committed = f.owner.snapshot().unwrap();
    assert_eq!(committed.revision(), before.revision() + 1);
    let recovered = f
        .owner
        .retain_proposal([3; 32], &before, &proposal, [73; 64])
        .unwrap();
    assert_eq!(recovered.retention_receipt().after(), &committed);
    assert_eq!(f.owner.snapshot().unwrap(), committed);
}

#[test]
fn proposal_retention_journal_tampering_refuses_recovery_and_consumer() {
    let mut f = setup();
    let before = bootstrap(&mut f);
    let proposal = observed(&mut f, 11);
    let retained = f
        .owner
        .retain_proposal([2; 32], &before, &proposal, [72; 64])
        .unwrap();
    let floor = retained.retention_receipt().after().clone();
    let connection = rusqlite::Connection::open(&f.path).unwrap();
    let mut request: Vec<u8> = connection
        .query_row(
            "SELECT request FROM adoption_decisions WHERE revision=2",
            [],
            |row| row.get(0),
        )
        .unwrap();
    *request.last_mut().unwrap() ^= 1;
    connection
        .execute(
            "UPDATE adoption_decisions SET request=?1 WHERE revision=2",
            rusqlite::params![request],
        )
        .unwrap();
    drop(connection);
    assert!(f
        .owner
        .retain_proposal([2; 32], &before, &proposal, [72; 64])
        .is_err());
    let called = Cell::new(false);
    assert!(f
        .owner
        .with_selected_guard(&floor, &f.anchor, &execution(), || {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
    drop(f.owner);
    assert!(CellAdoptionOwnerV1::open(&f.path, &f.policy, &floor).is_err());
}

#[test]
fn legacy_retention_does_not_gain_a_proposal_binding_on_retry() {
    let mut f = setup();
    let before = bootstrap(&mut f);
    let proposal = observed(&mut f, 11);
    let legacy = f
        .owner
        .decide(
            [2; 32],
            &before,
            CellAdoptionActionV1::Retain,
            f.anchor.commitment(),
            [72; 64],
        )
        .unwrap();
    let error = f
        .owner
        .retain_proposal([2; 32], &before, &proposal, [72; 64])
        .unwrap_err();
    assert!(error.to_string().contains("request identity conflict"));
    assert_eq!(f.owner.snapshot().unwrap(), *legacy.after());
}

#[test]
fn proposal_removal_refuses_typed_replay_without_reinterpreting_legacy_history() {
    let mut f = setup();
    let before = bootstrap(&mut f);
    let proposal = observed(&mut f, 11);
    let retained = f
        .owner
        .retain_proposal([2; 32], &before, &proposal, [72; 64])
        .unwrap();
    let floor = retained.retention_receipt().after().clone();
    drop(f.owner);
    let connection = rusqlite::Connection::open(&f.path).unwrap();
    connection
        .execute(
            "DELETE FROM adoption_observations WHERE candidate=?1",
            rusqlite::params![proposal.candidate.as_slice()],
        )
        .unwrap();
    connection
        .execute(
            "DELETE FROM adoption_candidates WHERE commitment=?1",
            rusqlite::params![proposal.candidate.as_slice()],
        )
        .unwrap();
    drop(connection);
    // The unchanged legacy history still means Retain(parent). It cannot
    // recover or authenticate a proposal from an opaque review commitment.
    let mut owner = CellAdoptionOwnerV1::open(&f.path, &f.policy, &floor).unwrap();
    assert_eq!(owner.snapshot().unwrap(), floor);
    let error = owner
        .retain_proposal([2; 32], &before, &proposal, [72; 64])
        .unwrap_err();
    assert!(error.to_string().contains("proposal missing"));
    assert_eq!(owner.snapshot().unwrap(), floor);
}

#[test]
fn matching_raw_retention_does_not_attest_historical_typed_validation() {
    let mut f = setup();
    let before = bootstrap(&mut f);
    let evidence = CellCandidateEvidenceV1 {
        evaluation: Some([11; 64]),
        ..Default::default()
    };
    let proposal = CellCandidateObservationV1 {
        candidate: f.candidate.commitment(),
        parent: Some(f.anchor.commitment()),
        evidence: evidence.commitment(),
    };
    let bound =
        super::super::types::proposal_retention_review([2; 32], &before, &proposal, [72; 64])
            .unwrap();
    // The trusted raw API can commit this digest before any proposal observation.
    let raw = f
        .owner
        .decide(
            [2; 32],
            &before,
            CellAdoptionActionV1::Retain,
            f.anchor.commitment(),
            bound,
        )
        .unwrap();
    assert!(f
        .owner
        .retain_proposal([2; 32], &before, &proposal, [72; 64])
        .is_err());
    let observed = f
        .owner
        .observe_candidate(&f.candidate, proposal.parent, evidence)
        .unwrap();
    assert_eq!(observed, proposal);
    let typed = f
        .owner
        .retain_proposal([2; 32], &before, &proposal, [72; 64])
        .unwrap();
    assert_eq!(typed.retention_receipt(), &raw);
    assert_eq!(typed.proposal(), &proposal);
    assert_eq!(f.owner.snapshot().unwrap(), *raw.after());
}
