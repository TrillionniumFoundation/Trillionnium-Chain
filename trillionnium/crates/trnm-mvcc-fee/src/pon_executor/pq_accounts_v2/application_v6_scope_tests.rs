//! Historical signatures establish a frozen-round conflict, never a signing
//! time or a permanent penalty on the stable account after key rotation.
use super::*;

fn dispute(h: &Harness, candidate: Hash, who: usize) -> Vec<u8> {
    let round = evaluation::round(&h.evaluation(candidate)).unwrap();
    let first = h.signed(
        who,
        1,
        14,
        &[candidate.as_slice(), &round, &[91; 32]].concat(),
    );
    let second = h.signed(
        who,
        1,
        14,
        &[candidate.as_slice(), &round, &[92; 32]].concat(),
    );
    let payload = [
        candidate.as_slice(),
        &(first.len() as u16).to_le_bytes(),
        &first,
        &(second.len() as u16).to_le_bytes(),
        &second,
    ]
    .concat();
    let nonce = h.state[&format!("account:{}", hex::encode(h.keys[0].id))]["nonce"]
        .as_u64()
        .unwrap()
        + 1;
    h.signed(0, nonce, 16, &payload)
}

fn vote_pair(
    h: &Harness,
    candidate: Hash,
    account: usize,
    key: usize,
    generation: u64,
    nonce: u64,
) -> (Vec<u8>, Vec<u8>) {
    let value = evaluation::Reveal {
        candidate,
        round: evaluation::round(&h.evaluation(candidate)).unwrap(),
        evaluator: h.keys[account].id,
        plan: h.cfg.plan,
        evidence: [75; 32],
        score: 100,
        salt: [account as u8; 32],
    };
    let commitment = evaluation::reveal_commitment_for(&h.evaluation(candidate), &value).unwrap();
    let witnesses = [fixture::primary(&h.keys[key], generation)];
    let commit = h.raw(
        value.evaluator,
        nonce,
        generation,
        14,
        &[candidate.as_slice(), &value.round, &commitment].concat(),
        &witnesses,
    );
    let reveal = h.raw(
        value.evaluator,
        nonce + 1,
        generation,
        15,
        &[
            candidate.as_slice(),
            &value.round,
            &value.plan,
            &value.evidence,
            &value.score.to_le_bytes(),
            &value.salt,
        ]
        .concat(),
        &witnesses,
    );
    (commit, reveal)
}

#[test]
fn retired_key_newly_signed_old_evidence_cannot_poison_new_generation_round() {
    let mut h = Harness::new();
    let (old, candidate) = h.candidate(1, [81; 32], [0; 32]);
    h.block(vec![candidate]);
    let rotation = h.raw(
        h.keys[1].id,
        1,
        1,
        wire::ROTATE,
        &[
            2_u64.to_be_bytes().as_slice(),
            &authority_digest(&h.state, h.keys[1].id, &h.cfg).unwrap(),
        ]
        .concat(),
        &[
            Witness {
                key: &h.keys[1],
                role: 3,
                generation: 1,
                carried: false,
            },
            Witness {
                key: &h.keys[3],
                role: 4,
                generation: 2,
                carried: true,
            },
        ],
    );
    h.block(vec![rotation]);
    h.until(128);
    let (new, candidate) = h.candidate(2, [82; 32], [0; 32]);
    h.block(vec![candidate]);
    // Both inner statements are created only now, after retirement, for an
    // archived old round. There is deliberately no invented trusted timestamp.
    let forged_time_claim = dispute(&h, old, 1);
    assert_eq!(h.block(vec![forged_time_claim]), 3);
    assert!(!h
        .state
        .keys()
        .any(|key| key.starts_with("evaluation-disqualified:")));
    let old_evaluation = h.evaluation(old);
    assert_eq!(old_evaluation["conflicts"].as_object().unwrap().len(), 1);
    assert!(evaluation::adoption_allowed(&old_evaluation, 184).is_err());
    assert_eq!(
        application_v6::frozen_generation(&h.evaluation(new), h.keys[1].id).unwrap(),
        2
    );
    let (commit1, reveal1) = vote_pair(&h, new, 1, 3, 2, 2);
    let (commit2, reveal2) = vote_pair(&h, new, 2, 2, 1, 1);
    h.until(143);
    assert_eq!(h.block(vec![commit1, commit2]), 2);
    h.until(159);
    assert_eq!(h.block(vec![reveal1, reveal2]), 2);
    h.until(183);
    let new_evaluation = h.evaluation(new);
    assert_eq!(new_evaluation["closed"]["status"], "complete-scored");
    assert!(evaluation::adoption_allowed(&new_evaluation, 184).is_ok());
    assert!(new_evaluation["conflicts"].as_object().unwrap().is_empty());
}

#[test]
fn same_generation_other_round_is_live_but_conflicted_round_cannot_vote() {
    let mut h = Harness::new();
    let (old, a) = h.candidate(1, [83; 32], [0; 32]);
    let (other, b) = h.candidate(2, [84; 32], [0; 32]);
    h.block(vec![a, b]);
    let evidence = dispute(&h, old, 1);
    h.block(vec![evidence]);
    let conflicted = h.evaluation(old);
    assert_ne!(conflicted["round"], h.evaluation(other)["round"]);
    let (blocked, _) = vote_pair(&h, old, 1, 1, 1, 1);
    let (commit1, reveal1) = vote_pair(&h, other, 1, 1, 1, 1);
    let (commit2, reveal2) = vote_pair(&h, other, 2, 2, 1, 1);
    h.until(15);
    assert_eq!(
        h.output(&[blocked], Some(1016)).unwrap_err(),
        "PUBLIC_EVAL_DISQUALIFIED"
    );
    h.block(vec![commit1, commit2]);
    h.until(31);
    h.block(vec![reveal1, reveal2]);
    h.until(55);
    assert!(evaluation::adoption_allowed(&h.evaluation(old), 56).is_err());
    assert!(evaluation::adoption_allowed(&h.evaluation(other), 56).is_ok());

    let key = format!("{}:14", hex::encode(h.keys[1].id));
    for (field, bad) in [
        ("scope", json!("stable-account-permanent")),
        ("signer_generation", json!(2)),
        ("round", h.evaluation(other)["round"].clone()),
        ("candidate", json!(hex::encode(other))),
    ] {
        let mut changed = conflicted.clone();
        changed["conflicts"][&key][field] = bad;
        assert!(evaluation::record_rows(old, &changed).is_err(), "{field}");
    }
    let mut changed = h.evaluation(other);
    let expected = evaluation::expected_round(&changed).unwrap();
    changed["plan"]["pq_conflict_scope"] = json!("stable-account-permanent");
    assert!(evaluation::round(&changed).is_err());
    assert!(evaluation::expected_round(&changed).is_err());
    let mut committed = h.evaluation(other);
    committed["plan"]["pq_generations"][0] = json!(2);
    assert_ne!(evaluation::expected_round(&committed).unwrap(), expected);
    assert!(evaluation::round(&committed).is_err());
}

#[test]
fn late_round_conflict_blocks_unexecuted_adoption_without_rewriting_closure() {
    let mut h = Harness::new();
    let (candidate, command) = h.candidate(1, [85; 32], [0; 32]);
    h.block(vec![command]);
    let (commit1, reveal1) = vote_pair(&h, candidate, 1, 1, 1, 1);
    let (commit2, reveal2) = vote_pair(&h, candidate, 2, 2, 1, 1);
    h.until(15);
    h.block(vec![commit1, commit2]);
    h.until(31);
    h.block(vec![reveal1, reveal2]);
    h.until(55);
    let before = h.evaluation(candidate);
    assert!(evaluation::adoption_allowed(&before, 56).is_ok());
    let evidence = dispute(&h, candidate, 1);
    h.block(vec![evidence]);
    let after = h.evaluation(candidate);
    assert_eq!(before["closed"], after["closed"]);
    assert_eq!(
        evaluation::closed_digest(&before).unwrap(),
        evaluation::closed_digest(&after).unwrap()
    );
    assert!(evaluation::adoption_allowed(&after, 56).is_err());
    assert!(!h
        .state
        .keys()
        .any(|key| key.starts_with("evaluation-disqualified:")));
}

#[test]
fn pq_quorum_ignores_cross_round_bans_but_keeps_its_frozen_denominator() {
    let mut h = Harness::new();
    let accounts: Vec<_> = h
        .keys
        .iter()
        .map(|key| GenesisAccount {
            spki: key.spki.clone(),
            balance: 100_000_000,
        })
        .collect();
    let (cfg, state, _) = application_v6::genesis(
        &accounts,
        1000,
        &application_v6::ApplicationPolicy {
            evaluators: BTreeSet::from([h.keys[1].id, h.keys[2].id, h.keys[3].id]),
            evaluation_profile: evaluation::QUORUM_PROFILE.into(),
            model_profile: crate::model_evidence_v3::PROFILE.into(),
        },
    )
    .unwrap();
    h.cfg = cfg;
    h.state = state;
    let candidate = [86; 32];
    let all_global = h.cfg.evaluators.clone();
    let mut contribution = json!({
        "owner": hex::encode(h.keys[0].id),
        "artifact": hex::encode([87; 32]),
        "components_root": hex::encode([0; 32]),
        "parent": hex::encode([0; 32])
    });
    contribution["public_evaluation"] =
        evaluation::freeze(&h.cfg, candidate, &contribution, 1, &all_global).unwrap();
    application_v6::pin_evaluators(&mut View::new(&h.state, None), &mut contribution, &h.cfg)
        .unwrap();
    h.state.insert(
        format!("contribution:{}", hex::encode(candidate)),
        contribution,
    );
    let mut evaluated = h.evaluation(candidate);
    assert_eq!(evaluated["plan"]["disqualified_at_freeze"], json!([]));
    assert_eq!(evaluated["plan"]["quorum"], 2);
    // Exercise the evaluation state machine directly; the conflict below still
    // comes from three real M01 verifications, not a fabricated proof object.
    for who in [1, 2] {
        let value = evaluation::Reveal {
            candidate,
            round: evaluation::round(&evaluated).unwrap(),
            evaluator: h.keys[who].id,
            plan: h.cfg.plan,
            evidence: [88; 32],
            score: 100,
            salt: [who as u8; 32],
        };
        let commitment = evaluation::reveal_commitment_for(&evaluated, &value).unwrap();
        evaluation::commit(
            &mut evaluated,
            &hex::encode(value.evaluator),
            value.round,
            commitment,
            16,
        )
        .unwrap();
        evaluation::reveal(&mut evaluated, value, 32).unwrap();
    }
    let mut closed_before_conflict = evaluated.clone();
    assert_eq!(
        evaluation::close_with_disqualified(&mut closed_before_conflict, 48, &all_global).unwrap(),
        Some(100)
    );
    assert!(evaluation::adoption_allowed_with_disqualified(
        &closed_before_conflict,
        56,
        &all_global
    )
    .is_ok());
    let raw = dispute(&h, candidate, 1);
    let attempts = AtomicUsize::new(0);
    let prepared = prepare_signature_metered(&h.state, &raw, 1001, &h.cfg, &attempts).unwrap();
    assert_eq!(attempts.load(Ordering::Relaxed), 3);
    let (first, second) = wire::conflict_evidence(prepared.payload()).unwrap();
    let proof = prepared.conflict.as_ref().unwrap();
    evaluation::conflict_pq(&mut evaluated, &h.cfg, candidate, first, second, proof).unwrap();
    let round = evaluation::round(&evaluated).unwrap();
    assert_eq!(
        evaluation::commit(
            &mut evaluated,
            &hex::encode(h.keys[1].id),
            round,
            [89; 32],
            17
        )
        .unwrap_err(),
        "PUBLIC_EVAL_DISQUALIFIED"
    );
    assert_eq!(
        evaluation::close_with_disqualified(&mut evaluated, 48, &all_global).unwrap(),
        None
    );
    assert_eq!(evaluated["closed"]["quorum"], 2);
    assert_eq!(evaluated["closed"]["eligible_reveal_count"], 1);
    assert_eq!(evaluated["closed"]["disqualified_count_before_close"], 1);
    assert_eq!(evaluated["closed"]["status"], "aborted");
    let closure = closed_before_conflict["closed"].clone();
    evaluation::conflict_pq(
        &mut closed_before_conflict,
        &h.cfg,
        candidate,
        first,
        second,
        proof,
    )
    .unwrap();
    assert_eq!(closed_before_conflict["closed"], closure);
    assert!(evaluation::adoption_allowed_with_disqualified(
        &closed_before_conflict,
        56,
        &all_global
    )
    .is_err());
}
