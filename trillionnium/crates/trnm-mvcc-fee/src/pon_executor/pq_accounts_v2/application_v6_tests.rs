//! Adversarial integration tests run real ML-DSA and the original M06 owner.
use super::*;
use crate::{pon_executor as exec, public_evaluation as evaluation};
use exec::{BlockExecution, ExecutionControl};
use std::sync::atomic::{AtomicUsize, Ordering};
use trnm_crypto_primitives::{pon_work, qualified_work_task::TaskMaterial};
#[allow(dead_code)]
#[path = "../../../../trnm-protocol/tests/support/native_pq_task_fixture_v5.rs"]
mod fixture;
use fixture::{Key, Witness};

struct Harness {
    cfg: Config,
    state: State,
    height: u64,
    keys: [Key; 4],
}
impl Harness {
    fn new() -> Self {
        let keys = [
            Key::public_test_seed(211),
            Key::public_test_seed(212),
            Key::public_test_seed(213),
            Key::public_test_seed(214),
        ];
        let accounts: Vec<_> = keys
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
                evaluators: BTreeSet::from([keys[1].id, keys[2].id]),
                evaluation_profile: evaluation::PROFILE.into(),
                model_profile: "linear-expert-dev-v1".into(),
            },
        )
        .unwrap();
        Self {
            cfg,
            state,
            height: 0,
            keys,
        }
    }
    fn raw(
        &self,
        account: Hash,
        nonce: u64,
        generation: u64,
        kind: u8,
        payload: &[u8],
        witnesses: &[Witness<'_>],
    ) -> Vec<u8> {
        fixture::signed_for_profile(
            wire::AccountProfile::ApplicationV6,
            &fixture::common(context(&self.cfg).unwrap(), account, nonce, generation),
            kind,
            payload,
            witnesses,
            None,
        )
    }
    fn signed(&self, who: usize, nonce: u64, kind: u8, payload: &[u8]) -> Vec<u8> {
        self.raw(
            self.keys[who].id,
            nonce,
            1,
            kind,
            payload,
            &[fixture::primary(&self.keys[who], 1)],
        )
    }
    fn output(&self, rows: &[Vec<u8>], timestamp: Option<u64>) -> Result<exec::Output> {
        exec::relation_only(exec::execute_with_control(
            &self.state,
            BlockExecution {
                timestamp,
                transactions: rows,
                height: self.height + 1,
                miner: self.keys[0].id,
                parent_id: [self.height as u8; 32],
                workers: 1,
            },
            &self.cfg,
            &ExecutionControl::new(&exec::no_cancellation, &()),
        ))
    }
    fn block(&mut self, rows: Vec<Vec<u8>>) -> usize {
        let output = self.output(&rows, Some(1001 + self.height)).unwrap();
        let proofs = output.metrics.signature_verifications;
        self.state = output.state;
        self.height += 1;
        proofs
    }
    fn until(&mut self, height: u64) {
        while self.height < height {
            self.block(vec![]);
        }
    }
    fn candidate(&self, nonce: u64, artifact: Hash, components: Hash) -> (Hash, Vec<u8>) {
        let parent = [0; 32];
        let round = (self.height + 1) / self.cfg.limit("candidate_round_blocks").unwrap();
        let cid = hash(
            b"contribution-v3",
            &[
                &self.keys[0].id,
                &self.cfg.family,
                &parent,
                &artifact,
                &components,
                &round.to_le_bytes(),
            ],
        );
        let payload = [
            cid.as_slice(),
            &self.cfg.family,
            &parent,
            &artifact,
            &32_u64.to_le_bytes(),
            &components,
            &round.to_le_bytes(),
        ]
        .concat();
        (cid, self.signed(0, nonce, 6, &payload))
    }
    fn evaluation(&self, candidate: Hash) -> Value {
        evaluation::read_evaluation(&self.state, candidate).unwrap()
    }
}

#[test]
fn application_v6_tasks_use_both_current_keys_and_exact_selected_domains() {
    let mut h = Harness::new();
    let chain = context(&h.cfg).unwrap();
    let lease = fixture::lease(chain, h.keys[0].id, h.keys[1].id);
    let open = h.signed(0, 1, 18, &lease.encode().unwrap());
    assert!(
        wire::UnverifiedEnvelope::decode_for_profile(&open, wire::AccountProfile::TasksV5).is_err()
    );
    assert!(h.output(std::slice::from_ref(&open), None).is_err());
    let mut old = fixture::signed(
        &fixture::common(chain, h.keys[0].id, 1, 1),
        18,
        &lease.encode().unwrap(),
        &[fixture::primary(&h.keys[0], 1)],
        None,
    );
    assert_eq!(
        h.output(&[old.clone()], Some(1001)).unwrap_err(),
        "PQ2_ENCODING"
    );
    old[..5].copy_from_slice(b"NPQ6\x06");
    assert!(
        h.output(&[old], Some(1001)).is_err(),
        "changing only magic cannot change signed domains"
    );
    assert_eq!(h.block(vec![open]), 1);
    let (model, input, a, b) = fixture::material();
    let task = pon_work::task_id(&a, &b).unwrap();
    let registration = fixture::registration(&lease, task, 1, [0; 32]);
    let raw = h.raw(
        h.keys[0].id,
        2,
        1,
        21,
        &registration.encode().unwrap(),
        &[
            fixture::primary(&h.keys[0], 1),
            fixture::source(&h.keys[1], 1),
        ],
    );
    assert_eq!(h.block(vec![raw.clone()]), 2);
    let attempts = AtomicUsize::new(0);
    let (_, admission) = tasks_v5::admit_material_metered(
        &h.state,
        task,
        3,
        &h.cfg,
        TaskMaterial {
            model: &model,
            input: &input,
            a: &a,
            b: &b,
        },
        &attempts,
    )
    .unwrap();
    assert_eq!(admission.matrix_task(), task);
    assert_eq!(
        attempts.load(Ordering::Relaxed),
        4,
        "both eligibility and material owners reverify two roles"
    );
    let wrong = h.raw(
        h.keys[0].id,
        2,
        1,
        21,
        &registration.encode().unwrap(),
        &[
            fixture::primary(&h.keys[0], 1),
            fixture::source(&h.keys[2], 1),
        ],
    );
    assert!(prepare_signature(&h.state, &wrong, 1003, &h.cfg).is_err());
    assert!(
        trnm_crypto_primitives::qualified_work_task::pq_lifecycle_v5::statement_id(&raw).is_err()
    );
}

#[test]
fn historical_equivocation_survives_rotation_and_retains_bounded_verified_chunks() {
    let mut h = Harness::new();
    let (cid, candidate) = h.candidate(1, [41; 32], [0; 32]);
    h.block(vec![candidate]);
    let round = evaluation::round(&h.evaluation(cid)).unwrap();
    let first = h.signed(1, 1, 14, &[cid.as_slice(), &round, &[51; 32]].concat());
    let second = h.signed(1, 1, 14, &[cid.as_slice(), &round, &[52; 32]].concat());
    h.until(15);
    assert_eq!(h.block(vec![first.clone()]), 1);
    let rotation_payload = [
        2_u64.to_be_bytes().as_slice(),
        &authority_digest(&h.state, h.keys[1].id, &h.cfg).unwrap(),
    ]
    .concat();
    let rotation = h.raw(
        h.keys[1].id,
        2,
        1,
        wire::ROTATE,
        &rotation_payload,
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
    assert!(
        prepare_signature(&h.state, &second, 1018, &h.cfg).is_err(),
        "retired spending is closed"
    );
    let evidence = [
        cid.as_slice(),
        &(first.len() as u16).to_le_bytes(),
        &first,
        &(second.len() as u16).to_le_bytes(),
        &second,
    ]
    .concat();
    let dispute = h.signed(0, 2, 16, &evidence);
    assert!(dispute.len() > wire::MAX_BYTES && dispute.len() <= wire::APPLICATION_MAX_BYTES);
    assert_eq!(h.block(vec![dispute]), 3);
    let full = h.evaluation(cid);
    assert_eq!(full["conflicts"].as_object().unwrap().len(), 1);
    assert!(!h
        .state
        .keys()
        .any(|key| key.starts_with("evaluation-disqualified:")));
    let conflict = &full["conflicts"][format!("{}:14", hex::encode(h.keys[1].id))];
    assert_eq!(conflict["round"], full["round"]);
    assert_eq!(conflict["signer_generation"], 1);
    assert_eq!(conflict["scope"], evaluation::pq_storage::CONFLICT_SCOPE);
    assert!(h
        .state
        .iter()
        .all(|(k, v)| k.len() <= 160 && canonical(v).unwrap().len() <= 4096));
    let prefix = evaluation::record_prefix_for(cid, &full).unwrap();
    let chunk = h
        .state
        .keys()
        .find(|key| key.starts_with(&prefix) && key.ends_with(":0000"))
        .unwrap()
        .clone();
    let mut damaged = h.state.clone();
    damaged.get_mut(&chunk).unwrap()["bytes"] = json!("00");
    assert!(evaluation::read_evaluation(&damaged, cid).is_err());
    let mut missing = h.state.clone();
    missing.remove(&chunk);
    assert!(evaluation::read_evaluation(&missing, cid).is_err());
    let mut extra = h.state.clone();
    extra.insert(
        format!("{prefix}f:{}:14:ffff", hex::encode(h.keys[1].id)),
        json!({}),
    );
    assert!(evaluation::read_evaluation(&extra, cid).is_err());
}

#[test]
fn actual_pq_evaluation_release_and_mature_claim_use_original_economic_owner() {
    let mut h = Harness::new();
    let score = 100_u64;
    let (component, component_tx) = h.candidate(1, [61; 32], [0; 32]);
    let allocation = hash(
        b"allocation-leaf",
        &[&component, &h.keys[0].id, &score.to_le_bytes()],
    );
    let (bundle, bundle_tx) = h.candidate(2, [62; 32], allocation);
    h.block(vec![component_tx, bundle_tx]);
    let mut commits = Vec::new();
    let mut reveals = Vec::new();
    for who in [1, 2] {
        for (index, candidate) in [component, bundle].into_iter().enumerate() {
            let value = evaluation::Reveal {
                candidate,
                round: evaluation::round(&h.evaluation(candidate)).unwrap(),
                evaluator: h.keys[who].id,
                plan: h.cfg.plan,
                evidence: [71; 32],
                score,
                salt: [(who + index + 1) as u8; 32],
            };
            let commitment =
                evaluation::reveal_commitment_for(&h.evaluation(candidate), &value).unwrap();
            commits.push(h.signed(
                who,
                1 + index as u64,
                14,
                &[candidate.as_slice(), &value.round, &commitment].concat(),
            ));
            reveals.push(
                h.signed(
                    who,
                    3 + index as u64,
                    15,
                    &[
                        candidate.as_slice(),
                        &value.round,
                        &value.plan,
                        &value.evidence,
                        &score.to_le_bytes(),
                        &value.salt,
                    ]
                    .concat(),
                ),
            );
        }
    }
    h.until(15);
    assert_eq!(h.block(commits), 4);
    h.until(31);
    assert_eq!(h.block(reveals), 4);
    h.until(55);
    assert_eq!(h.evaluation(bundle)["closed"]["status"], "complete-scored");
    let budget = 10_000_u64;
    let parent = [0; 32];
    let release = hash(
        b"release",
        &[
            &parent,
            &bundle,
            &budget.to_le_bytes(),
            &allocation,
            &score.to_le_bytes(),
        ],
    );
    let payload = [
        release.as_slice(),
        &parent,
        &bundle,
        &budget.to_le_bytes(),
        &allocation,
        &score.to_le_bytes(),
        &[1],
        &component,
        &score.to_le_bytes(),
    ]
    .concat();
    let adoption = h.signed(0, 3, 8, &payload);
    assert_eq!(h.block(vec![adoption]), 1);
    assert_eq!(h.state["model:current"], hex::encode(release));
    let maturity = h.state[&format!("release:{}", hex::encode(release))]["maturity"]
        .as_u64()
        .unwrap();
    h.until(maturity - 1);
    let claim = h.signed(
        0,
        4,
        9,
        &[release.as_slice(), &component, &score.to_le_bytes(), &[0]].concat(),
    );
    assert_eq!(h.block(vec![claim]), 1);
    let record = &h.state[&format!("release:{}", hex::encode(release))];
    assert_eq!(record["remaining"], 0);
    assert_eq!(record["claims"][hex::encode(component)], budget);
    assert_eq!(
        h.state[&format!("account:{}", hex::encode(h.keys[0].id))]["nonce"],
        4
    );
}

#[test]
fn invalid_signature_retry_cannot_refill_prefix_verification_capacity() {
    let h = Harness::new();
    let valid = h.signed(
        0,
        1,
        1,
        &[
            h.keys[1].id.as_slice(),
            &1_u64.to_le_bytes(),
            &0_u16.to_be_bytes(),
        ]
        .concat(),
    );
    let mut bad = valid.clone();
    *bad.last_mut().unwrap() ^= 1;
    let control = ExecutionControl::new(&exec::no_cancellation, &());
    let mut prefix = exec::TransactionPrefix::new(
        &h.state,
        exec::PrefixContext {
            timestamp: Some(1001),
            height: 1,
            miner: h.keys[0].id,
            parent_id: [9; 32],
        },
        &h.cfg,
        &control,
    )
    .unwrap();
    for _ in 0..wire::APPLICATION_MAX_VERIFICATIONS {
        assert!(prefix
            .execute_with_commitment_and_control(
                std::slice::from_ref(&bad),
                |state| exec::root_for_config(state, &h.cfg),
                &control
            )
            .is_err());
    }
    assert_eq!(prefix.len(), 0);
    let error = exec::relation_only(prefix.execute_with_commitment_and_control(
        &[valid],
        |state| exec::root_for_config(state, &h.cfg),
        &control,
    ))
    .unwrap_err();
    assert_eq!(error, "PQ_VERIFY_BUDGET");
    assert_eq!(
        h.state[&format!("account:{}", hex::encode(h.keys[0].id))]["nonce"],
        0
    );
}

#[test]
fn resource_preflight_counts_inner_proofs_and_underpriced_commands_do_no_crypto() {
    let h = Harness::new();
    let first = h.signed(1, 1, 14, &[[1; 32].as_slice(), &[2; 32], &[3; 32]].concat());
    let second = h.signed(1, 1, 14, &[[1; 32].as_slice(), &[2; 32], &[4; 32]].concat());
    let payload = [
        [1; 32].as_slice(),
        &(first.len() as u16).to_le_bytes(),
        &first,
        &(second.len() as u16).to_le_bytes(),
        &second,
    ]
    .concat();
    let raw = h.signed(0, 1, 16, &payload);
    assert_eq!(
        decode_for_config(&raw, &h.cfg)
            .unwrap()
            .verification_count(),
        3
    );
    assert!(validate_block(
        &h.state,
        &vec![raw.clone(); 21],
        h.keys[0].id,
        Some(1001),
        &h.cfg
    )
    .is_ok());
    assert_eq!(
        validate_block(&h.state, &vec![raw; 22], h.keys[0].id, Some(1001), &h.cfg).unwrap_err(),
        "PQ_VERIFY_BUDGET"
    );
    let mut common = fixture::common(context(&h.cfg).unwrap(), h.keys[0].id, 1, 1);
    common.max_fee = 1;
    let underpriced = fixture::signed_for_profile(
        wire::AccountProfile::ApplicationV6,
        &common,
        1,
        &[
            h.keys[1].id.as_slice(),
            &1_u64.to_le_bytes(),
            &0_u16.to_be_bytes(),
        ]
        .concat(),
        &[fixture::primary(&h.keys[0], 1)],
        None,
    );
    let attempts = AtomicUsize::new(0);
    assert!(matches!(
        prepare_signature_metered(&h.state, &underpriced, 1001, &h.cfg, &attempts),
        Err("FEE")
    ));
    assert_eq!(attempts.load(Ordering::Relaxed), 0);
    let mut changed = h.cfg.clone();
    changed.params["max_pq_verifications"] = json!(u64::MAX);
    assert!(validate_state(&h.state, &changed).is_err());
}

#[path = "application_v6_scope_tests.rs"]
mod scope_tests;
