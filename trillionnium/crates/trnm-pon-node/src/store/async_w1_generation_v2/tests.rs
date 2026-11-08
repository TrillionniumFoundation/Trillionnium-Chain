//! Unexecuted integration-test candidate. Native signatures, escrow, blocks,
//! branch changes and payment readback are REAL Node operations. TestRuntime is
//! an explicit verifier/runtime FIXTURE: these tests establish no fresh proof,
//! cryptographic verifier qualification, process ownership or timing result.
use super::super::StateBackend;
use super::*;
use crate::development_public;
use serde_json::json;
use std::path::Path;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::continuity_v1;
use trnm_protocol::pon_wire::{hash, Envelope};
use trnm_service_settlement::native_generation_budget_v2::{
    ConfigurationV2, DispatchDecisionV2, GenerationLaneV2, NativeGenerationStoreV2,
    OriginalDeadlineV2,
};

// These helpers are the same actual owner path used by b6 store/funding/tests.rs.
fn public(who: u64) -> Hash {
    development_public(who).unwrap()
}
fn settings(backend: StateBackend) -> crate::Settings {
    let base = crate::Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    if backend == StateBackend::PermanentAccountGrowthV2 {
        base.with_permanent_account_growth_v2("native-budget-bridge-v2")
            .unwrap()
    } else {
        base
    }
}
fn open(path: &Path, backend: StateBackend) -> Node {
    match backend {
        StateBackend::Legacy => Node::open(path, settings(backend), 1).unwrap(),
        StateBackend::AuthenticatedV1 => {
            Node::open_with_authenticated_state(path, settings(backend), 1).unwrap()
        }
        StateBackend::PermanentAccountGrowthV2 => {
            Node::open_with_permanent_account_growth_v2(path, settings(backend)).unwrap()
        }
        _ => panic!("an independently pinned PQ owner fixture is required"),
    }
}
fn signed(s: &crate::Settings, sender: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = Envelope {
        network: s.network(),
        sender: public(sender),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let key = signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&sender.to_le_bytes()],
    )))
    .unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn mine(n: &mut Node, parent: Hash, transactions: Vec<Vec<u8>>) -> Hash {
    let height = n.record(parent).unwrap().height + 1;
    let id = if n.state_backend == StateBackend::PermanentAccountGrowthV2 {
        let p = n
            .make_growth_consensus_maintenance(
                parent,
                transactions,
                public(3),
                1 + height * 10,
                4096,
            )
            .unwrap();
        n.admit_growth(&p, 100_000).unwrap()
    } else {
        let p = n
            .make_consensus_maintenance(parent, transactions, public(3), 1 + height * 10, 4096)
            .unwrap();
        n.admit(&p, 100_000).unwrap()
    };
    n.activate(id).unwrap();
    id
}
fn reject(n: &mut Node, parent: Hash, transaction: Vec<u8>) {
    let height = n.record(parent).unwrap().height + 1;
    if n.state_backend == StateBackend::PermanentAccountGrowthV2 {
        assert!(n
            .make_growth_consensus_maintenance(
                parent,
                vec![transaction],
                public(3),
                1 + height * 10,
                4096
            )
            .is_err());
    } else {
        assert!(n
            .make_consensus_maintenance(parent, vec![transaction], public(3), 1 + height * 10, 4096)
            .is_err());
    }
}
fn reserve(s: &crate::Settings) -> (Hash, Vec<u8>) {
    let task = hash(
        b"task-instance-v3",
        &[
            &s.network(),
            &s.parameters(),
            &public(0),
            &1u64.to_le_bytes(),
            &public(1),
            &1000u64.to_le_bytes(),
            &20u64.to_le_bytes(),
        ],
    );
    let mut payload = task.to_vec();
    payload.extend(public(1));
    payload.extend(1000u64.to_le_bytes());
    payload.extend(20u64.to_le_bytes());
    (task, signed(s, 0, 1, 2, payload))
}
fn balance(n: &Node, who: Hash) -> u64 {
    if n.state_backend == StateBackend::PermanentAccountGrowthV2 {
        n.growth_account(n.active().unwrap().0, who)
            .unwrap()
            .unwrap()
            .balance
    } else {
        n.read_active().unwrap().2[&format!("account:{}", hex::encode(who))]["balance"]
            .as_u64()
            .unwrap()
    }
}
fn configuration(n: &Node) -> ConfigurationV2 {
    ConfigurationV2 {
        network: n.settings.network(),
        parameters: n.settings.parameters(),
        genesis: n.settings.genesis(),
        max_records: 16,
    }
}
fn statement(task: Hash) -> GenerationStatementV2 {
    GenerationStatementV2 {
        lane: GenerationLaneV2::FullW1ProofGeneration,
        task,
        owner: public(0),
        provider: public(1),
        input_sha256: [1; 32],
        header_sha256: sha256(b"HEADER-FIXTURE"),
        expected_artifacts_sha256: sha256(&[2; 64]),
        expected_journal_sha256: [3; 32],
        expected_work_id: [4; 32],
        image_id: [5; 8],
        guest_sha256: [6; 32],
        verifier_binary_sha256: [7; 32],
        execution_source_commitment: [8; 32],
        original_deadline: OriginalDeadlineV2 {
            clock_domain: [9; 32],
            winner_ns: 100,
            deadline_ns: 10000,
        },
        chain_deadline: 20,
        provider_namespace: [10; 32],
        provider_operation: [11; 32],
        request_digest: [12; 32],
        resource_cap: GenerationResourcesV2 {
            cpu_ns: 1000,
            gpu_ns: 1000,
            memory_peak_upper_bound_bytes: 4096,
            receipt_bytes: 4096,
        },
    }
}
fn job(s: &GenerationStatementV2) -> ProviderJobV2 {
    ProviderJobV2 {
        provider_namespace: s.provider_namespace,
        operation: s.provider_operation,
        request_digest: s.request_digest,
        job_id: "TRUSTED-RUNTIME-FIXTURE-NOT-A-REAL-PROVIDER".into(),
    }
}
fn evidence() -> GenerationEvidenceV2<'static> {
    GenerationEvidenceV2 {
        receipt: b"TEST-FIXTURE-NOT-A-VALID-ZKVM-RECEIPT",
        header: b"HEADER-FIXTURE",
        expected_artifacts: &[2; 64],
        owned_execution_evidence: [13; 32],
    }
}
struct TestRuntime {
    corrupt_profile: bool,
    cancel_after_receipt: bool,
}
impl OwnedGenerationRuntimeV2 for TestRuntime {
    fn clock_checkpoint(&mut self) -> Result<ClockCheckpointV2> {
        Ok(ClockCheckpointV2 {
            clock_domain: [9; 32],
            now_ns: 200,
        })
    }
    fn reconcile_fresh_execution(
        &mut self,
        s: &GenerationStatementV2,
        j: &ProviderJobV2,
        e: &GenerationEvidenceV2<'_>,
    ) -> Result<OwnedFullGenerationV2> {
        // Deliberate trusted-owner fixture: no provider freshness claim is made.
        check(!self.cancel_after_receipt, "UNIT_TEST_RUNTIME_CANCELLATION")?;
        Ok(OwnedFullGenerationV2 {
            job: j.clone(),
            execution_source_commitment: s.execution_source_commitment,
            input_sha256: s.input_sha256,
            guest_sha256: s.guest_sha256,
            evidence_digest: e.owned_execution_evidence,
            receipt_sha256: sha256(e.receipt),
            resources: GenerationResourcesV2 {
                cpu_ns: 100,
                gpu_ns: 0,
                memory_peak_upper_bound_bytes: 100,
                receipt_bytes: e.receipt.len() as u64,
            },
            controller_received: self.clock_checkpoint()?,
        })
    }
    fn run_independent_verifier(
        &mut self,
        s: &GenerationStatementV2,
        e: &GenerationEvidenceV2<'_>,
    ) -> Result<OwnedVerifierRunV2> {
        let value = json!({"schema":"TRNM-W1-V2-FULL-VERIFY1","profile_id":PROFILE,
            "sdk":if self.corrupt_profile {"3.0.5"} else {"3.0.6"},"iterations":1,"independent_proof_trials":1,
            "receipt_bytes":e.receipt.len(),"image_id":s.image_id,"parent_eligibility_checked":false,
            "admission_authorized":false,"receipt_sha256":hex::encode(sha256(e.receipt)),
            "header_sha256":hex::encode(s.header_sha256),"expected_artifacts_sha256":hex::encode(s.expected_artifacts_sha256),
            "journal_sha256":hex::encode(s.expected_journal_sha256),"work_id":hex::encode(s.expected_work_id)});
        Ok(OwnedVerifierRunV2 {
            executable_sha256: s.verifier_binary_sha256,
            successful_exit: true,
            stdout: serde_json::to_vec(&value).unwrap(),
            finished: self.clock_checkpoint()?,
            resources: GenerationResourcesV2 {
                cpu_ns: 10,
                gpu_ns: 0,
                memory_peak_upper_bound_bytes: 10,
                receipt_bytes: 0,
            },
        })
    }
}
fn begin_fixture_verification(
    store: &mut NativeGenerationStoreV2,
    n: &mut Node,
    r: &mut TestRuntime,
    s: &GenerationStatementV2,
) -> Hash {
    let mut owner = NodeGenerationOwnerV2::new(n, r).unwrap();
    let id = store.prepare(&mut owner, s.clone()).unwrap();
    assert!(matches!(
        store.begin(&mut owner, id).unwrap(),
        DispatchDecisionV2::New
    ));
    store.bind_job(id, job(s)).unwrap();
    store.verify(&mut owner, id, &evidence()).unwrap();
    id
}

#[test]
fn real_native_payment_cold_reopen_reorg_and_duplicate_with_explicit_verifier_fixture() {
    for backend in [
        StateBackend::Legacy,
        StateBackend::AuthenticatedV1,
        StateBackend::PermanentAccountGrowthV2,
    ] {
        let d = tempfile::tempdir().unwrap();
        let node_path = d.path().join("node");
        let journal = d.path().join("generation.sqlite");
        let mut n = open(&node_path, backend);
        let config = configuration(&n);
        let settings = n.settings.clone();
        let genesis = settings.genesis();
        let (task, wire) = reserve(&settings);
        let reserved = mine(&mut n, genesis, vec![wire]);
        let s = statement(task);
        let mut store = NativeGenerationStoreV2::open(&journal, config.clone()).unwrap();
        let mut runtime = TestRuntime {
            corrupt_profile: false,
            cancel_after_receipt: false,
        };
        let id = begin_fixture_verification(&mut store, &mut n, &mut runtime, &s);
        let mut payload = task.to_vec();
        payload.extend(id);
        let receipt = mine(
            &mut n,
            reserved,
            vec![signed(&settings, 1, 1, 4, payload.clone())],
        );
        let provider_before_payment = balance(&n, public(1));
        let settle_wire = signed(&settings, 0, 2, 5, payload.clone());
        {
            let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
            assert!(matches!(
                store
                    .prepare_settlement(&mut owner, id, settle_wire.clone())
                    .unwrap(),
                DispatchDecisionV2::New
            ));
        }
        assert!(store.cancel(id, [99; 32]).is_err());
        let settled = mine(&mut n, receipt, vec![settle_wire.clone()]);
        assert_eq!(balance(&n, public(1)), provider_before_payment + 1000);
        // The hard crash gap: ordinary payment executed, local M12 has not recorded it.
        assert!(store.readback(id).unwrap().historical_payment.is_none());
        drop(store);
        drop(n);
        let mut n = open(&node_path, backend);
        let mut store = NativeGenerationStoreV2::open(&journal, config).unwrap();
        store.record_payment(&mut n, id).unwrap();
        let paid = store.readback(id).unwrap();
        store.record_payment(&mut n, id).unwrap();
        assert_eq!(store.readback(id).unwrap(), paid);
        assert_eq!(balance(&n, public(1)), provider_before_payment + 1000);
        // A different valid owner signature/nonce cannot settle the same task again.
        reject(&mut n, settled, signed(&settings, 0, 3, 5, payload));
        assert_eq!(balance(&n, public(1)), provider_before_payment + 1000);
        let f2 = mine(&mut n, reserved, vec![]);
        let f3 = mine(&mut n, f2, vec![]);
        let _f4 = mine(&mut n, f3, vec![]);
        assert!(store.reobserve_payment(&mut n, id).is_err());
        assert_eq!(store.readback(id).unwrap(), paid);
        // A historical Done does not imply current-chain paid or permission to resend.
        {
            let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
            assert!(matches!(
                store
                    .prepare_settlement(&mut owner, id, settle_wire)
                    .unwrap(),
                DispatchDecisionV2::Done
            ));
        }
        let r4 = mine(&mut n, settled, vec![]);
        let _r5 = mine(&mut n, r4, vec![]);
        let current = store.reobserve_payment(&mut n, id).unwrap();
        assert_eq!(
            current.operation,
            paid.historical_payment.as_ref().unwrap().operation
        );
        assert_eq!(store.readback(id).unwrap(), paid);
        assert_eq!(balance(&n, public(1)), provider_before_payment + 1000);
    }
}
#[test]
fn real_receipt_closes_native_cancel_but_service_cancel_still_blocks_new_settlement_intent() {
    let d = tempfile::tempdir().unwrap();
    let mut n = open(&d.path().join("node"), StateBackend::Legacy);
    let settings = n.settings.clone();
    let genesis = settings.genesis();
    let (task, wire) = reserve(&settings);
    let reserved = mine(&mut n, genesis, vec![wire]);
    let s = statement(task);
    let mut store =
        NativeGenerationStoreV2::open(&d.path().join("generation.sqlite"), configuration(&n))
            .unwrap();
    let mut runtime = TestRuntime {
        corrupt_profile: false,
        cancel_after_receipt: false,
    };
    let id = begin_fixture_verification(&mut store, &mut n, &mut runtime, &s);
    let mut payload = task.to_vec();
    payload.extend(id);
    let receipt = mine(
        &mut n,
        reserved,
        vec![signed(&settings, 1, 1, 4, payload.clone())],
    );
    store.cancel(id, [91; 32]).unwrap();
    let prior = store.readback(id).unwrap();
    reject(&mut n, receipt, signed(&settings, 0, 2, 3, task.to_vec()));
    {
        let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
        assert!(store
            .prepare_settlement(&mut owner, id, signed(&settings, 0, 2, 5, payload))
            .is_err());
    }
    assert_eq!(store.readback(id).unwrap(), prior);
    let row = n
        .native_funding_observation(NativeFundingSourceV1::Task(task))
        .unwrap()
        .row
        .unwrap();
    assert_eq!(row["status"], "receipt");
    assert_eq!(row["remaining"], 1000);
    // No assertion of an immediate refund: ordinary expiry remains at height 20.
}
#[test]
fn real_reserved_task_cancel_and_owner_wire_negative_controls() {
    let d = tempfile::tempdir().unwrap();
    let mut n = open(&d.path().join("node"), StateBackend::Legacy);
    let settings = n.settings.clone();
    let genesis = settings.genesis();
    let (task, wire) = reserve(&settings);
    let reserved = mine(&mut n, genesis, vec![wire]);
    let s = statement(task);
    let mut store =
        NativeGenerationStoreV2::open(&d.path().join("generation.sqlite"), configuration(&n))
            .unwrap();
    let mut runtime = TestRuntime {
        corrupt_profile: false,
        cancel_after_receipt: false,
    };
    let id = {
        let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
        store.prepare(&mut owner, s).unwrap()
    };
    store.cancel(id, [92; 32]).unwrap();
    let retained = store.readback(id).unwrap();
    {
        let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
        assert!(matches!(
            store.begin(&mut owner, id).unwrap(),
            DispatchDecisionV2::Done
        ));
    }
    assert_eq!(store.readback(id).unwrap(), retained);
    assert_eq!(retained.resource_charge, retained.statement.resource_cap);
    assert!(!retained.dispatch_intent);
    let cancelled = mine(
        &mut n,
        reserved,
        vec![signed(&settings, 0, 2, 3, task.to_vec())],
    );
    let row = n
        .native_funding_observation(NativeFundingSourceV1::Task(task))
        .unwrap()
        .row
        .unwrap();
    assert_eq!(row["status"], "cancelled");
    assert_eq!(row["remaining"], 0);
    let mut payload = task.to_vec();
    payload.extend(id);
    reject(&mut n, cancelled, signed(&settings, 1, 1, 4, payload));
    assert!(!store.readback(id).unwrap().dispatch_intent);
    assert!(store.readback(id).unwrap().historical_payment.is_none());
}
#[test]
fn success_shaped_verifier_response_with_wrong_sdk_cannot_produce_positive() {
    let d = tempfile::tempdir().unwrap();
    let mut n = open(&d.path().join("node"), StateBackend::Legacy);
    let settings = n.settings.clone();
    let genesis = settings.genesis();
    let (task, wire) = reserve(&settings);
    mine(&mut n, genesis, vec![wire]);
    let s = statement(task);
    let mut store =
        NativeGenerationStoreV2::open(&d.path().join("generation.sqlite"), configuration(&n))
            .unwrap();
    let mut runtime = TestRuntime {
        corrupt_profile: true,
        cancel_after_receipt: false,
    };
    let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
    let id = store.prepare(&mut owner, s.clone()).unwrap();
    store.begin(&mut owner, id).unwrap();
    store.bind_job(id, job(&s)).unwrap();
    let before = store.readback(id).unwrap();
    assert!(store.verify(&mut owner, id, &evidence()).is_err());
    assert_eq!(store.readback(id).unwrap(), before);
    assert!(before.verified.is_none());
}
#[test]
fn real_node_task_owner_assignment_survives_cold_reopen_and_refuses_another_generation_journal() {
    let d = tempfile::tempdir().unwrap();
    let node_path = d.path().join("node");
    let mut n = open(&node_path, StateBackend::Legacy);
    let settings = n.settings.clone();
    let genesis = settings.genesis();
    let (task, wire) = reserve(&settings);
    mine(&mut n, genesis, vec![wire]);
    let s = statement(task);
    let config = configuration(&n);
    let first_path = d.path().join("first.sqlite");
    let mut first = NativeGenerationStoreV2::open(&first_path, config.clone()).unwrap();
    let mut runtime = TestRuntime {
        corrupt_profile: false,
        cancel_after_receipt: false,
    };
    let id = {
        let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
        first.prepare(&mut owner, s.clone()).unwrap()
    };
    let first_identity = first.journal_identity();
    drop(first);
    drop(n);
    let mut n = open(&node_path, StateBackend::Legacy);
    let mut second =
        NativeGenerationStoreV2::open(&d.path().join("second.sqlite"), config.clone()).unwrap();
    {
        let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
        assert!(second.prepare(&mut owner, s.clone()).is_err());
    }
    let mut first = NativeGenerationStoreV2::open(&first_path, config).unwrap();
    assert_eq!(first.journal_identity(), first_identity);
    {
        let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
        assert_eq!(first.prepare(&mut owner, s).unwrap(), id);
    }
    assert!(!first.readback(id).unwrap().dispatch_intent);
    assert!(second.readback(id).is_err());
}
#[test]
fn real_owner_signed_wrong_subject_or_sender_never_creates_settlement_intent() {
    let d = tempfile::tempdir().unwrap();
    let mut n = open(&d.path().join("node"), StateBackend::Legacy);
    let settings = n.settings.clone();
    let genesis = settings.genesis();
    let (task, wire) = reserve(&settings);
    let reserved = mine(&mut n, genesis, vec![wire]);
    let s = statement(task);
    let mut store =
        NativeGenerationStoreV2::open(&d.path().join("generation.sqlite"), configuration(&n))
            .unwrap();
    let mut runtime = TestRuntime {
        corrupt_profile: false,
        cancel_after_receipt: false,
    };
    let id = begin_fixture_verification(&mut store, &mut n, &mut runtime, &s);
    let mut payload = task.to_vec();
    payload.extend(id);
    mine(
        &mut n,
        reserved,
        vec![signed(&settings, 1, 1, 4, payload.clone())],
    );
    let prior = store.readback(id).unwrap();
    let mut bad = task.to_vec();
    bad.extend([99; 32]);
    {
        let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
        assert!(store
            .prepare_settlement(&mut owner, id, signed(&settings, 0, 2, 5, bad))
            .is_err());
        assert!(store
            .prepare_settlement(&mut owner, id, signed(&settings, 2, 1, 5, payload.clone()))
            .is_err());
    }
    assert_eq!(store.readback(id).unwrap(), prior);
    {
        let mut owner = NodeGenerationOwnerV2::new(&mut n, &mut runtime).unwrap();
        assert!(matches!(
            store
                .prepare_settlement(&mut owner, id, signed(&settings, 0, 2, 5, payload))
                .unwrap(),
            DispatchDecisionV2::New
        ));
    }
}

mod heavy;
mod recovery_v3;
mod terminal;
