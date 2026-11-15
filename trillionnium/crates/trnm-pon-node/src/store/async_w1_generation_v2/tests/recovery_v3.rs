//! Actual Node, SQLite and ML-DSA witness operations. The provider/verifier and
//! clock are explicit fixtures. The two directories share one physical host;
//! these tests establish neither independent custody nor live provider effects.
use super::*;
use crate::ingress::pq_network::canonical_tests::key;
use crate::pq_rollback_witness::{
    Checkpoint, DurableWitness, WitnessBinding, WitnessClient, WitnessTransport,
};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};
use trnm_service_settlement::native_generation_budget_v2::FailureKindV2;

#[derive(Clone, Copy)]
enum Cut {
    BeforeCas(u64),
    AfterCas(u64),
    CorruptReply(u64),
    ExpireAfterCas(u64),
}
type CurrentHook = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;
struct External {
    service: Arc<Mutex<DurableWitness>>,
    context: [u8; 64],
    pin: [u8; 64],
    cut: Arc<Mutex<Option<Cut>>>,
    offline: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
    now: Arc<AtomicU64>,
    after_current: CurrentHook,
}
struct Transport {
    service: Arc<Mutex<DurableWitness>>,
    cut: Arc<Mutex<Option<Cut>>>,
    offline: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
    now: Arc<AtomicU64>,
    after_current: CurrentHook,
}
impl WitnessTransport for Transport {
    fn exchange(&mut self, request: &[u8], until: Instant) -> crate::Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.offline.load(Ordering::SeqCst) {
            return Err("EXPLICIT_WITNESS_UNAVAILABLE_CUT".into());
        }
        let sequence =
            (request[4] == 2).then(|| u64::from_be_bytes(request[141..149].try_into().unwrap()));
        let mut armed = self.cut.lock().unwrap();
        let selected = armed.filter(|cut| {
            let (Cut::BeforeCas(n)
            | Cut::AfterCas(n)
            | Cut::CorruptReply(n)
            | Cut::ExpireAfterCas(n)) = cut;
            Some(*n) == sequence
        });
        if selected.is_some() {
            *armed = None;
        }
        drop(armed);
        if matches!(selected, Some(Cut::BeforeCas(_))) {
            return Err("EXPLICIT_BEFORE_WITNESS_COMMIT_CUT".into());
        }
        let mut reply = self.service.lock().unwrap().handle(request, until)?;
        if request[4] == 1 {
            if let Some(hook) = self.after_current.lock().unwrap().take() {
                hook();
            }
        }
        match selected {
            Some(Cut::AfterCas(_)) => return Err("EXPLICIT_LOST_CAS_ACK".into()),
            Some(Cut::CorruptReply(_)) => *reply.last_mut().unwrap() ^= 1,
            Some(Cut::ExpireAfterCas(_)) => self.now.store(10_000, Ordering::SeqCst),
            _ => {}
        }
        Ok(reply)
    }
}
impl External {
    fn binding(&self) -> WitnessBinding {
        WitnessBinding::generation_v3(
            self.context,
            1,
            key(73).public_spki(),
            key(74).public_spki(),
        )
        .unwrap()
    }
    fn client(&self) -> WitnessClient {
        WitnessClient::new(
            self.binding(),
            key(74),
            Box::new(Transport {
                service: self.service.clone(),
                cut: self.cut.clone(),
                offline: self.offline.clone(),
                calls: self.calls.clone(),
                now: self.now.clone(),
                after_current: self.after_current.clone(),
            }),
        )
        .unwrap()
    }
}

struct Runtime {
    now: Arc<AtomicU64>,
    terminal_calls: usize,
}
impl OwnedGenerationRuntimeV2 for Runtime {
    fn clock_checkpoint(&mut self) -> Result<ClockCheckpointV2> {
        Ok(ClockCheckpointV2 {
            clock_domain: [9; 32],
            now_ns: self.now.load(Ordering::SeqCst),
        })
    }
    fn reconcile_fresh_execution(
        &mut self,
        s: &GenerationStatementV2,
        j: &ProviderJobV2,
        e: &GenerationEvidenceV2<'_>,
    ) -> Result<OwnedFullGenerationV2> {
        TestRuntime {
            corrupt_profile: false,
            cancel_after_receipt: false,
        }
        .reconcile_fresh_execution(s, j, e)
    }
    fn run_independent_verifier(
        &mut self,
        s: &GenerationStatementV2,
        e: &GenerationEvidenceV2<'_>,
    ) -> Result<OwnedVerifierRunV2> {
        TestRuntime {
            corrupt_profile: false,
            cancel_after_receipt: false,
        }
        .run_independent_verifier(s, e)
    }
}
impl OwnedTerminalGenerationRuntimeV3 for Runtime {
    fn reconcile_terminal_execution(
        &mut self,
        s: &GenerationStatementV2,
        j: &ProviderJobV2,
    ) -> Result<OwnedTerminalExecutionV3> {
        self.terminal_calls += 1;
        Ok(OwnedTerminalExecutionV3 {
            job: j.clone(),
            execution_source_commitment: s.execution_source_commitment,
            evidence_digest: sha256(b"EXPLICIT_V3_TERMINAL_FIXTURE"),
            reason: TerminalReasonV3::Failed,
            resources: None,
            controller_observed: self.clock_checkpoint()?,
        })
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    config: ConfigurationV2,
    statement: GenerationStatementV2,
    external: External,
    id: Hash,
}
impl Fixture {
    fn prepared() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let a = directory.path().join("domain-a");
        let b = directory.path().join("domain-b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        let mut node = open(&a.join("node"), StateBackend::PermanentAccountGrowthV2);
        let (task, wire) = reserve(&node.settings);
        let genesis = node.settings.genesis();
        mine(&mut node, genesis, vec![wire]);
        let config = configuration(&node);
        let statement = statement(task);
        let store = NativeGenerationStoreV2::open(&a.join("m12.sqlite"), config.clone()).unwrap();
        let context = store.recovery_context_v3().unwrap();
        let point = store.recovery_checkpoint_v3().unwrap();
        let binding =
            WitnessBinding::generation_v3(context, 1, key(73).public_spki(), key(74).public_spki())
                .unwrap();
        let pin = binding.id();
        let service = DurableWitness::register_new(
            &b.join("witness.sqlite"),
            binding,
            Checkpoint::new(point.sequence, point.root).unwrap(),
            key(73),
        )
        .unwrap();
        let now = Arc::new(AtomicU64::new(200));
        let external = External {
            service: Arc::new(Mutex::new(service)),
            context,
            pin,
            cut: Arc::new(Mutex::new(None)),
            offline: Arc::new(AtomicBool::new(false)),
            calls: Arc::new(AtomicUsize::new(0)),
            now: now.clone(),
            after_current: Arc::new(Mutex::new(None)),
        };
        let mut runtime = Runtime {
            now,
            terminal_calls: 0,
        };
        let mut owner =
            NodeGenerationOwnerV3::open(&mut node, &mut runtime, store, external.client(), 1, pin)
                .unwrap();
        let id = owner.prepare(statement.clone()).unwrap();
        drop(owner);
        drop(node);
        Self {
            directory,
            config,
            statement,
            external,
            id,
        }
    }
    fn local(&self) -> PathBuf {
        self.directory.path().join("domain-a")
    }
    fn node(&self) -> Node {
        open(
            &self.local().join("node"),
            StateBackend::PermanentAccountGrowthV2,
        )
    }
    fn store(&self) -> NativeGenerationStoreV2 {
        NativeGenerationStoreV2::open(&self.local().join("m12.sqlite"), self.config.clone())
            .unwrap()
    }
    fn runtime(&self) -> Runtime {
        Runtime {
            now: self.external.now.clone(),
            terminal_calls: 0,
        }
    }
    fn owner<'a>(
        &self,
        node: &'a mut Node,
        runtime: &'a mut Runtime,
    ) -> Result<NodeGenerationOwnerV3<'a, Runtime>> {
        NodeGenerationOwnerV3::open(
            node,
            runtime,
            self.store(),
            self.external.client(),
            1,
            self.external.pin,
        )
    }
}
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to.join(entry.file_name()));
        } else {
            assert!(entry.file_type().unwrap().is_file());
            std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
        }
    }
}

#[test]
fn full_local_backup_restore_refuses_dispatch_against_retained_signed_witness() {
    let f = Fixture::prepared();
    let backup = f.directory.path().join("whole-a-backup");
    copy_tree(&f.local(), &backup);
    let mut node = f.node();
    let mut runtime = f.runtime();
    let mut owner = f.owner(&mut node, &mut runtime).unwrap();
    assert!(matches!(
        owner.begin(f.id).unwrap(),
        DispatchDecisionV2::New
    ));
    let original = owner.readback_current(f.id).unwrap();
    assert!(matches!(
        owner.begin(f.id).unwrap(),
        DispatchDecisionV2::Pending
    ));
    drop(owner);
    drop(node);
    std::fs::remove_dir_all(f.local()).unwrap();
    copy_tree(&backup, &f.local());
    let mut node = f.node();
    assert!(f
        .owner(&mut node, &mut runtime)
        .err()
        .unwrap()
        .to_string()
        .contains("ROLLBACK_OR_UNWITNESSED"));
    let restored = f.store().readback(f.id).unwrap();
    assert!(!restored.dispatch_intent);
    assert_eq!(
        restored.statement.provider_operation,
        original.statement.provider_operation
    );
    assert_eq!(restored.resource_charge, f.statement.resource_cap);
}

#[test]
fn lost_or_corrupt_cas_ack_recovers_same_operation_pending_without_redispatch() {
    for cut in [Cut::AfterCas(3), Cut::CorruptReply(3)] {
        let f = Fixture::prepared();
        *f.external.cut.lock().unwrap() = Some(cut);
        let mut node = f.node();
        let mut runtime = f.runtime();
        let mut owner = f.owner(&mut node, &mut runtime).unwrap();
        let mut provider_calls = 0;
        let result = owner.begin(f.id);
        if matches!(result, Ok(DispatchDecisionV2::New)) {
            provider_calls += 1;
        }
        assert!(result.is_err());
        assert!(owner.is_quarantined());
        assert!(owner.begin(f.id).is_err());
        let unknown = owner.historical_readback(f.id).unwrap();
        assert!(unknown.dispatch_intent);
        assert_eq!(unknown.resource_charge, f.statement.resource_cap);
        drop(owner);
        let mut recovered = f.owner(&mut node, &mut runtime).unwrap();
        assert!(matches!(
            recovered.begin(f.id).unwrap(),
            DispatchDecisionV2::Pending
        ));
        assert_eq!(recovered.readback_current(f.id).unwrap(), unknown);
        assert_eq!(provider_calls, 0, "no witness ACK, no provider dispatch");
    }
}

#[test]
fn error_after_actual_local_commit_quarantines_without_signing_that_successor() {
    let f = Fixture::prepared();
    let mut node = f.node();
    let mut runtime = f.runtime();
    let mut owner = f.owner(&mut node, &mut runtime).unwrap();
    assert!(matches!(
        owner.begin(f.id).unwrap(),
        DispatchDecisionV2::New
    ));
    let before = f.external.client().current().unwrap();
    assert!(owner.fixture_error_after_committed_cancel(f.id).is_err());
    assert!(owner.is_quarantined());
    let historical = owner.historical_readback(f.id).unwrap();
    assert_eq!(historical.cancellation, Some([62; 32]));
    assert_eq!(historical.resource_charge, f.statement.resource_cap);
    assert_eq!(f.external.client().current().unwrap(), before);
    drop(owner);
    assert!(f.owner(&mut node, &mut runtime).is_err());
}

#[test]
fn local_commit_without_external_commit_remains_quarantined_on_cold_reopen() {
    let f = Fixture::prepared();
    *f.external.cut.lock().unwrap() = Some(Cut::BeforeCas(3));
    let mut node = f.node();
    let mut runtime = f.runtime();
    let mut owner = f.owner(&mut node, &mut runtime).unwrap();
    assert!(owner.begin(f.id).is_err());
    let pending = owner.historical_readback(f.id).unwrap();
    assert!(pending.dispatch_intent);
    assert_eq!(pending.resource_charge, f.statement.resource_cap);
    drop(owner);
    assert!(f.owner(&mut node, &mut runtime).is_err());
    assert_eq!(f.store().readback(f.id).unwrap(), pending);
}

#[test]
fn witness_unavailable_refuses_before_local_dispatch_and_missing_fence_has_no_fallback() {
    let f = Fixture::prepared();
    let mut node = f.node();
    let mut runtime = f.runtime();
    let mut owner = f.owner(&mut node, &mut runtime).unwrap();
    let before = owner.historical_readback(f.id).unwrap();
    f.external.offline.store(true, Ordering::SeqCst);
    assert!(owner.begin(f.id).is_err());
    assert!(owner.is_quarantined());
    assert_eq!(owner.historical_readback(f.id).unwrap(), before);
    drop(owner);
    assert!(f.owner(&mut node, &mut runtime).is_err());
}

#[test]
fn independent_pin_authority_generation_and_random_journal_cannot_be_rebound() {
    let f = Fixture::prepared();
    let mut node = f.node();
    let mut runtime = f.runtime();
    let calls = f.external.calls.load(Ordering::SeqCst);
    assert!(!f.external.binding().matches_policy(&[]));
    for (generation, pin) in [(1, [0; 64]), (1, [99; 64]), (2, f.external.pin)] {
        assert!(NodeGenerationOwnerV3::open(
            &mut node,
            &mut runtime,
            f.store(),
            f.external.client(),
            generation,
            pin
        )
        .is_err());
    }
    let replacement =
        NativeGenerationStoreV2::open(&f.local().join("replacement.sqlite"), f.config.clone())
            .unwrap();
    assert!(NodeGenerationOwnerV3::open(
        &mut node,
        &mut runtime,
        replacement,
        f.external.client(),
        1,
        f.external.pin
    )
    .is_err());
    assert_eq!(calls, f.external.calls.load(Ordering::SeqCst));
}

#[test]
fn transaction_head_change_after_witness_read_is_not_promoted_to_a_signed_successor() {
    let f = Fixture::prepared();
    let mut node = f.node();
    let mut runtime = f.runtime();
    let mut owner = f.owner(&mut node, &mut runtime).unwrap();
    let before = f.external.client().current().unwrap();
    let path = f.local().join("m12.sqlite");
    let config = f.config.clone();
    let id = f.id;
    *f.external.after_current.lock().unwrap() = Some(Box::new(move || {
        // A real second SQLite writer runs after the authenticated read but
        // before the guarded owner's transaction. It has no V3 authority.
        NativeGenerationStoreV2::open(&path, config)
            .unwrap()
            .cancel(id, [61; 32])
            .unwrap();
    }));
    assert!(owner
        .begin(f.id)
        .err()
        .unwrap()
        .to_string()
        .contains("TRANSACTION_HEAD"));
    assert!(owner.is_quarantined());
    assert_eq!(f.external.client().current().unwrap(), before);
    let retained = owner.historical_readback(f.id).unwrap();
    assert_eq!(retained.cancellation, Some([61; 32]));
    assert!(!retained.dispatch_intent);
}

#[test]
fn lost_settlement_ack_retains_exact_wire_and_never_generates_a_replacement_operation() {
    let f = Fixture::prepared();
    let mut node = f.node();
    let mut runtime = f.runtime();
    let mut owner = f.owner(&mut node, &mut runtime).unwrap();
    assert!(matches!(
        owner.begin(f.id).unwrap(),
        DispatchDecisionV2::New
    ));
    owner.bind_job(f.id, job(&f.statement)).unwrap();
    owner.verify(f.id, &evidence()).unwrap();
    drop(owner);
    let mut payload = f.statement.task.to_vec();
    payload.extend(f.id);
    let receipt = signed(&node.settings, 1, 1, 4, payload.clone());
    let active = node.active().unwrap().0;
    mine(&mut node, active, vec![receipt]);
    let exact = signed(&node.settings, 0, 2, 5, payload.clone());
    let replacement = signed(&node.settings, 0, 3, 5, payload);
    *f.external.cut.lock().unwrap() = Some(Cut::AfterCas(6));
    let before_balance = balance(&node, f.statement.provider);
    let mut owner = f.owner(&mut node, &mut runtime).unwrap();
    assert!(owner.prepare_settlement(f.id, exact.clone()).is_err());
    assert!(owner.is_quarantined());
    let pending = owner.historical_readback(f.id).unwrap();
    assert_eq!(pending.settlement.as_ref().unwrap().exact_wire, exact);
    assert!(pending.historical_payment.is_none());
    drop(owner);
    let mut owner = f.owner(&mut node, &mut runtime).unwrap();
    assert!(matches!(
        owner.prepare_settlement(f.id, exact).unwrap(),
        DispatchDecisionV2::Pending
    ));
    assert!(owner.prepare_settlement(f.id, replacement).is_err());
    assert_eq!(owner.readback_current(f.id).unwrap(), pending);
    drop(owner);
    assert_eq!(balance(&node, f.statement.provider), before_balance);
}

#[test]
fn independent_service_reopen_pin_rejects_restored_witness_database() {
    let f = Fixture::prepared();
    let old = f.directory.path().join("domain-b/stale-witness.sqlite");
    std::fs::copy(f.external.service.lock().unwrap().storage_path(), &old).unwrap();
    let mut node = f.node();
    let mut runtime = f.runtime();
    let mut owner = f.owner(&mut node, &mut runtime).unwrap();
    assert!(matches!(
        owner.begin(f.id).unwrap(),
        DispatchDecisionV2::New
    ));
    let independently_retained = f.external.client().current().unwrap();
    assert!(DurableWitness::open_existing(
        &old,
        f.external.binding(),
        independently_retained,
        key(73)
    )
    .is_err());
}

#[test]
fn restored_journal_count_and_blob_limits_refuse_before_witness_or_effect() {
    for (sql, expected) in [
        (
            "UPDATE native_generation_meta_v2 SET sequence=193",
            "GENERATION_STORE_CONFIGURATION",
        ),
        (
            "PRAGMA ignore_check_constraints=ON; UPDATE native_generation_events_v2 SET payload=zeroblob(16385) WHERE sequence=1",
            "GENERATION_EVENT_SIZE",
        ),
        (
            "UPDATE native_generation_meta_v2 SET configuration=zeroblob(16385)",
            "GENERATION_STORE_CONFIGURATION",
        ),
    ] {
        let f = Fixture::prepared();
        let calls = f.external.calls.load(Ordering::SeqCst);
        let path = f.local().join("m12.sqlite");
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(sql)
            .unwrap();
        let error = NativeGenerationStoreV2::open(&path, f.config.clone()).err().unwrap();
        assert!(error.to_string().contains(expected));
        assert_eq!(f.external.calls.load(Ordering::SeqCst), calls);
    }
}

#[test]
fn record_limit_refuses_unbounded_journal_before_database_creation() {
    let f = Fixture::prepared();
    for records in [0, 4097, u32::MAX] {
        let path = f.local().join(format!("invalid-{records}.sqlite"));
        let mut config = f.config.clone();
        config.max_records = records;
        let error = NativeGenerationStoreV2::open(&path, config).err().unwrap();
        assert!(error.to_string().contains("GENERATION_RECORD_LIMIT"));
        assert!(!path.exists());
    }
}

#[test]
fn authenticated_cas_cannot_extend_original_generation_deadline() {
    let f = Fixture::prepared();
    *f.external.cut.lock().unwrap() = Some(Cut::ExpireAfterCas(3));
    let mut node = f.node();
    let mut runtime = f.runtime();
    let mut owner = f.owner(&mut node, &mut runtime).unwrap();
    assert!(owner.begin(f.id).is_err());
    assert!(owner.historical_readback(f.id).unwrap().dispatch_intent);
    assert!(matches!(
        owner.begin(f.id).unwrap(),
        DispatchDecisionV2::Pending
    ));
    assert_eq!(
        owner.historical_readback(f.id).unwrap().resource_charge,
        f.statement.resource_cap
    );
}

#[test]
fn reorg_unknown_and_cancel_preserve_operation_cap_and_do_not_dispatch_or_pay() {
    let f = Fixture::prepared();
    let mut node = f.node();
    let mut runtime = f.runtime();
    let mut owner = f.owner(&mut node, &mut runtime).unwrap();
    assert!(matches!(
        owner.begin(f.id).unwrap(),
        DispatchDecisionV2::New
    ));
    owner.bind_job(f.id, job(&f.statement)).unwrap();
    drop(owner);
    let genesis = node.settings.genesis();
    let fork = mine(&mut node, genesis, vec![]);
    mine(&mut node, fork, vec![]);
    assert!(node
        .native_funding_observation(NativeFundingSourceV1::Task(f.statement.task))
        .unwrap()
        .row
        .is_none());
    let mut owner = f.owner(&mut node, &mut runtime).unwrap();
    assert!(matches!(
        owner.begin(f.id).unwrap(),
        DispatchDecisionV2::Pending
    ));
    owner.cancel(f.id, [55; 32]).unwrap();
    let failure = owner.reconcile_terminal_failure(f.id).unwrap();
    assert_eq!(failure.kind, FailureKindV2::Unknown);
    let after = owner.readback_current(f.id).unwrap();
    assert_eq!(after.resource_charge, f.statement.resource_cap);
    assert!(after.settlement.is_none() && after.historical_payment.is_none());
    assert!(matches!(
        owner.begin(f.id).unwrap(),
        DispatchDecisionV2::Done
    ));
    assert!(owner.prepare_settlement(f.id, vec![1]).is_err());
    drop(owner);
    let mut owner = f.owner(&mut node, &mut runtime).unwrap();
    assert_eq!(owner.reconcile_terminal_failure(f.id).unwrap(), failure);
    assert_eq!(owner.readback_current(f.id).unwrap(), after);
    drop(owner);
    assert_eq!(runtime.terminal_calls, 1);
}
