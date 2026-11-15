//! Actual native proofs consumed by the unchanged complete-State M06 relation.
//! No AccountArchive or authenticated-state sidecar is created by this suite.
use rusqlite::{Connection, OpenFlags};
use serde_json::json;
use std::{path::Path, sync::Mutex};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{
    continuity_v1,
    pon_executor::{self, Config, ExecutionProgress, State},
};
use trnm_pon_node::{
    account_archive_execution::{
        self as execution,
        state_witness::{
            StatePhase, StateWitness, StateWitnessError as S, StateWitnessProgress as P,
        },
        BlockInput, CheckedExecutionError as E, CompactStateExecutionInput,
        CompactStateWitnessExecutionOutput,
    },
    account_archive_prototype::{
        multiproof::{CheckedMultiproof, Multiproof},
        Account, ArchiveError, Checkpoint, Context,
    },
    development_public, sequence_root, Node, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

fn public(owner: u64) -> Hash {
    development_public(owner).unwrap()
}
fn signed(cfg: &Settings, sender: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut envelope = Envelope {
        network: cfg.network(),
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
    envelope.signature = hex::decode(sign_hex(&key, &envelope.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    envelope.encode().unwrap()
}
fn transfer(cfg: &Settings, sender: u64, nonce: u64, recipient: u64, amount: u64) -> Vec<u8> {
    let mut payload = public(recipient).to_vec();
    payload.extend(amount.to_le_bytes());
    signed(cfg, sender, nonce, 1, payload)
}
fn rows(path: &Path) -> Vec<(String, Vec<Vec<String>>)> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|row| row.unwrap())
        .collect();
    tables
        .into_iter()
        .map(|table| {
            assert!(table
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'));
            let mut query = db.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let columns = query.column_count();
            let mut values: Vec<Vec<String>> = query
                .query_map([], |row| {
                    (0..columns)
                        .map(|i| {
                            row.get::<_, rusqlite::types::Value>(i)
                                .map(|value| format!("{value:?}"))
                        })
                        .collect()
                })
                .unwrap()
                .map(|row| row.unwrap())
                .collect();
            values.sort();
            (table, values)
        })
        .collect()
}
struct Inputs {
    checkpoint: Checkpoint,
    state: State,
    proof: Multiproof,
    witness: StateWitness,
}
struct Fixture {
    directory: tempfile::TempDir,
    cfg: Settings,
    node: Node,
}
impl Fixture {
    fn new(legacy: bool) -> Self {
        let cfg = if legacy {
            Settings::development(Some(1)).unwrap()
        } else {
            Settings::development_with_profiles(
                Some(1),
                "native-public-evaluation-dev-v1",
                continuity_v1::PROFILE,
            )
            .unwrap()
        };
        let directory = tempfile::tempdir().unwrap();
        let node =
            Node::open_with_authenticated_state(&directory.path().join("node"), cfg.clone(), 4)
                .unwrap();
        Self {
            directory,
            cfg,
            node,
        }
    }
    fn inputs(&self, owners: &[u64]) -> Inputs {
        let parent = self.node.active().unwrap().0;
        let (checkpoint, proof, _) = self
            .node
            .authenticated_account_multiproof(
                parent,
                &owners.iter().copied().map(public).collect::<Vec<_>>(),
            )
            .unwrap();
        let state = self.node.state_at(parent).unwrap();
        let witness =
            execution::prepare_state_witness_from_checkpoint(&self.cfg, &checkpoint, &state)
                .unwrap();
        Inputs {
            checkpoint,
            state,
            proof,
            witness,
        }
    }
    fn run(
        &self,
        inputs: &Inputs,
        txs: &[Vec<u8>],
        miner: u64,
        progress: &(impl Fn(P) -> execution::Result<()> + Sync),
    ) -> execution::Result<CompactStateWitnessExecutionOutput> {
        execution::execute_compact_from_checkpoint_and_progress(
            &self.cfg,
            &inputs.checkpoint,
            &inputs.state,
            BlockInput {
                transactions: txs,
                height: inputs.checkpoint.height() + 1,
                miner: public(miner),
                parent_id: inputs.checkpoint.branch(),
            },
            CompactStateExecutionInput {
                accounts: &inputs.proof,
                state: &inputs.witness,
            },
            progress,
        )
    }
    fn snapshot(&self) -> Vec<(String, Vec<Vec<String>>)> {
        rows(&self.directory.path().join("node/native.sqlite"))
    }
    fn accept(
        &mut self,
        txs: Vec<Vec<u8>>,
        miner: u64,
        owners: &[u64],
    ) -> CompactStateWitnessExecutionOutput {
        let inputs = self.inputs(owners);
        let before = self.snapshot();
        let active = self.node.read_active().unwrap();
        let preview = self.run(&inputs, &txs, miner, &|_| Ok(())).unwrap();
        assert_eq!(self.snapshot(), before);
        assert_eq!(self.node.read_active().unwrap(), active);
        let parent = inputs.checkpoint.branch();
        let height = inputs.checkpoint.height() + 1;
        let packet = if self.cfg.task_profile() == pon_executor::LEGACY_TASK_PROFILE {
            self.node
                .make(parent, txs, public(miner), 1 + height * 10, 4096)
        } else {
            self.node
                .make_consensus_maintenance(parent, txs, public(miner), 1 + height * 10, 4096)
        }
        .unwrap();
        let checked = &preview.execution.execution;
        assert_eq!(packet.header.state, checked.output.root);
        assert_eq!(
            packet.header.receipts,
            sequence_root("receipts", &checked.output.receipts)
        );
        let id = self.node.admit(&packet, 100_000).unwrap();
        assert_eq!(self.node.state_at(id).unwrap(), checked.output.state);
        self.node.activate(id).unwrap();
        let (next, _, _) = self
            .node
            .authenticated_account_multiproof(id, &[public(0)])
            .unwrap();
        assert_eq!(
            next.account_root(),
            preview
                .execution
                .state_observation
                .successor
                .commitment
                .account_root
        );
        assert_eq!(
            next.account_count(),
            preview
                .execution
                .state_observation
                .successor
                .commitment
                .account_count
        );
        assert!(
            checked.observation.complete_state_required
                && checked.observation.aggregate_account_scans_are_full
        );
        assert!(!checked.observation.consensus_admission && !checked.observation.archive_mutated);
        preview
    }
}

#[test]
fn native_compact_signed_overlay_zero_nonce_reentry_matches_real_admission_and_reopen() {
    let mut f = Fixture::new(false);
    let config =
        Config::installed_with_profiles("native-public-evaluation-dev-v1", continuity_v1::PROFILE)
            .unwrap();
    let fee = config.fees[1]
        + transfer(&f.cfg, 0, 1, 1, 1).len() as u64
            * config.params["byte_fee_units"].as_u64().unwrap();
    let txs = vec![
        transfer(&f.cfg, 0, 1, 10, fee + 7),
        transfer(&f.cfg, 10, 1, 1, 7),
        transfer(&f.cfg, 0, 2, 0, 1),
    ];
    let first = f.accept(txs, 0, &[0, 1, 10]);
    let account = format!("account:{}", hex::encode(public(10)));
    assert_eq!(
        first.execution.execution.output.state[&account],
        json!({"balance":0,"nonce":1})
    );
    assert!(first
        .execution
        .state_observation
        .mandatory
        .account_changes
        .is_empty());
    let second = f.accept(
        vec![
            transfer(&f.cfg, 0, 3, 10, fee + 1),
            transfer(&f.cfg, 10, 2, 1, 1),
        ],
        0,
        &[0, 1, 10],
    );
    assert_eq!(
        second.execution.execution.output.state[&account],
        json!({"balance":0,"nonce":2})
    );
    let inputs = f.inputs(&[10, 99]);
    let checked = CheckedMultiproof::verify(
        Context {
            network: f.cfg.network(),
            parameters: f.cfg.parameters(),
            genesis: f.cfg.genesis(),
        },
        &inputs.checkpoint,
        &inputs.proof,
    )
    .unwrap();
    assert_eq!(
        checked.account(public(10)).unwrap(),
        Some(Account {
            balance: 0,
            nonce: 2
        })
    );
    assert_eq!(checked.account(public(99)).unwrap(), None);
    let stale = vec![transfer(&f.cfg, 10, 1, 1, 1)];
    let inputs = f.inputs(&[0, 1, 10]);
    assert_eq!(
        f.run(&inputs, &stale, 0, &|_| Ok(())).unwrap_err(),
        E::Relation("NONCE")
    );
    assert_eq!(
        f.node
            .make_consensus_maintenance(inputs.checkpoint.branch(), stale, public(0), 31, 4096)
            .unwrap_err()
            .to_string(),
        "NONCE"
    );
    let actual = f.node.read_active().unwrap();
    let before = f.snapshot();
    let directory = f.directory;
    let cfg = f.cfg;
    drop(f.node);
    let reopened =
        Node::open_with_authenticated_state(&directory.path().join("node"), cfg, 4).unwrap();
    assert_eq!(reopened.read_active().unwrap(), actual);
    assert_eq!(rows(&directory.path().join("node/native.sqlite")), before);
    assert_eq!(
        std::fs::read_dir(directory.path()).unwrap().count(),
        1,
        "only the native Node directory exists"
    );
}

#[test]
fn native_compact_missing_extra_counterfeit_and_wrong_parent_inputs_fail_without_state_fallback() {
    let f = Fixture::new(false);
    let original = f.snapshot();
    let absent = f.inputs(&[]);
    assert_eq!(
        f.run(&absent, &[], 70, &|_| Ok(())).unwrap_err(),
        E::MissingWitness { owner: public(70) }
    );
    let extra = f.inputs(&[70, 99]);
    assert_eq!(
        f.run(&extra, &[], 70, &|_| Ok(())).unwrap_err(),
        E::UnusedWitness {
            owners: vec![public(99)]
        }
    );
    let mut inputs = f.inputs(&[70]);
    inputs.proof.accounts[0].account = Some(Account {
        balance: 0,
        nonce: 0,
    });
    assert_eq!(
        f.run(&inputs, &[], 70, &|_| Ok(())).unwrap_err(),
        E::Archive(ArchiveError::InvalidWitness)
    );
    let mut inputs = f.inputs(&[70]);
    inputs.proof.checkpoint[0] ^= 1;
    assert_eq!(
        f.run(&inputs, &[], 70, &|_| Ok(())).unwrap_err(),
        E::Archive(ArchiveError::InvalidWitness)
    );
    let mut inputs = f.inputs(&[70]);
    inputs.witness.non_accounts.pop();
    assert_eq!(
        f.run(&inputs, &[], 70, &|_| Ok(())).unwrap_err(),
        E::StateWitness(S::Partition)
    );
    let mut inputs = f.inputs(&[70]);
    inputs.witness.commitment.account_balance += 1;
    assert_eq!(
        f.run(&inputs, &[], 70, &|_| Ok(())).unwrap_err(),
        E::StateWitness(S::Commitment)
    );
    let inputs = f.inputs(&[70]);
    for (parent, height, expected) in [
        ([255; 32], 1, E::Parent),
        (inputs.checkpoint.branch(), 2, E::Height),
    ] {
        let mut broken = inputs.proof.clone();
        broken.checkpoint[0] ^= 1;
        assert_eq!(
            execution::execute_compact_from_checkpoint_and_progress(
                &f.cfg,
                &inputs.checkpoint,
                &inputs.state,
                BlockInput {
                    transactions: &[],
                    height,
                    miner: public(70),
                    parent_id: parent
                },
                CompactStateExecutionInput {
                    accounts: &broken,
                    state: &inputs.witness
                },
                &|_| Ok(())
            )
            .unwrap_err(),
            expected
        );
    }
    assert_eq!(f.snapshot(), original);
}

#[test]
fn native_compact_preserves_source_binding_budgets_and_old_namespace_refusals() {
    let mut f = Fixture::new(false);
    let prior = f.inputs(&[0]);
    f.accept(vec![], 0, &[0]);
    let current = f.inputs(&[0]);
    let before = f.snapshot();
    assert_eq!(
        execution::prepare_state_witness_from_checkpoint(&f.cfg, &prior.checkpoint, &current.state)
            .unwrap_err(),
        E::SourceRoot
    );
    assert_eq!(
        execution::execute_compact_from_checkpoint_and_progress(
            &f.cfg,
            &current.checkpoint,
            &current.state,
            BlockInput {
                transactions: &[],
                height: 2,
                miner: public(0),
                parent_id: current.checkpoint.branch()
            },
            CompactStateExecutionInput {
                accounts: &prior.proof,
                state: &current.witness
            },
            &|_| Ok(())
        )
        .unwrap_err(),
        E::Archive(ArchiveError::InvalidWitness)
    );
    let mut oversized = f.inputs(&[0]);
    oversized.proof.accounts = vec![oversized.proof.accounts[0].clone(); oversized.state.len() + 2];
    let trace = Mutex::new(Vec::new());
    assert_eq!(
        f.run(&oversized, &[], 0, &|p| {
            trace.lock().unwrap().push(p);
            Ok(())
        })
        .unwrap_err(),
        E::Budget
    );
    assert_eq!(*trace.lock().unwrap(), vec![P::BeforeBinding]);
    let growth = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        "consensus-maintenance-growth-reference-dev-v2",
    )
    .unwrap();
    assert_eq!(
        execution::prepare_state_witness_from_checkpoint(
            &growth,
            &current.checkpoint,
            &current.state
        )
        .unwrap_err(),
        E::Archive(ArchiveError::Context)
    );
    assert_eq!(
        execution::execute_compact_from_checkpoint_and_progress(
            &growth,
            &current.checkpoint,
            &current.state,
            BlockInput {
                transactions: &[],
                height: 2,
                miner: public(0),
                parent_id: current.checkpoint.branch()
            },
            CompactStateExecutionInput {
                accounts: &current.proof,
                state: &current.witness
            },
            &|_| Ok(())
        )
        .unwrap_err(),
        E::Archive(ArchiveError::Context)
    );
    let mut too_many = current.state.clone();
    for index in 0..65_537 {
        too_many.insert(format!("unused:{index}"), json!(0));
    }
    assert_eq!(
        execution::execute_compact_from_checkpoint_and_progress(
            &f.cfg,
            &current.checkpoint,
            &too_many,
            BlockInput {
                transactions: &[],
                height: 2,
                miner: public(0),
                parent_id: current.checkpoint.branch()
            },
            CompactStateExecutionInput {
                accounts: &current.proof,
                state: &current.witness
            },
            &|_| Ok(())
        )
        .unwrap_err(),
        E::Budget
    );
    assert_eq!(f.snapshot(), before);
}

#[test]
fn native_compact_cancellation_keeps_both_checked_phases_and_has_no_publication() {
    let f = Fixture::new(false);
    let inputs = f.inputs(&[70]);
    let before = f.snapshot();
    let active = f.node.read_active().unwrap();
    let trace = Mutex::new(Vec::new());
    f.run(&inputs, &[], 70, &|p| {
        trace.lock().unwrap().push(p);
        Ok(())
    })
    .unwrap();
    for point in [
        P::BeforeBinding,
        P::Execution(ExecutionProgress::BeforeParentBinding),
        P::AfterBinding,
        P::BeforeMandatoryVerification,
        P::AfterMandatoryVerification,
        P::BeforeSuccessorVerification,
        P::AfterSuccessorVerification,
        P::BeforeOutput,
    ] {
        assert!(trace.lock().unwrap().contains(&point));
        assert_eq!(
            f.run(&inputs, &[], 70, &|p| if p == point {
                Err(E::Cancelled)
            } else {
                Ok(())
            })
            .unwrap_err(),
            E::Cancelled
        );
        assert_eq!(f.snapshot(), before);
        assert_eq!(f.node.read_active().unwrap(), active);
    }
}

#[test]
fn native_compact_real_expiry_and_maturity_require_proofs_before_signed_spending() {
    let mut f = Fixture::new(true);
    let budget = 1000u64;
    let deadline = 2u64;
    let nonce = 1u64;
    let task = hash(
        b"task-instance-v3",
        &[
            &f.cfg.network(),
            &f.cfg.parameters(),
            &public(0),
            &nonce.to_le_bytes(),
            &public(2),
            &budget.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let mut payload = task.to_vec();
    payload.extend(public(2));
    payload.extend(budget.to_le_bytes());
    payload.extend(deadline.to_le_bytes());
    let reserve = signed(&f.cfg, 0, nonce, 2, payload);
    f.accept(vec![reserve], 70, &[0]);
    let parent = f.node.read_active().unwrap();
    let empty = f.inputs(&[]);
    assert_eq!(
        f.run(&empty, &[], 0, &|_| Ok(())).unwrap_err(),
        E::MissingWitness { owner: public(0) }
    );
    let refunded = f.accept(vec![], 0, &[0]);
    let key = format!("account:{}", hex::encode(public(0)));
    assert_eq!(
        refunded.execution.execution.output.state[&key]["balance"]
            .as_u64()
            .unwrap(),
        parent.2[&key]["balance"].as_u64().unwrap() + budget
    );
    assert_eq!(
        refunded.execution.execution.output.state[&format!("task:{}", hex::encode(task))]["status"],
        "expired"
    );
    for _ in 3..=20 {
        f.accept(vec![], 0, &[]);
    }
    let empty = f.inputs(&[]);
    assert_eq!(
        f.run(&empty, &[], 0, &|_| Ok(())).unwrap_err(),
        E::MissingWitness { owner: public(70) }
    );
    let spend = transfer(&f.cfg, 70, 1, 1, 1);
    let inputs = f.inputs(&[1, 70]);
    let before = f.snapshot();
    let trace = Mutex::new(Vec::new());
    f.run(&inputs, std::slice::from_ref(&spend), 0, &|p| {
        trace.lock().unwrap().push(p);
        Ok(())
    })
    .unwrap();
    for phase in [StatePhase::Mandatory, StatePhase::Successor] {
        let point = *trace
            .lock()
            .unwrap()
            .iter()
            .find(
                |point| matches!(point, P::AccountUpdate { phase: actual, .. } if *actual == phase),
            )
            .expect("each phase applies a real authenticated account update");
        assert_eq!(
            f.run(
                &inputs,
                std::slice::from_ref(&spend),
                0,
                &|p| if p == point {
                    Err(E::Cancelled)
                } else {
                    Ok(())
                }
            )
            .unwrap_err(),
            E::Cancelled
        );
        assert_eq!(f.snapshot(), before);
        assert_eq!(f.node.read_active().unwrap().0, inputs.checkpoint.branch());
    }
    let matured = f.accept(vec![spend], 0, &[1, 70]);
    let observed = &matured.execution.state_observation;
    let mandatory = observed
        .mandatory
        .account_changes
        .iter()
        .find(|change| change.owner == public(70))
        .unwrap();
    assert_eq!(mandatory.before, None);
    assert_eq!(mandatory.after.nonce, 0);
    let successor = observed
        .successor
        .account_changes
        .iter()
        .find(|change| change.owner == public(70))
        .unwrap();
    assert_eq!(successor.before, None);
    assert_eq!(successor.after.nonce, 1);
    assert!(mandatory.after.balance > successor.after.balance);
}
