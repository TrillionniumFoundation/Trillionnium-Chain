//! Actual complete M06 blocks with original-parent account point-access proofs.
//! Complete State remains the aggregate/root reference; this does not admit a
//! larger account space or install the research wrapper in the Node lifecycle.
use rusqlite::Connection;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{
    continuity_v1,
    pon_executor::{self, Config, ExecutionProgress},
};
use trnm_pon_node::{
    account_archive_execution::{
        self,
        obligations::{self, WitnessBudget, WitnessDiscoveryProgress as D},
        state_witness::{StatePhase, StateWitnessError as S, StateWitnessProgress as P},
        BlockInput, CheckedExecutionError as E, CheckedExecutionOutput, CompactStateExecutionInput,
        StateExecutionInput,
    },
    account_archive_prototype::{
        AccountArchive, ArchiveError, Checkpoint, Context, Limits, Witness,
    },
    development_public, sequence_root, Node, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

fn public(owner: u64) -> Hash {
    development_public(owner).unwrap()
}
fn signed(settings: &Settings, sender: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = Envelope {
        network: settings.network(),
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
fn transfer(settings: &Settings, sender: u64, nonce: u64, recipient: u64, amount: u64) -> Vec<u8> {
    let mut payload = public(recipient).to_vec();
    payload.extend(amount.to_le_bytes());
    signed(settings, sender, nonce, 1, payload)
}
fn transfer_fee(settings: &Settings) -> u64 {
    // The fixture only reads installed fee constants here; actual Settings,
    // signature context, complete transition and resulting state are Node-owned.
    let cfg =
        Config::installed_with_profiles("native-public-evaluation-dev-v1", continuity_v1::PROFILE)
            .unwrap();
    cfg.fees[1]
        + transfer(settings, 0, 1, 1, 1).len() as u64
            * cfg.params["byte_fee_units"].as_u64().unwrap()
}
fn rows(path: &Path) -> Vec<String> {
    let db = Connection::open(path).unwrap();
    let rows = db
        .prepare(
            "SELECT 'meta:'||key||':'||hex(value) FROM archive_meta
         UNION ALL SELECT 'node:'||hex(id)||':'||hex(data) FROM archive_nodes
         UNION ALL SELECT 'checkpoint:'||hex(id)||':'||hex(branch)||':'||hex(data)
                   FROM archive_checkpoints
         UNION ALL SELECT 'active:'||singleton||':'||hex(checkpoint)||':'||generation
                   FROM archive_active
         ORDER BY 1",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|row| row.unwrap())
        .collect();
    rows
}
struct Fixture {
    _dir: tempfile::TempDir,
    archive_path: PathBuf,
    settings: Settings,
    node: Node,
    archive: AccountArchive,
    checkpoint: Checkpoint,
}
impl Fixture {
    fn new() -> Self {
        let settings = Settings::development_with_profiles(
            Some(1),
            "native-public-evaluation-dev-v1",
            continuity_v1::PROFILE,
        )
        .unwrap();
        Self::with_settings(settings)
    }
    fn with_settings(settings: Settings) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("account-archive.sqlite");
        // The ordinary worker-4 Node remains the independent execution route.
        let node = Node::open(&dir.path().join("node"), settings.clone(), 4).unwrap();
        let state = node.read_active().unwrap().2;
        let mut archive = AccountArchive::open(
            &archive_path,
            Context {
                network: settings.network(),
                parameters: settings.parameters(),
                genesis: settings.genesis(),
            },
            Limits::default(),
        )
        .unwrap();
        let checkpoint = archive
            .project_initial(&state, pon_executor::root(&state).unwrap())
            .unwrap();
        archive
            .activate(None, checkpoint.id(), &mut || Ok(()))
            .unwrap();
        Self {
            _dir: dir,
            archive_path,
            settings,
            node,
            archive,
            checkpoint,
        }
    }
    fn witnesses(&self, owners: &[u64]) -> Vec<Witness> {
        owners
            .iter()
            .map(|&owner| {
                self.archive
                    .witness(self.checkpoint.id(), public(owner))
                    .unwrap()
                    .0
            })
            .collect()
    }
    fn execute(
        &self,
        txs: &[Vec<u8>],
        miner: u64,
        witnesses: &[Witness],
    ) -> account_archive_execution::Result<CheckedExecutionOutput> {
        let parent = self.node.state_at(self.checkpoint.branch()).unwrap();
        account_archive_execution::execute(
            &self.settings,
            &self.archive,
            self.checkpoint.id(),
            &parent,
            BlockInput {
                transactions: txs,
                height: self.checkpoint.height() + 1,
                miner: public(miner),
                parent_id: self.checkpoint.branch(),
            },
            witnesses,
        )
    }
    fn accept(&mut self, txs: Vec<Vec<u8>>, miner: u64, owners: &[u64]) -> CheckedExecutionOutput {
        let original_rows = rows(&self.archive_path);
        let original_node = self.node.read_active().unwrap();
        let witnesses = self.witnesses(owners);
        let checked = self.execute(&txs, miner, &witnesses).unwrap();
        assert_eq!(rows(&self.archive_path), original_rows);
        assert_eq!(self.node.read_active().unwrap(), original_node);
        let height = self.checkpoint.height() + 1;
        let packet = if self.settings.task_profile() == pon_executor::LEGACY_TASK_PROFILE {
            self.node.make(
                self.checkpoint.branch(),
                txs,
                public(miner),
                1 + height * 10,
                4096,
            )
        } else {
            self.node.make_consensus_maintenance(
                self.checkpoint.branch(),
                txs,
                public(miner),
                1 + height * 10,
                4096,
            )
        }
        .unwrap();
        assert_eq!(packet.header.state, checked.output.root);
        assert_eq!(
            packet.header.receipts,
            sequence_root("receipts", &checked.output.receipts)
        );
        let id = self.node.admit(&packet, 100_000).unwrap();
        let after = self.node.state_at(id).unwrap();
        assert_eq!(after, checked.output.state);
        let next = self
            .archive
            .project_successor(
                self.checkpoint.id(),
                &original_node.2,
                &after,
                id,
                height,
                &mut || Ok(()),
            )
            .unwrap();
        assert_eq!(
            checked.observation.successor_account_root,
            next.account_root()
        );
        assert_eq!(
            checked.observation.successor_account_count,
            next.account_count()
        );
        assert_eq!(self.node.activate(id).unwrap(), id);
        self.archive
            .activate(self.archive.active().unwrap(), next.id(), &mut || Ok(()))
            .unwrap();
        self.checkpoint = next;
        checked
    }
}

#[test]
fn checked_accounts_execute_same_block_creation_spend_and_self_transfer_against_native_node() {
    let mut f = Fixture::new();
    let fee = transfer_fee(&f.settings);
    let txs = vec![
        transfer(&f.settings, 0, 1, 10, 10_000),
        transfer(&f.settings, 10, 1, 1, 10_000 - fee),
        transfer(&f.settings, 0, 2, 0, 1),
    ];
    let before_node = f.node.read_active().unwrap();
    let before_rows = rows(&f.archive_path);
    assert_eq!(
        f.execute(&txs, 0, &f.witnesses(&[0, 1])).unwrap_err(),
        E::MissingWitness { owner: public(10) }
    );
    assert_eq!(
        f.execute(&txs, 0, &f.witnesses(&[0, 10])).unwrap_err(),
        E::MissingWitness { owner: public(1) }
    );
    assert_eq!(
        f.execute(&txs, 0, &f.witnesses(&[0, 1, 10, 2]))
            .unwrap_err(),
        E::UnusedWitness {
            owners: vec![public(2)]
        }
    );
    assert_eq!(f.node.read_active().unwrap(), before_node);
    assert_eq!(rows(&f.archive_path), before_rows);
    let checked = f.accept(txs, 0, &[0, 1, 10]);
    assert_eq!(checked.observation.workers, 1);
    assert_eq!(checked.observation.parent_account_count, 4);
    assert_eq!(checked.observation.successor_account_count, 5);
    assert_eq!(
        checked.observation.used_owners,
        checked.observation.requested_owners
    );
    assert_eq!(
        checked.output.state[&format!("account:{}", hex::encode(public(10)))],
        json!({"balance":0,"nonce":1})
    );
    // A replenishment does not erase the already-used nonce. The failed old
    // signed command is evaluated after its earlier in-block funding command.
    let replay = vec![
        transfer(&f.settings, 0, 3, 10, 5000),
        transfer(&f.settings, 10, 1, 1, 1),
    ];
    let original = f.node.read_active().unwrap();
    let original_rows = rows(&f.archive_path);
    assert_eq!(
        f.execute(&replay, 0, &f.witnesses(&[0, 1, 10]))
            .unwrap_err(),
        E::Relation("NONCE")
    );
    assert_eq!(f.node.read_active().unwrap(), original);
    assert_eq!(rows(&f.archive_path), original_rows);
}

#[test]
fn checked_accounts_preserve_canonical_errors_source_binding_and_exact_witness_coverage() {
    let f = Fixture::new();
    let txs = vec![transfer(&f.settings, 0, 1, 1, 1)];
    let parent = f.node.read_active().unwrap();
    let original_rows = rows(&f.archive_path);
    let valid = f.witnesses(&[0, 1]);
    let input = BlockInput {
        transactions: &txs,
        height: 1,
        miner: public(0),
        parent_id: parent.0,
    };
    let mut wrong_nonaccount = parent.2.clone();
    wrong_nonaccount.insert("meta:issued".into(), json!(1));
    assert_eq!(
        account_archive_execution::execute(
            &f.settings,
            &f.archive,
            f.checkpoint.id(),
            &wrong_nonaccount,
            input,
            &valid,
        )
        .unwrap_err(),
        E::SourceRoot
    );
    for (input, error) in [
        (
            BlockInput {
                parent_id: [99; 32],
                ..input
            },
            E::Parent,
        ),
        (BlockInput { height: 2, ..input }, E::Height),
    ] {
        assert_eq!(
            account_archive_execution::execute(
                &f.settings,
                &f.archive,
                f.checkpoint.id(),
                &parent.2,
                input,
                &valid,
            )
            .unwrap_err(),
            error
        );
    }
    let other_settings = Settings::development_with_profiles(
        Some(2),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    assert_eq!(
        account_archive_execution::execute(
            &other_settings,
            &f.archive,
            f.checkpoint.id(),
            &parent.2,
            input,
            &valid,
        )
        .unwrap_err(),
        E::Context
    );
    let mut tampered = valid.clone();
    tampered[0].account = None;
    assert_eq!(
        f.execute(&txs, 0, &tampered).unwrap_err(),
        E::Archive(ArchiveError::InvalidWitness)
    );
    let duplicated = vec![valid[0].clone(), valid[0].clone()];
    assert_eq!(
        f.execute(&txs, 0, &duplicated).unwrap_err(),
        E::Archive(ArchiveError::InvalidWitness)
    );
    let budget = WitnessBudget::for_block(&f.settings, parent.2.len(), txs.len()).unwrap();
    let owners: Vec<_> = (0..=budget.maximum_accounts as u64).collect();
    assert_eq!(
        f.execute(&txs, 0, &f.witnesses(&owners)).unwrap_err(),
        E::Budget
    );
    let priority = vec![
        transfer(&f.settings, 0, 2, 1, 1),
        transfer(&f.settings, 2, 1, 3, 1),
    ];
    // No proof for the later sender is supplied. Its missing witness cannot
    // replace the earlier canonical nonce failure.
    assert_eq!(
        f.execute(&priority, 0, &f.witnesses(&[0])).unwrap_err(),
        E::Relation("NONCE")
    );
    let mut wrong_signature = priority;
    *wrong_signature[0].last_mut().unwrap() ^= 1;
    assert_eq!(
        f.execute(&wrong_signature, 0, &f.witnesses(&[0]))
            .unwrap_err(),
        E::Relation("SIGNATURE")
    );
    assert_eq!(f.node.read_active().unwrap(), parent);
    assert_eq!(rows(&f.archive_path), original_rows);
}

#[test]
fn checked_accounts_gate_new_miner_future_reservation_and_late_cancellation_without_publication() {
    let f = Fixture::new();
    let original = f.node.read_active().unwrap();
    let original_rows = rows(&f.archive_path);
    // An immature reward creates no account yet, but its future recipient must
    // be authenticated under the selected continuity capacity relation.
    assert_eq!(
        f.execute(&[], 70, &[]).unwrap_err(),
        E::MissingWitness { owner: public(70) }
    );
    let checked = f.execute(&[], 70, &f.witnesses(&[70])).unwrap();
    assert_eq!(checked.observation.parent_account_count, 4);
    assert_eq!(checked.observation.successor_account_count, 4);
    assert_eq!(
        checked
            .observation
            .successor_capacity
            .unwrap()
            .credit_account_reserve,
        1
    );
    let witnesses = f.witnesses(&[70]);
    assert_eq!(
        account_archive_execution::execute_with_progress(
            &f.settings,
            &f.archive,
            f.checkpoint.id(),
            &original.2,
            BlockInput {
                transactions: &[],
                height: 1,
                miner: public(70),
                parent_id: original.0,
            },
            &witnesses,
            &|phase| {
                if phase == ExecutionProgress::BeforeOutput {
                    Err(E::Cancelled)
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err(),
        E::Cancelled
    );
    assert_eq!(f.node.read_active().unwrap(), original);
    assert_eq!(rows(&f.archive_path), original_rows);
}

#[test]
fn checked_accounts_apply_reward_maturity_before_next_nonce_spend_and_refuse_old_branch_proof() {
    let mut f = Fixture::new();
    let fee = transfer_fee(&f.settings);
    f.accept(
        vec![
            transfer(&f.settings, 0, 1, 10, fee + 7),
            transfer(&f.settings, 10, 1, 1, 7),
        ],
        10,
        &[0, 1, 10],
    );
    let prior_proof = f.witnesses(&[10]).remove(0);
    for _height in 2..=20 {
        f.accept(vec![], 0, &[0, 10]);
    }
    let before = f.node.read_active().unwrap();
    assert_eq!(
        before.2[&format!("account:{}", hex::encode(public(10)))],
        json!({"balance":0,"nonce":1})
    );
    let txs = vec![transfer(&f.settings, 10, 2, 1, 1)];
    let original_rows = rows(&f.archive_path);
    assert_eq!(
        f.execute(&txs, 0, &f.witnesses(&[0, 1])).unwrap_err(),
        E::MissingWitness { owner: public(10) }
    );
    let mut stale = f.witnesses(&[0, 1]);
    stale.push(prior_proof);
    assert_eq!(
        f.execute(&txs, 0, &stale).unwrap_err(),
        E::Archive(ArchiveError::InvalidWitness)
    );
    assert_eq!(rows(&f.archive_path), original_rows);
    let after = f.accept(txs, 0, &[0, 1, 10]);
    assert_eq!(
        after.output.state[&format!("account:{}", hex::encode(public(10)))]["nonce"],
        2
    );
    assert!(
        after.output.state[&format!("account:{}", hex::encode(public(10)))]["balance"]
            .as_u64()
            .unwrap()
            > 0
    );
}

#[test]
fn checked_accounts_gate_real_legacy_expiry_refund_without_continuity_or_transaction_masking() {
    let mut f = Fixture::with_settings(Settings::development(Some(1)).unwrap());
    let budget = 1000_u64;
    let deadline = 2_u64;
    let nonce = 1_u64;
    let task = hash(
        b"task-instance-v3",
        &[
            &f.settings.network(),
            &f.settings.parameters(),
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
    let reserve = signed(&f.settings, 0, nonce, 2, payload);
    // Legacy rules do not consult the immature miner recipient's existence.
    let first = f.accept(vec![reserve], 70, &[0]);
    assert_eq!(first.observation.parent_capacity, None);
    assert_eq!(first.observation.successor_capacity, None);
    let parent = f.node.read_active().unwrap();
    let original_rows = rows(&f.archive_path);
    // At height2 there are no transactions or matured rewards. This missing
    // witness is reached specifically by credit_state's expiry refund path.
    assert_eq!(
        f.execute(&[], 0, &[]).unwrap_err(),
        E::MissingWitness { owner: public(0) }
    );
    assert_eq!(f.node.read_active().unwrap(), parent);
    assert_eq!(rows(&f.archive_path), original_rows);
    let after = f.accept(vec![], 0, &[0]);
    let account = format!("account:{}", hex::encode(public(0)));
    assert_eq!(
        after.output.state[&account]["balance"].as_u64().unwrap(),
        parent.2[&account]["balance"].as_u64().unwrap() + budget
    );
    assert_eq!(after.output.state[&account]["nonce"], 1);
    let task_key = format!("task:{}", hex::encode(task));
    assert_eq!(after.output.state[&task_key]["remaining"], 0);
    assert_eq!(after.output.state[&task_key]["status"], "expired");
    assert_eq!(
        after.output.receipts,
        vec![serde_json::to_vec(&json!({"expiry":task_key})).unwrap()]
    );
}

#[test]
fn authenticated_state_preserves_signed_same_block_overlay_and_both_proof_phases() {
    let mut f = Fixture::new();
    let fee = transfer_fee(&f.settings);
    let transactions = vec![
        transfer(&f.settings, 0, 1, 10, 10_000),
        transfer(&f.settings, 10, 1, 1, 10_000 - fee),
        transfer(&f.settings, 0, 2, 0, 1),
    ];
    let original = f.node.read_active().unwrap();
    let original_rows = rows(&f.archive_path);
    let witness = account_archive_execution::prepare_state_witness(
        &f.settings,
        &f.archive,
        f.checkpoint.id(),
        &original.2,
    )
    .unwrap();
    // Unique proof order is deliberately independent of canonical changed-owner
    // order, just as the original v1 account input contract permits.
    let proofs = f.witnesses(&[10, 1, 0]);
    let checked = account_archive_execution::execute_with_state_witness(
        &f.settings,
        &f.archive,
        f.checkpoint.id(),
        &original.2,
        BlockInput {
            transactions: &transactions,
            height: 1,
            miner: public(0),
            parent_id: original.0,
        },
        StateExecutionInput {
            accounts: &proofs,
            state: &witness,
        },
    )
    .unwrap();
    let legacy = f.execute(&transactions, 0, &proofs).unwrap();
    assert_eq!(checked.execution.output.state, legacy.output.state);
    assert_eq!(checked.execution.output.root, legacy.output.root);
    assert_eq!(checked.execution.output.receipts, legacy.output.receipts);
    assert_eq!(checked.execution.observation, legacy.observation);
    let observed = &checked.state_observation;
    assert_eq!(observed.parent.account_count, 4);
    assert_eq!(observed.mandatory.commitment.account_count, 4);
    assert!(observed.mandatory.account_changes.is_empty());
    assert_eq!(observed.successor.commitment.account_count, 5);
    assert_eq!(observed.successor.account_changes.len(), 3);
    assert_eq!(observed.successor.commitment.state_root, legacy.output.root);
    assert_eq!(
        observed.successor.commitment.account_balance
            + observed.successor.commitment.escrow_balance
            + observed.successor.commitment.reward_balance,
        observed.successor.commitment.issued
    );
    let created = observed
        .successor
        .account_changes
        .iter()
        .find(|change| change.owner == public(10))
        .unwrap();
    assert_eq!(created.before, None);
    assert_eq!(created.after.balance, 0);
    assert_eq!(created.after.nonce, 1);
    assert_eq!(f.node.read_active().unwrap(), original);
    assert_eq!(rows(&f.archive_path), original_rows);
    let admitted = f.accept(transactions, 0, &[0, 1, 10]);
    assert_eq!(checked.execution.output.state, admitted.output.state);
    assert_eq!(
        observed.successor.commitment.account_root,
        f.checkpoint.account_root()
    );
}

#[test]
fn authenticated_state_rejects_partition_claims_and_late_cancellation_without_publication() {
    let f = Fixture::new();
    let original = f.node.read_active().unwrap();
    let original_rows = rows(&f.archive_path);
    let transactions = vec![transfer(&f.settings, 0, 1, 1, 1)];
    let proofs = f.witnesses(&[0, 1]);
    let witness = account_archive_execution::prepare_state_witness(
        &f.settings,
        &f.archive,
        f.checkpoint.id(),
        &original.2,
    )
    .unwrap();
    let block = BlockInput {
        transactions: &transactions,
        height: 1,
        miner: public(0),
        parent_id: original.0,
    };
    let mut omitted = witness.clone();
    omitted
        .non_accounts
        .retain(|row| row.key != continuity_v1::MAINTENANCE_KEY);
    let mut duplicate = witness.clone();
    duplicate
        .non_accounts
        .insert(0, duplicate.non_accounts[0].clone());
    let mut wrong_claim = witness.clone();
    wrong_claim.commitment.account_balance -= 1;
    let mut wrong_context = witness.clone();
    wrong_context.parent_id[0] ^= 1;
    for (invalid, expected) in [
        (omitted, S::Partition),
        (duplicate, S::CanonicalOrder),
        (wrong_claim, S::Commitment),
        (wrong_context, S::Context),
    ] {
        assert_eq!(
            account_archive_execution::execute_with_state_witness(
                &f.settings,
                &f.archive,
                f.checkpoint.id(),
                &original.2,
                block,
                StateExecutionInput {
                    accounts: &proofs,
                    state: &invalid
                },
            )
            .unwrap_err(),
            E::StateWitness(expected)
        );
    }
    for stop in [
        P::BeforeMandatoryVerification,
        P::AfterMandatoryVerification,
        P::BeforeSuccessorVerification,
        P::AfterSuccessorVerification,
        P::BeforeOutput,
    ] {
        let phases = Mutex::new(Vec::new());
        assert_eq!(
            account_archive_execution::execute_with_state_witness_and_progress(
                &f.settings,
                &f.archive,
                f.checkpoint.id(),
                &original.2,
                block,
                StateExecutionInput {
                    accounts: &proofs,
                    state: &witness
                },
                &|point| {
                    phases.lock().unwrap().push(point);
                    if point == stop {
                        Err(E::Cancelled)
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err(),
            E::Cancelled
        );
        let phases = phases.into_inner().unwrap();
        assert_eq!(phases.last(), Some(&stop));
        if matches!(
            stop,
            P::BeforeMandatoryVerification | P::AfterMandatoryVerification
        ) {
            assert!(!phases.iter().any(|point| matches!(
                point,
                P::Execution(ExecutionProgress::BeforePrepare { .. })
            )));
        }
        assert_eq!(f.node.read_active().unwrap(), original);
        assert_eq!(rows(&f.archive_path), original_rows);
    }
}

#[test]
fn authenticated_state_checks_real_expiry_and_maturity_before_signed_spend() {
    let mut f = Fixture::with_settings(Settings::development(Some(1)).unwrap());
    let budget = 1000u64;
    let deadline = 21u64;
    let nonce = 1u64;
    let task = hash(
        b"task-instance-v3",
        &[
            &f.settings.network(),
            &f.settings.parameters(),
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
    let reserve = signed(&f.settings, 0, nonce, 2, payload);
    f.accept(vec![reserve], 70, &[0]);
    for _height in 2..=20 {
        f.accept(vec![], 0, &[]);
    }
    let original = f.node.read_active().unwrap();
    let witness = account_archive_execution::prepare_state_witness(
        &f.settings,
        &f.archive,
        f.checkpoint.id(),
        &original.2,
    )
    .unwrap();
    let proofs = f.witnesses(&[0, 1, 70]);
    let transactions = vec![transfer(&f.settings, 70, 1, 1, 1)];
    let checked = account_archive_execution::execute_with_state_witness(
        &f.settings,
        &f.archive,
        f.checkpoint.id(),
        &original.2,
        BlockInput {
            transactions: &transactions,
            height: 21,
            miner: public(0),
            parent_id: original.0,
        },
        StateExecutionInput {
            accounts: &proofs,
            state: &witness,
        },
    )
    .unwrap();
    let observed = &checked.state_observation;
    assert_eq!(observed.mandatory.commitment.issued, observed.parent.issued);
    assert_eq!(observed.parent.escrow_balance, budget);
    assert_eq!(observed.mandatory.commitment.escrow_balance, 0);
    assert_eq!(
        observed.mandatory.commitment.account_count,
        observed.parent.account_count + 1
    );
    assert_eq!(
        observed.mandatory.receipts,
        vec![serde_json::to_vec(&json!({"expiry":format!("task:{}",hex::encode(task))})).unwrap()]
    );
    let mature = observed
        .mandatory
        .account_changes
        .iter()
        .find(|change| change.owner == public(70))
        .unwrap();
    assert_eq!(mature.before, None);
    assert_eq!(mature.after.nonce, 0);
    let spent = observed
        .successor
        .account_changes
        .iter()
        .find(|change| change.owner == public(70))
        .unwrap();
    assert_eq!(spent.before, None);
    assert_eq!(spent.after.nonce, 1);
    assert!(mature.after.balance > spent.after.balance);
    let admitted = f.accept(transactions, 0, &[0, 1, 70]);
    assert_eq!(checked.execution.output.state, admitted.output.state);
    assert_eq!(
        observed.successor.commitment.account_root,
        f.checkpoint.account_root()
    );
}

#[test]
fn authenticated_state_discovers_more_than_32_real_mandatory_recipients_and_preserves_native_order()
{
    let mut f = Fixture::new();
    let export_path = std::env::var_os("TRNM_ACCOUNT_MULTIPROOF_VECTORS").map(PathBuf::from);
    if let Some(path) = &export_path {
        assert!(!path.exists(), "fresh multiproof vector path required");
    }
    let genesis_checkpoint = f.checkpoint.clone();
    let mut exported = Vec::new();
    let owners: Vec<_> = std::iter::once(0).chain(100..140).collect();
    // Forty independently signed owners, forty genuine pending obligations, and
    // three legal deadline buckets (the installed expiry limit remains sixteen).
    // No injected account/escrow state or enlarged installed limits are used.
    let funding: Vec<_> = (100..140)
        .map(|owner| transfer(&f.settings, 0, owner - 99, owner, 5_000))
        .collect();
    let genesis = f.node.read_active().unwrap();
    let discovered_funding = obligations::prepare(
        &f.settings,
        &f.archive,
        f.checkpoint.id(),
        &genesis.2,
        BlockInput {
            transactions: &funding,
            height: 1,
            miner: public(0),
            parent_id: genesis.0,
        },
    )
    .unwrap();
    assert_eq!(discovered_funding.accounts.len(), 41);
    assert_eq!(discovered_funding.observation.transaction_owners.len(), 41);
    let funding_state = account_archive_execution::prepare_state_witness(
        &f.settings,
        &f.archive,
        f.checkpoint.id(),
        &genesis.2,
    )
    .unwrap();
    let checked_funding = account_archive_execution::execute_with_state_witness(
        &f.settings,
        &f.archive,
        f.checkpoint.id(),
        &genesis.2,
        BlockInput {
            transactions: &funding,
            height: 1,
            miner: public(0),
            parent_id: genesis.0,
        },
        StateExecutionInput {
            accounts: &discovered_funding.accounts,
            state: &funding_state,
        },
    )
    .unwrap();
    assert_eq!(
        checked_funding
            .state_observation
            .successor
            .account_changes
            .len(),
        41
    );
    if export_path.is_some() {
        exported.push(compact_native_export_step(&f, &funding, 0, "funding"));
    }
    assert_eq!(
        f.accept(funding, 0, &owners).output.state,
        checked_funding.execution.output.state
    );
    if let Some(row) = exported.last_mut() {
        row["admitted_id"] = json!(f.checkpoint.branch());
        row["packet_hex"] = json!(hex::encode(
            f.node
                .packet(f.checkpoint.branch())
                .unwrap()
                .encode()
                .unwrap()
        ));
    }

    let reservations: Vec<_> = (100..140)
        .map(|owner| {
            let nonce = 1u64;
            let budget = 1_000u64;
            let deadline = 3 + (owner - 100) / 16;
            let task = hash(
                b"task-instance-v3",
                &[
                    &f.settings.network(),
                    &f.settings.parameters(),
                    &public(owner),
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
            signed(&f.settings, owner, nonce, 2, payload)
        })
        .collect();
    if export_path.is_some() {
        exported.push(compact_native_export_step(
            &f,
            &reservations,
            0,
            "reservations",
        ));
    }
    f.accept(reservations, 0, &owners);
    if let Some(row) = exported.last_mut() {
        row["admitted_id"] = json!(f.checkpoint.branch());
        row["packet_hex"] = json!(hex::encode(
            f.node
                .packet(f.checkpoint.branch())
                .unwrap()
                .encode()
                .unwrap()
        ));
    }
    let parent = f.node.read_active().unwrap();
    let original_rows = rows(&f.archive_path);
    let block = BlockInput {
        transactions: &[],
        height: 3,
        miner: public(0),
        parent_id: parent.0,
    };
    let discovered =
        obligations::prepare(&f.settings, &f.archive, f.checkpoint.id(), &parent.2, block).unwrap();
    assert_eq!(discovered.accounts.len(), 41);
    assert_eq!(discovered.observation.mandatory_owners.len(), 41);
    assert!(discovered.observation.transaction_owners.is_empty());
    assert_eq!(discovered.observation.successor_owners.len(), 25);
    assert_eq!(
        discovered.observation.encoded_witness_bytes,
        discovered
            .accounts
            .iter()
            .map(|proof| proof.encode().unwrap().len())
            .sum::<usize>(),
    );
    assert!(discovered.observation.recheck_required);
    assert!(!discovered.observation.consensus_admission);
    let state = account_archive_execution::prepare_state_witness(
        &f.settings,
        &f.archive,
        f.checkpoint.id(),
        &parent.2,
    )
    .unwrap();
    let checked = account_archive_execution::execute_with_state_witness(
        &f.settings,
        &f.archive,
        f.checkpoint.id(),
        &parent.2,
        block,
        StateExecutionInput {
            accounts: &discovered.accounts,
            state: &state,
        },
    )
    .unwrap();
    assert_eq!(
        checked.state_observation.mandatory.account_changes.len(),
        16
    );
    assert_eq!(checked.state_observation.mandatory.receipts.len(), 16);
    assert_eq!(
        checked
            .state_observation
            .mandatory
            .commitment
            .escrow_balance,
        24_000
    );
    assert_eq!(
        checked.execution.output.root,
        discovered.observation.successor_state_root
    );
    assert_eq!(
        checked.execution.observation.used_owners,
        discovered.observation.requested_owners
    );
    let compact =
        obligations::prepare_compact(&f.settings, &f.archive, f.checkpoint.id(), &parent.2, block)
            .unwrap();
    assert_eq!(compact.accounts.accounts.len(), 41);
    assert_eq!(compact.construction.expanded_witnesses_allocated, 0);
    assert_eq!(
        compact.observation.requested_owners,
        discovered.observation.requested_owners
    );
    assert_eq!(
        compact.observation.mandatory_owners,
        discovered.observation.mandatory_owners
    );
    assert_eq!(
        compact.observation.successor_owners,
        discovered.observation.successor_owners
    );
    assert!(
        compact.observation.encoded_witness_bytes * 50
            < discovered.observation.encoded_witness_bytes
    );
    let compact_bytes = compact.accounts.encode().unwrap();
    let compact_accounts =
        trnm_pon_node::account_archive_prototype::multiproof::Multiproof::decode(&compact_bytes)
            .unwrap();
    let compact_checked = account_archive_execution::execute_with_compact_state_witness(
        &f.settings,
        &f.archive,
        f.checkpoint.id(),
        &parent.2,
        block,
        CompactStateExecutionInput {
            accounts: &compact_accounts,
            state: &state,
        },
    )
    .unwrap();
    assert_eq!(
        compact_checked.execution.execution.output.state,
        checked.execution.output.state
    );
    assert_eq!(
        compact_checked.execution.execution.output.receipts,
        checked.execution.output.receipts
    );
    assert_eq!(
        compact_checked.execution.execution.observation,
        checked.execution.observation
    );
    assert_eq!(
        compact_checked.execution.state_observation,
        checked.state_observation
    );
    assert_eq!(
        compact_checked.account_proof.encoded_bytes,
        compact_bytes.len()
    );
    // A valid smaller multiproof still cannot hide a future reservation owner.
    let fewer: Vec<_> = compact
        .observation
        .requested_owners
        .iter()
        .copied()
        .filter(|owner| *owner != public(139))
        .collect();
    let omitted_compact = f.archive.multiproof(f.checkpoint.id(), &fewer).unwrap().0;
    assert_eq!(
        account_archive_execution::execute_with_compact_state_witness(
            &f.settings,
            &f.archive,
            f.checkpoint.id(),
            &parent.2,
            block,
            CompactStateExecutionInput {
                accounts: &omitted_compact,
                state: &state
            },
        )
        .unwrap_err(),
        E::MissingWitness { owner: public(139) },
    );
    for stop in [
        P::AccountUpdate {
            phase: StatePhase::Mandatory,
            index: 0,
        },
        P::BeforeSuccessorVerification,
        P::BeforeOutput,
    ] {
        assert_eq!(
            account_archive_execution::execute_with_compact_state_witness_and_progress(
                &f.settings,
                &f.archive,
                f.checkpoint.id(),
                &parent.2,
                block,
                CompactStateExecutionInput {
                    accounts: &compact_accounts,
                    state: &state
                },
                &|point| if point == stop {
                    Err(E::Cancelled)
                } else {
                    Ok(())
                },
            )
            .unwrap_err(),
            E::Cancelled
        );
    }
    // The future recipient is needed by the original capacity scan even though
    // it receives no credit at this height. Neither discovery nor full State can
    // repair a caller's later omission from the independently checked input.
    for owner in [100, 139] {
        let omitted: Vec<_> = discovered
            .accounts
            .iter()
            .filter(|proof| proof.owner != public(owner))
            .cloned()
            .collect();
        assert_eq!(
            account_archive_execution::execute_with_state_witness(
                &f.settings,
                &f.archive,
                f.checkpoint.id(),
                &parent.2,
                block,
                StateExecutionInput {
                    accounts: &omitted,
                    state: &state
                },
            )
            .unwrap_err(),
            E::MissingWitness {
                owner: public(owner)
            },
        );
    }
    let mut damaged = discovered.accounts.clone();
    damaged[33].siblings[200][0] ^= 1;
    let boundaries = AtomicUsize::new(0);
    assert_eq!(
        account_archive_execution::execute_with_progress(
            &f.settings,
            &f.archive,
            f.checkpoint.id(),
            &parent.2,
            block,
            &damaged,
            &|point| {
                if point == ExecutionProgress::BeforeParentBinding
                    && boundaries.fetch_add(1, Ordering::SeqCst) == 2
                {
                    Err(E::Cancelled)
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err(),
        E::Cancelled,
    );
    assert_eq!(
        f.execute(&[], 0, &damaged).unwrap_err(),
        E::Archive(ArchiveError::InvalidWitness)
    );
    let mut duplicate_across_batches = discovered.accounts.clone();
    duplicate_across_batches[32] = duplicate_across_batches[0].clone();
    assert_eq!(
        f.execute(&[], 0, &duplicate_across_batches).unwrap_err(),
        E::Archive(ArchiveError::InvalidWitness)
    );
    let mut omitted_obligation = state.clone();
    let index = omitted_obligation
        .non_accounts
        .iter()
        .position(|row| row.key.starts_with("task:") && row.value["deadline"] == 5)
        .unwrap();
    omitted_obligation.non_accounts.remove(index);
    assert_eq!(
        account_archive_execution::execute_with_state_witness(
            &f.settings,
            &f.archive,
            f.checkpoint.id(),
            &parent.2,
            block,
            StateExecutionInput {
                accounts: &discovered.accounts,
                state: &omitted_obligation
            },
        )
        .unwrap_err(),
        E::StateWitness(S::Partition),
    );
    for stop in [
        D::AccountAccess { owner: public(139) },
        D::Witness { index: 32 },
        D::BeforeOutput,
    ] {
        assert_eq!(
            obligations::prepare_with_progress(
                &f.settings,
                &f.archive,
                f.checkpoint.id(),
                &parent.2,
                block,
                &|point| if point == stop {
                    Err(E::Cancelled)
                } else {
                    Ok(())
                },
            )
            .unwrap_err(),
            E::Cancelled,
        );
    }
    let stop = P::AccountMerge {
        phase: StatePhase::Mandatory,
        index: 7,
    };
    assert_eq!(
        account_archive_execution::execute_with_state_witness_and_progress(
            &f.settings,
            &f.archive,
            f.checkpoint.id(),
            &parent.2,
            block,
            StateExecutionInput {
                accounts: &discovered.accounts,
                state: &state
            },
            &|point| if point == stop {
                Err(E::Cancelled)
            } else {
                Ok(())
            },
        )
        .unwrap_err(),
        E::Cancelled,
    );
    assert_eq!(f.node.read_active().unwrap(), parent);
    assert_eq!(rows(&f.archive_path), original_rows);
    if export_path.is_some() {
        exported.push(compact_native_export_step(&f, &[], 0, "expiry"));
    }
    assert_eq!(
        f.accept(vec![], 0, &owners).output.state,
        checked.execution.output.state
    );
    if let Some(row) = exported.last_mut() {
        row["admitted_id"] = json!(f.checkpoint.branch());
        row["packet_hex"] = json!(hex::encode(
            f.node
                .packet(f.checkpoint.branch())
                .unwrap()
                .encode()
                .unwrap()
        ));
    }
    if let Some(path) = export_path {
        let observation = json!({
            "schema": "pon-account-multiproof-native-observation-v1",
            "context": {
                "network": f.settings.network(),
                "parameters": f.settings.parameters(),
                "genesis": f.settings.genesis(),
            },
            "genesis_state": genesis.2,
            "genesis_checkpoint": genesis_checkpoint,
            "blocks": exported,
            "scope": {
                "actual_signed_node_admission": true,
                "direct_archive_collection": true,
                "complete_state_reference_required": true,
                "public_availability_accepted": false,
                "production_activation": false,
            },
        });
        std::fs::write(path, serde_json::to_vec_pretty(&observation).unwrap()).unwrap();
    }
}

fn compact_native_export_step(
    f: &Fixture,
    txs: &[Vec<u8>],
    miner: u64,
    label: &str,
) -> serde_json::Value {
    let parent = f.node.state_at(f.checkpoint.branch()).unwrap();
    let block = BlockInput {
        transactions: txs,
        height: f.checkpoint.height() + 1,
        miner: public(miner),
        parent_id: f.checkpoint.branch(),
    };
    let prepared =
        obligations::prepare_compact(&f.settings, &f.archive, f.checkpoint.id(), &parent, block)
            .unwrap();
    let state = account_archive_execution::prepare_state_witness(
        &f.settings,
        &f.archive,
        f.checkpoint.id(),
        &parent,
    )
    .unwrap();
    let checked = account_archive_execution::execute_with_compact_state_witness(
        &f.settings,
        &f.archive,
        f.checkpoint.id(),
        &parent,
        block,
        CompactStateExecutionInput {
            accounts: &prepared.accounts,
            state: &state,
        },
    )
    .unwrap();
    // Preserve the actual raw M06 mandatory callback State independently of the
    // compact transition's reported deltas; the Python oracle checks both.
    let partition = parent
        .iter()
        .filter(|(key, _)| !key.starts_with("account:"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    // This public M06 reference has its own installed configuration. Reproduce
    // the fixture's explicit genesis selection and verify the exact parameter
    // digest before it can produce an artifact comparison.
    let mut app =
        Config::installed_with_profiles("native-public-evaluation-dev-v1", continuity_v1::PROFILE)
            .unwrap();
    app.params["genesis_timestamp"] = json!(1);
    let chain_label = format!(
        "trnm-pon-task-lifecycle-wall-devnet-{}-native-public-evaluation-dev-v1-1-evaluation-storage{}",
        app.params["consensus_revision"].as_u64().unwrap(),
        trnm_mvcc_fee::public_evaluation::STORAGE_REVISION,
    );
    app.params["chain_label"] = json!(chain_label);
    app.network = hash(b"network", &[chain_label.as_bytes()]);
    let wire: serde_json::Value =
        serde_json::from_str(include_str!("../../../../config/pon/ledger-v1.json")).unwrap();
    let work: serde_json::Value =
        serde_json::from_str(include_str!("../../../../config/pon/work-profile-v1.json")).unwrap();
    app.parameters = hash(
        b"parameters",
        &[
            &serde_json::to_vec(&app.params).unwrap(),
            &serde_json::to_vec(&wire).unwrap(),
            &serde_json::to_vec(&work).unwrap(),
            &serde_json::to_vec(&app.model_registry).unwrap(),
        ],
    );
    assert_eq!(app.network, f.settings.network());
    assert_eq!(app.parameters, f.settings.parameters());
    let mandatory = Mutex::new(None);
    let reference = pon_executor::execute_with_authenticated_state_input(
        &parent,
        pon_executor::BlockExecution {
            transactions: txs,
            height: block.height,
            miner: block.miner,
            parent_id: block.parent_id,
            workers: 1,
        },
        &app,
        &|_| Ok(()),
        &pon_executor::MandatoryStateInput {
            non_accounts: &partition,
            completed: &|_, after, _| {
                let mut retained = mandatory.lock().unwrap();
                assert!(retained.is_none());
                *retained = Some(after.clone());
                Ok(())
            },
        },
        &|_| Ok::<_, E>(()),
    )
    .unwrap();
    assert_eq!(reference.state, checked.execution.execution.output.state);
    assert_eq!(
        reference.receipts,
        checked.execution.execution.output.receipts
    );
    // Extra kernel executions record actual branch-hash counters and compare
    // their roots with the successful complete M06 phases. These are diagnostic
    // replay counts, never whole-execution timings or allocation measurements.
    let query = trnm_pon_node::account_archive_prototype::multiproof::CheckedMultiproof::verify(
        Context {
            network: f.settings.network(),
            parameters: f.settings.parameters(),
            genesis: f.settings.genesis(),
        },
        &f.checkpoint,
        &prepared.accounts,
    )
    .unwrap();
    let update_observation = |phase: &account_archive_execution::state_witness::StateTransition| {
        let updates: Vec<_> = phase
            .account_changes
            .iter()
            .map(
                |change| trnm_pon_node::account_archive_prototype::ResearchUpdate {
                    owner: change.owner,
                    before: change.before,
                    after: change.after,
                },
            )
            .collect();
        let (root, observation) = query
            .root_for_updates(&updates, &|_| Ok::<_, ArchiveError>(()))
            .unwrap();
        assert_eq!(root, phase.commitment.account_root);
        observation
    };
    let mandatory_update_observation =
        update_observation(&checked.execution.state_observation.mandatory);
    let successor_update_observation =
        update_observation(&checked.execution.state_observation.successor);
    json!({
        "label": label,
        "height": block.height,
        "parent": block.parent_id,
        "miner": block.miner,
        "transactions_hex": txs.iter().map(hex::encode).collect::<Vec<_>>(),
        "parent_state": parent,
        "parent_checkpoint": f.checkpoint,
        "requested": prepared.observation.requested_owners,
        "proof_hex": hex::encode(prepared.accounts.encode().unwrap()),
        "proof": prepared.accounts,
        "construction": prepared.construction,
        "mandatory_state": mandatory.into_inner().unwrap().unwrap(),
        "mandatory_updates": checked.execution.state_observation.mandatory.account_changes,
        "mandatory_account_root": checked.execution.state_observation.mandatory.commitment.account_root,
        "mandatory_update_observation": mandatory_update_observation,
        "successor_state": reference.state,
        "successor_updates": checked.execution.state_observation.successor.account_changes,
        "successor_account_root": checked.execution.state_observation.successor.commitment.account_root,
        "successor_update_observation": successor_update_observation,
    })
}

#[test]
fn compact_authenticated_execution_binds_signed_overlay_aggregates_and_cancellation() {
    let mut f = Fixture::new();
    let parent = f.node.read_active().unwrap();
    let original_rows = rows(&f.archive_path);
    let txs = vec![
        transfer(&f.settings, 0, 1, 100, 100_000),
        transfer(&f.settings, 100, 1, 101, 10_000),
        transfer(&f.settings, 101, 1, 101, 1),
    ];
    let block = BlockInput {
        transactions: &txs,
        height: 1,
        miner: public(0),
        parent_id: parent.0,
    };
    let prepared =
        obligations::prepare_compact(&f.settings, &f.archive, f.checkpoint.id(), &parent.2, block)
            .unwrap();
    let state = account_archive_execution::prepare_state_witness(
        &f.settings,
        &f.archive,
        f.checkpoint.id(),
        &parent.2,
    )
    .unwrap();
    let execute = |proof: &_, state: &_| {
        account_archive_execution::execute_with_compact_state_witness(
            &f.settings,
            &f.archive,
            f.checkpoint.id(),
            &parent.2,
            block,
            CompactStateExecutionInput {
                accounts: proof,
                state,
            },
        )
    };
    let checked = execute(&prepared.accounts, &state).unwrap();
    assert_eq!(checked.account_proof.accounts, 3);
    assert_eq!(
        checked
            .execution
            .state_observation
            .successor
            .commitment
            .account_count,
        checked.execution.state_observation.parent.account_count + 2
    );
    let mut extra = prepared.observation.requested_owners.clone();
    extra.push(public(999));
    let extra = f.archive.multiproof(f.checkpoint.id(), &extra).unwrap().0;
    assert_eq!(
        execute(&extra, &state).unwrap_err(),
        E::UnusedWitness {
            owners: vec![public(999)]
        }
    );
    for field in 0..4 {
        let mut wrong = state.clone();
        match field {
            0 => wrong.commitment.account_count += 1,
            1 => wrong.commitment.account_balance -= 1,
            2 => wrong.commitment.account_root[0] ^= 1,
            _ => wrong.commitment.id[0] ^= 1,
        }
        assert_eq!(
            execute(&prepared.accounts, &wrong).unwrap_err(),
            E::StateWitness(S::Commitment)
        );
    }
    let mut wrong_partition = state.clone();
    wrong_partition.non_accounts.pop();
    assert_eq!(
        execute(&prepared.accounts, &wrong_partition).unwrap_err(),
        E::StateWitness(S::Partition)
    );
    let mut wrong_leaf = prepared.accounts.clone();
    let present = wrong_leaf
        .accounts
        .iter_mut()
        .find(|account| account.account.is_some())
        .unwrap();
    present.account.as_mut().unwrap().nonce += 1;
    assert_eq!(
        execute(&wrong_leaf, &state).unwrap_err(),
        E::Archive(ArchiveError::InvalidWitness)
    );
    let seen = AtomicUsize::new(0);
    assert_eq!(
        account_archive_execution::execute_with_compact_state_witness_and_progress(
            &f.settings,
            &f.archive,
            f.checkpoint.id(),
            &parent.2,
            block,
            CompactStateExecutionInput {
                accounts: &prepared.accounts,
                state: &state
            },
            &|point| if point == P::Execution(ExecutionProgress::BeforeParentBinding)
                && seen.fetch_add(1, Ordering::SeqCst) == 3
            {
                Err(E::Cancelled)
            } else {
                Ok(())
            },
        )
        .unwrap_err(),
        E::Cancelled
    );
    assert_eq!(f.node.read_active().unwrap(), parent);
    assert_eq!(rows(&f.archive_path), original_rows);
    let native = f.accept(txs, 0, &[0, 100, 101]);
    assert_eq!(
        native.output.state,
        checked.execution.execution.output.state
    );
    assert_eq!(
        native.output.receipts,
        checked.execution.execution.output.receipts
    );
}

#[test]
fn witness_discovery_preserves_invalid_transaction_order_and_requires_available_archive_bytes() {
    let f = Fixture::new();
    let parent = f.node.read_active().unwrap();
    let txs = vec![
        transfer(&f.settings, 0, 2, 1, 1),
        transfer(&f.settings, 2, 1, 3, 1),
    ];
    let block = BlockInput {
        transactions: &txs,
        height: 1,
        miner: public(0),
        parent_id: parent.0,
    };
    assert_eq!(
        obligations::prepare(&f.settings, &f.archive, f.checkpoint.id(), &parent.2, block)
            .unwrap_err(),
        E::Relation("NONCE"),
    );
    let valid = vec![transfer(&f.settings, 0, 1, 10, 1)];
    let original_node = f.node.read_active().unwrap();
    // Actual archived node loss cannot turn a missing witness into default zero
    // during discovery. This disposable archive is deliberately corrupted.
    let db = Connection::open(&f.archive_path).unwrap();
    db.execute("DELETE FROM archive_nodes", []).unwrap();
    assert!(matches!(
        obligations::prepare(
            &f.settings,
            &f.archive,
            f.checkpoint.id(),
            &parent.2,
            BlockInput {
                transactions: &valid,
                ..block
            },
        ),
        Err(E::Archive(ArchiveError::DataUnavailable)),
    ));
    assert_eq!(f.node.read_active().unwrap(), original_node);
}

#[test]
fn witness_discovery_includes_settlement_provider_from_parent_record() {
    let mut f = Fixture::new();
    let nonce = 2u64;
    let budget = 1_000u64;
    let deadline = 5u64;
    let task = hash(
        b"task-instance-v3",
        &[
            &f.settings.network(),
            &f.settings.parameters(),
            &public(0),
            &nonce.to_le_bytes(),
            &public(70),
            &budget.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let mut reserve = task.to_vec();
    reserve.extend(public(70));
    reserve.extend(budget.to_le_bytes());
    reserve.extend(deadline.to_le_bytes());
    f.accept(
        vec![
            transfer(&f.settings, 0, 1, 70, 5_000),
            signed(&f.settings, 0, nonce, 2, reserve),
        ],
        0,
        &[0, 70],
    );
    let mut output = task.to_vec();
    output.extend([7; 32]);
    f.accept(
        vec![signed(&f.settings, 70, 1, 4, output.clone())],
        0,
        &[0, 70],
    );
    let settlement = vec![signed(&f.settings, 0, 3, 5, output)];
    let parent = f.node.read_active().unwrap();
    let prepared = obligations::prepare(
        &f.settings,
        &f.archive,
        f.checkpoint.id(),
        &parent.2,
        BlockInput {
            transactions: &settlement,
            height: 3,
            miner: public(0),
            parent_id: parent.0,
        },
    )
    .unwrap();
    let mut expected = vec![public(0), public(70)];
    expected.sort_unstable();
    assert_eq!(prepared.observation.transaction_owners, expected);
    assert_eq!(
        f.execute(&settlement, 0, &f.witnesses(&[0])).unwrap_err(),
        E::MissingWitness { owner: public(70) }
    );
    let checked = f.execute(&settlement, 0, &prepared.accounts).unwrap();
    assert_eq!(
        checked.output.root,
        prepared.observation.successor_state_root
    );
    assert_eq!(
        f.accept(settlement, 0, &[0, 70]).output.state,
        checked.output.state
    );
}
