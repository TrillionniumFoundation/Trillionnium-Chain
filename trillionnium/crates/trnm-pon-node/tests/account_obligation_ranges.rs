//! Real signed Node transitions through the separately selected monetary-range
//! relation. The ordinary Node remains an independent complete-State route.
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{
    continuity_v1,
    pon_executor::{self, Config, ExecutionProgress, State},
};
use trnm_pon_node::{
    account_archive_execution::{
        self as execution,
        obligation_ranges::{self, RangeError, RangeProof},
        obligations,
        state_witness::StateWitnessProgress as P,
        BlockInput, CheckedExecutionError as E, MonetaryStateExecutionInput,
    },
    account_archive_prototype::{AccountArchive, ArchiveError, Checkpoint, Context, Limits},
    development_public, sequence_root, Node, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

fn public(owner: u64) -> Hash {
    development_public(owner).unwrap()
}
fn signed(settings: &Settings, owner: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: public(owner),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&owner.to_le_bytes()]))).unwrap();
    tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    tx.encode().unwrap()
}
fn transfer(settings: &Settings, owner: u64, nonce: u64, recipient: u64, amount: u64) -> Vec<u8> {
    let mut payload = public(recipient).to_vec();
    payload.extend(amount.to_le_bytes());
    signed(settings, owner, nonce, 1, payload)
}
fn application(settings: &Settings) -> Config {
    let mut app =
        Config::installed_with_profiles("native-public-evaluation-dev-v1", continuity_v1::PROFILE)
            .unwrap();
    app.params["genesis_timestamp"] = json!(1);
    let label = format!("trnm-pon-task-lifecycle-wall-devnet-{}-native-public-evaluation-dev-v1-1-evaluation-storage{}",
        app.params["consensus_revision"].as_u64().unwrap(), trnm_mvcc_fee::public_evaluation::STORAGE_REVISION);
    app.params["chain_label"] = json!(label);
    app.network = hash(b"network", &[label.as_bytes()]);
    let wire: Value =
        serde_json::from_str(include_str!("../../../../config/pon/ledger-v1.json")).unwrap();
    let work: Value =
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
    assert_eq!(app.network, settings.network());
    assert_eq!(app.parameters, settings.parameters());
    app
}
struct Fixture {
    _directory: tempfile::TempDir,
    settings: Settings,
    app: Config,
    node: Node,
    archive: AccountArchive,
    checkpoint: Checkpoint,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development_with_profiles(
            Some(1),
            "native-public-evaluation-dev-v1",
            continuity_v1::PROFILE,
        )
        .unwrap();
        let app = application(&settings);
        let node = Node::open(&directory.path().join("node"), settings.clone(), 4).unwrap();
        let state = node.read_active().unwrap().2;
        let mut archive = AccountArchive::open(
            &directory.path().join("archive.sqlite"),
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
            _directory: directory,
            settings,
            app,
            node,
            archive,
            checkpoint,
        }
    }
    fn input<'a>(&self, txs: &'a [Vec<u8>], miner: u64) -> BlockInput<'a> {
        BlockInput {
            transactions: txs,
            height: self.checkpoint.height() + 1,
            miner: public(miner),
            parent_id: self.checkpoint.branch(),
        }
    }
    fn proof(&self, parent: &State) -> RangeProof {
        obligation_ranges::prepare(&self.settings, &self.archive, self.checkpoint.id(), parent)
            .unwrap()
    }
    fn accept(&mut self, txs: Vec<Vec<u8>>, miner: u64, label: String) -> Value {
        let parent = self.node.state_at(self.checkpoint.branch()).unwrap();
        let block = self.input(&txs, miner);
        let accounts = obligations::prepare_compact(
            &self.settings,
            &self.archive,
            self.checkpoint.id(),
            &parent,
            block,
        )
        .unwrap();
        let proof = self.proof(&parent);
        let archive_before = self.archive.observation().unwrap();
        let checked = execution::execute_with_monetary_state_witness(
            &self.settings,
            &self.archive,
            self.checkpoint.id(),
            &parent,
            block,
            MonetaryStateExecutionInput {
                accounts: &accounts.accounts,
                monetary: &proof,
            },
        )
        .unwrap();
        assert_eq!(self.archive.observation().unwrap(), archive_before);
        assert_eq!(
            checked.monetary_obligations.monetary_rows,
            parent
                .keys()
                .filter(|key| pon_executor::is_monetary_obligation(key))
                .count()
        );
        let partition = parent
            .iter()
            .filter(|(key, _)| !key.starts_with("account:"))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let mandatory = Mutex::new(None);
        let reference = pon_executor::execute_with_authenticated_state_input(
            &parent,
            pon_executor::BlockExecution {
                transactions: &txs,
                height: block.height,
                miner: block.miner,
                parent_id: block.parent_id,
                workers: 1,
            },
            &self.app,
            &|_| Ok(()),
            &pon_executor::MandatoryStateInput {
                non_accounts: &partition,
                completed: &|_, after, _| {
                    *mandatory.lock().unwrap() = Some(after.clone());
                    Ok(())
                },
            },
            &|_| Ok::<_, E>(()),
        )
        .unwrap();
        let result = &checked.execution.execution;
        assert_eq!(reference.state, result.execution.output.state);
        assert_eq!(reference.receipts, result.execution.output.receipts);
        assert_eq!(reference.root, result.execution.output.root);
        let packet = self
            .node
            .make_consensus_maintenance(
                block.parent_id,
                txs.clone(),
                block.miner,
                1 + block.height * 10,
                4096,
            )
            .unwrap();
        assert_eq!(packet.header.state, reference.root);
        assert_eq!(
            packet.header.receipts,
            sequence_root("receipts", &reference.receipts)
        );
        let id = self.node.admit(&packet, 100_000).unwrap();
        let successor = self.node.state_at(id).unwrap();
        assert_eq!(successor, reference.state);
        self.node.activate(id).unwrap();
        let record = json!({
            "label": label, "height": block.height, "parent": block.parent_id, "miner": block.miner,
            "transactions_hex": txs.iter().map(hex::encode).collect::<Vec<_>>(),
            "parent_state": parent, "parent_checkpoint": self.checkpoint,
            "requested": accounts.observation.requested_owners,
            "account_proof_hex": hex::encode(accounts.accounts.encode().unwrap()),
            "account_proof": accounts.accounts,
            "range_proof": proof, "range_observation": checked.monetary_obligations,
            "state_observation": result.state_observation,
            "mandatory_state": mandatory.into_inner().unwrap().unwrap(),
            "successor_state": successor, "packet_hex": hex::encode(packet.encode().unwrap()), "admitted_id": id,
        });
        let next = self
            .archive
            .project_successor(
                self.checkpoint.id(),
                &parent,
                &successor,
                id,
                block.height,
                &mut || Ok(()),
            )
            .unwrap();
        self.archive
            .activate(self.archive.active().unwrap(), next.id(), &mut || Ok(()))
            .unwrap();
        self.checkpoint = next;
        record
    }
}

#[test]
fn monetary_ranges_execute_signed_expiry_future_capacity_and_reward_maturity_against_native_node() {
    let mut f = Fixture::new();
    let export_path = std::env::var_os("TRNM_OBLIGATION_RANGE_VECTORS").map(PathBuf::from);
    if let Some(path) = &export_path {
        assert!(!path.exists(), "fresh monetary observation path required");
    }
    let genesis = f.node.read_active().unwrap().2;
    let genesis_checkpoint = f.checkpoint.clone();
    let funding = (100..118)
        .map(|owner| transfer(&f.settings, 0, owner - 99, owner, 5_000))
        .collect();
    let mut blocks = vec![f.accept(funding, 999, "funding".into())];
    let reservations = (100..118)
        .map(|owner| {
            let budget = 1_000u64;
            let deadline = 3 + (owner - 100) / 16;
            let task = hash(
                b"task-instance-v3",
                &[
                    &f.settings.network(),
                    &f.settings.parameters(),
                    &public(owner),
                    &1u64.to_le_bytes(),
                    &public(2),
                    &budget.to_le_bytes(),
                    &deadline.to_le_bytes(),
                ],
            );
            let mut payload = task.to_vec();
            payload.extend(public(2));
            payload.extend(budget.to_le_bytes());
            payload.extend(deadline.to_le_bytes());
            signed(&f.settings, owner, 1, 2, payload)
        })
        .collect();
    blocks.push(f.accept(reservations, 0, "reservations".into()));

    let parent = f.node.read_active().unwrap().2;
    let block = f.input(&[], 0);
    let accounts =
        obligations::prepare_compact(&f.settings, &f.archive, f.checkpoint.id(), &parent, block)
            .unwrap();
    let proof = f.proof(&parent);
    assert_eq!(
        proof
            .rows
            .iter()
            .filter(|row| row.key.starts_with("task:"))
            .count(),
        18
    );
    let before_node = f.node.read_active().unwrap();
    let before_archive = f.archive.observation().unwrap();
    let call = |range: &RangeProof| {
        execution::execute_with_monetary_state_witness(
            &f.settings,
            &f.archive,
            f.checkpoint.id(),
            &parent,
            block,
            MonetaryStateExecutionInput {
                accounts: &accounts.accounts,
                monetary: range,
            },
        )
    };
    // Replay an actual valid earlier certificate, rather than merely corrupting
    // a header field. It has its own valid source count, boundary and root.
    let earlier =
        obligation_ranges::prepare(&f.settings, &f.archive, genesis_checkpoint.id(), &genesis)
            .unwrap();
    assert_eq!(
        call(&earlier).unwrap_err(),
        E::ObligationRange(RangeError::Context)
    );
    let other_context = Settings::development_with_profiles(
        Some(2),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    assert_eq!(
        execution::execute_with_monetary_state_witness(
            &other_context,
            &f.archive,
            f.checkpoint.id(),
            &parent,
            block,
            MonetaryStateExecutionInput {
                accounts: &accounts.accounts,
                monetary: &proof
            },
        )
        .unwrap_err(),
        E::Archive(ArchiveError::Context)
    );
    // An authentic complete range cannot be replaced with a due-only subset,
    // nor can a caller alter its namespace, amount, order, source or frontier.
    let future = proof
        .rows
        .iter()
        .position(|row| row.key.starts_with("task:") && row.value["deadline"] == 4)
        .unwrap();
    let mut mutations = Vec::new();
    let mut omitted = proof.clone();
    omitted.rows.remove(future);
    mutations.push(omitted);
    let mut changed = proof.clone();
    changed.rows[future].value["remaining"] = json!(0);
    mutations.push(changed);
    let mut reordered = proof.clone();
    reordered.rows.swap(0, 1);
    mutations.push(reordered);
    let mut duplicated = proof.clone();
    duplicated.rows.insert(0, duplicated.rows[0].clone());
    mutations.push(duplicated);
    let mut stale = proof.clone();
    stale.parent_height -= 1;
    mutations.push(stale);
    let mut wrong_parent = proof.clone();
    wrong_parent.parent_id[0] ^= 1;
    mutations.push(wrong_parent);
    let mut wrong_context = proof.clone();
    wrong_context.state_commitment[0] ^= 1;
    mutations.push(wrong_context);
    let mut root = proof.clone();
    root.index_root[0] ^= 1;
    mutations.push(root);
    let mut frontier = proof.clone();
    frontier.frontier[0].digest[0] ^= 1;
    mutations.push(frontier);
    for invalid in mutations {
        assert!(matches!(call(&invalid), Err(E::ObligationRange(_))));
    }
    // A source-valid smaller AAM1 still cannot hide a future escrow owner.
    let fewer: Vec<_> = accounts
        .observation
        .requested_owners
        .iter()
        .copied()
        .filter(|owner| *owner != public(117))
        .collect();
    let smaller = f.archive.multiproof(f.checkpoint.id(), &fewer).unwrap().0;
    assert_eq!(
        execution::execute_with_monetary_state_witness(
            &f.settings,
            &f.archive,
            f.checkpoint.id(),
            &parent,
            block,
            MonetaryStateExecutionInput {
                accounts: &smaller,
                monetary: &proof
            },
        )
        .unwrap_err(),
        E::MissingWitness { owner: public(117) }
    );
    // The new miner appears only in the successor capacity scan. No parent
    // monetary certificate authorizes an unchecked future reward recipient.
    let new_miner = BlockInput {
        miner: public(1000),
        ..block
    };
    assert_eq!(
        execution::execute_with_monetary_state_witness(
            &f.settings,
            &f.archive,
            f.checkpoint.id(),
            &parent,
            new_miner,
            MonetaryStateExecutionInput {
                accounts: &accounts.accounts,
                monetary: &proof
            },
        )
        .unwrap_err(),
        E::MissingWitness {
            owner: public(1000)
        }
    );
    for cancel in [
        P::ObligationRange { index: 0 },
        P::AfterMandatoryVerification,
        P::Execution(ExecutionProgress::BeforeReward),
        P::BeforeOutput,
    ] {
        assert_eq!(
            execution::execute_with_monetary_state_witness_and_progress(
                &f.settings,
                &f.archive,
                f.checkpoint.id(),
                &parent,
                block,
                MonetaryStateExecutionInput {
                    accounts: &accounts.accounts,
                    monetary: &proof
                },
                &|point| if point == cancel {
                    Err(E::Cancelled)
                } else {
                    Ok(())
                },
            )
            .unwrap_err(),
            E::Cancelled
        );
    }
    let events = AtomicUsize::new(0);
    let mut over = proof.clone();
    over.non_account_count = u32::MAX;
    assert_eq!(
        execution::execute_with_monetary_state_witness_and_progress(
            &f.settings,
            &f.archive,
            f.checkpoint.id(),
            &parent,
            block,
            MonetaryStateExecutionInput {
                accounts: &accounts.accounts,
                monetary: &over
            },
            &|_| {
                events.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap_err(),
        E::ObligationRange(RangeError::Bounds)
    );
    assert_eq!(events.load(Ordering::SeqCst), 0);
    assert_eq!(f.node.read_active().unwrap(), before_node);
    assert_eq!(f.archive.observation().unwrap(), before_archive);

    blocks.push(f.accept(vec![], 0, "expiry".into()));
    assert_eq!(
        blocks[2]["state_observation"]["mandatory"]["receipts"]
            .as_array()
            .unwrap()
            .len(),
        16
    );
    assert_eq!(
        f.node
            .read_active()
            .unwrap()
            .2
            .values()
            .filter(|value| value.get("deadline") == Some(&json!(4))
                && value.get("remaining") == Some(&json!(1000)))
            .count(),
        2
    );
    for height in 4..=20 {
        blocks.push(f.accept(vec![], 0, format!("continuation-{height}")));
    }
    assert!(!f
        .node
        .read_active()
        .unwrap()
        .2
        .contains_key(&format!("account:{}", hex::encode(public(999)))));
    let spend = transfer(&f.settings, 999, 1, 0, 1);
    blocks.push(f.accept(vec![spend], 0, "maturity-spend".into()));
    assert_eq!(
        f.node.read_active().unwrap().2[&format!("account:{}", hex::encode(public(999)))]["nonce"],
        1
    );
    assert_eq!(blocks.len(), 21);
    if let Some(path) = export_path {
        std::fs::write(path, serde_json::to_vec_pretty(&json!({
            "schema": "pon-monetary-obligation-range-native-observation-v1",
            "context": { "network": f.settings.network(), "parameters": f.settings.parameters(), "genesis": f.settings.genesis() },
            "genesis_state": genesis, "genesis_checkpoint": genesis_checkpoint, "blocks": blocks,
            "scope": {
                "actual_signed_node_admission": true, "complete_state_reference_required": true,
                "monetary_ranges_complete": true, "parent_monetary_discovery_uses_verified_rows": true,
                "other_non_account_rules_use_full_state": true, "default_node_admission_uses_full_state": true,
                "public_availability_accepted": false, "production_activation": false,
            },
        })).unwrap()).unwrap();
    }
}

#[test]
fn monetary_ranges_preserve_nonmonetary_cleanup_and_refuse_raw_m06_projection_omission() {
    let f = Fixture::new();
    // Explicit component State, not injected into a Node database or claimed as
    // an admitted genesis. It isolates unrelated mandatory cleanup behavior.
    let mut parent = f.node.read_active().unwrap().2;
    parent.insert("artifact:wrong-round".into(), json!({"retained": true}));
    parent.insert("retained:opaque".into(), Value::Null);
    let directory = tempfile::tempdir().unwrap();
    let mut archive = AccountArchive::open(
        &directory.path().join("component.sqlite"),
        Context {
            network: f.settings.network(),
            parameters: f.settings.parameters(),
            genesis: f.settings.genesis(),
        },
        Limits::default(),
    )
    .unwrap();
    let checkpoint = archive
        .project_initial(&parent, pon_executor::root(&parent).unwrap())
        .unwrap();
    let block = BlockInput {
        transactions: &[],
        height: 1,
        miner: public(0),
        parent_id: checkpoint.branch(),
    };
    let accounts =
        obligations::prepare_compact(&f.settings, &archive, checkpoint.id(), &parent, block)
            .unwrap();
    let proof =
        obligation_ranges::prepare(&f.settings, &archive, checkpoint.id(), &parent).unwrap();
    let result = execution::execute_with_monetary_state_witness(
        &f.settings,
        &archive,
        checkpoint.id(),
        &parent,
        block,
        MonetaryStateExecutionInput {
            accounts: &accounts.accounts,
            monetary: &proof,
        },
    )
    .unwrap();
    let reference =
        pon_executor::execute(&parent, &[], 1, public(0), checkpoint.branch(), 1, &f.app).unwrap();
    assert_eq!(
        result.execution.execution.execution.output.state,
        reference.state
    );
    assert!(!reference.state.contains_key("artifact:wrong-round"));
    assert_eq!(reference.state["retained:opaque"], Value::Null);
    // The next raw M06 input cannot omit the real immature reward row, even if
    // a caller bypasses the higher-layer certificate API entirely.
    let next_parent = reference.state;
    let partition = next_parent
        .iter()
        .filter(|(key, _)| !key.starts_with("account:"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let completed = AtomicUsize::new(0);
    let raw = pon_executor::execute_with_authenticated_obligation_input(
        &next_parent,
        pon_executor::BlockExecution {
            transactions: &[],
            height: 2,
            miner: public(0),
            parent_id: [1; 32],
            workers: 1,
        },
        &f.app,
        &|_| Ok(()),
        &pon_executor::MandatoryStateInput {
            non_accounts: &partition,
            completed: &|_, _, _| {
                completed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        },
        &pon_executor::MonetaryObligationInput {
            rows: &State::new(),
        },
        &|_| Ok::<_, E>(()),
    );
    assert!(matches!(
        raw,
        Err(pon_executor::ExecutionError::Relation(
            "MONETARY_OBLIGATION_PARTITION"
        ))
    ));
    assert_eq!(completed.load(Ordering::SeqCst), 0);
}
