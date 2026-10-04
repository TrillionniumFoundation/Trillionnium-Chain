//! Actual signed/admitted transitions for the independent checked-account oracle.
//! The complete State remains authoritative. This is a disposable research fixture.
#[path = "support/account_archive_artifact.rs"]
mod account_archive_artifact;
use account_archive_artifact::{create_working_archive_path, finish_archive_artifact};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{
    continuity_v1,
    pon_executor::{self, Config, ExecutionProgress, State},
};
use trnm_pon_node::{
    account_archive_execution::{self, BlockInput, CheckedExecutionError},
    account_archive_prototype::{
        AccountArchive, ArchiveError, Checkpoint, Context, Limits, Witness,
    },
    development_public, sequence_root, Node, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

const POLICY: &str = "native-public-evaluation-dev-v1";
const MINER: u64 = 79_999;

fn key(number: u64) -> Hash {
    development_public(number).unwrap()
}

fn signature(number: u64, digest: &Hash) -> [u8; 64] {
    let signing = signing_key_from_hex(&hex::encode(hash(
        b"DEV-ONLY-KEY",
        &[&number.to_le_bytes()],
    )))
    .unwrap();
    hex::decode(sign_hex(&signing, digest))
        .unwrap()
        .try_into()
        .unwrap()
}

fn envelope(settings: &Settings, sender: u64, nonce: u64, tag: u8, payload: Vec<u8>) -> Vec<u8> {
    let mut tx = Envelope {
        network: settings.network(),
        sender: key(sender),
        nonce,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag,
        payload,
        signature: [0; 64],
    };
    tx.signature = signature(sender, &tx.signing_digest().unwrap());
    tx.encode().unwrap()
}

fn transfer(settings: &Settings, sender: u64, nonce: u64, recipient: u64, amount: u64) -> Vec<u8> {
    let mut payload = key(recipient).to_vec();
    payload.extend(amount.to_le_bytes());
    envelope(settings, sender, nonce, 1, payload)
}

fn task(
    settings: &Settings,
    sender: u64,
    nonce: u64,
    budget: u64,
    deadline: u64,
) -> (Hash, Vec<u8>) {
    let provider = key(3);
    let id = hash(
        b"task-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &key(sender),
            &nonce.to_le_bytes(),
            &provider,
            &budget.to_le_bytes(),
            &deadline.to_le_bytes(),
        ],
    );
    let mut payload = id.to_vec();
    payload.extend(provider);
    payload.extend(budget.to_le_bytes());
    payload.extend(deadline.to_le_bytes());
    (id, envelope(settings, sender, nonce, 2, payload))
}

fn fixture_config(settings: &Settings) -> Config {
    // This replica is fixture metadata/reference input, never wrapper authority.
    // The production research wrapper takes the privately installed Settings.
    let mut cfg = Config::installed_with_profiles(POLICY, continuity_v1::PROFILE).unwrap();
    cfg.params["genesis_timestamp"] = json!(settings.genesis_time());
    let label = format!(
        "trnm-pon-task-lifecycle-wall-devnet-{}-{POLICY}-{}-evaluation-storage{}",
        cfg.params["consensus_revision"].as_u64().unwrap(),
        settings.genesis_time(),
        trnm_mvcc_fee::public_evaluation::STORAGE_REVISION
    );
    cfg.params["chain_label"] = json!(label);
    cfg.network = hash(b"network", &[label.as_bytes()]);
    let wire: Value =
        serde_json::from_str(include_str!("../../../../config/pon/ledger-v1.json")).unwrap();
    let work: Value =
        serde_json::from_str(include_str!("../../../../config/pon/work-profile-v1.json")).unwrap();
    cfg.parameters = hash(
        b"parameters",
        &[
            &serde_json::to_vec(&cfg.params).unwrap(),
            &serde_json::to_vec(&wire).unwrap(),
            &serde_json::to_vec(&work).unwrap(),
            &serde_json::to_vec(&cfg.model_registry).unwrap(),
        ],
    );
    assert_eq!(cfg.network, settings.network());
    assert_eq!(cfg.parameters, settings.parameters());
    cfg
}

fn fee(cfg: &Config, raw: &[u8]) -> u64 {
    let tx = Envelope::decode(raw).unwrap();
    cfg.fees[tx.tag as usize] + raw.len() as u64 * cfg.params["byte_fee_units"].as_u64().unwrap()
}

fn capacity(state: &State, height: u64, cfg: &Config) -> Value {
    let value = continuity_v1::capacity(state, height, cfg).unwrap();
    json!({"actual_keys":value.actual_keys,"credit_account_reserve":value.credit_account_reserve,
        "archive_reserve":value.archive_reserve,"reward_queue_reserve":value.reward_queue_reserve,
        "required_keys":value.required_keys})
}

fn rows(path: &Path) -> Value {
    let db = Connection::open(path).unwrap();
    let nodes: Vec<Value> = db.prepare("SELECT id,data FROM archive_nodes ORDER BY id").unwrap()
        .query_map([], |row| Ok(json!({"id":hex::encode(row.get::<_,Vec<u8>>(0)?),"data":hex::encode(row.get::<_,Vec<u8>>(1)?)})))
        .unwrap().map(|row| row.unwrap()).collect();
    let checkpoints: Vec<Value> = db.prepare("SELECT id,branch,data FROM archive_checkpoints ORDER BY id").unwrap()
        .query_map([], |row| Ok(json!({"id":hex::encode(row.get::<_,Vec<u8>>(0)?),"branch":hex::encode(row.get::<_,Vec<u8>>(1)?),"data":hex::encode(row.get::<_,Vec<u8>>(2)?)})))
        .unwrap().map(|row| row.unwrap()).collect();
    let active: Vec<Value> = db.prepare("SELECT singleton,checkpoint,generation FROM archive_active ORDER BY singleton").unwrap()
        .query_map([], |row| Ok(json!({"singleton":row.get::<_,u64>(0)?,"checkpoint":hex::encode(row.get::<_,Vec<u8>>(1)?),"generation":row.get::<_,u64>(2)?})))
        .unwrap().map(|row| row.unwrap()).collect();
    let meta: Vec<Value> = db
        .prepare("SELECT key,value FROM archive_meta ORDER BY key")
        .unwrap()
        .query_map([], |row| {
            Ok(json!({"key":row.get::<_,String>(0)?,"value":hex::encode(row.get::<_,Vec<u8>>(1)?)}))
        })
        .unwrap()
        .map(|row| row.unwrap())
        .collect();
    json!({"archive_nodes":nodes,"archive_checkpoints":checkpoints,"archive_active":active,"archive_meta":meta})
}

fn expected_owners(parent: &State, transactions: &[Vec<u8>], miner: Hash) -> Vec<Hash> {
    // Fixture-side dependency prediction; exact used coverage is checked by the
    // research executor and derived independently by the Python transition oracle.
    let mut owners = BTreeSet::from([miner]);
    for (name, value) in parent {
        if name.starts_with("reward:")
            || ((name.starts_with("task:")
                || name.starts_with("quota:")
                || name.starts_with("release:"))
                && value["remaining"].as_u64().unwrap() > 0)
        {
            owners.insert(
                hex::decode(value["owner"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
        }
    }
    for raw in transactions {
        let tx = Envelope::decode(raw).unwrap();
        owners.insert(tx.sender);
        if tx.tag == 1 {
            owners.insert(tx.payload[..32].try_into().unwrap());
        } else if tx.tag == 5 {
            let task = &parent[&format!("task:{}", hex::encode(&tx.payload[..32]))];
            owners.insert(
                hex::decode(task["provider"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
        }
    }
    owners.into_iter().collect()
}

struct Fixture {
    settings: Settings,
    cfg: Config,
    context: Context,
    node: Node,
    archive: AccountArchive,
    node_path: PathBuf,
    archive_path: PathBuf,
    checkpoints: BTreeMap<Hash, Checkpoint>,
    blocks: Vec<Value>,
    reopens: Vec<Value>,
    reorganizations: usize,
}

#[derive(Clone)]
struct NegativeCase {
    label: String,
    source: String,
    settings: Settings,
    parent: Hash,
    checkpoint: Hash,
    state: State,
    height: u64,
    miner: Hash,
    transactions: Vec<Vec<u8>>,
    witnesses: Vec<Witness>,
    cancel_at: Option<ExecutionProgress>,
    expected: CheckedExecutionError,
}

fn outcome(error: &CheckedExecutionError) -> Value {
    match error {
        CheckedExecutionError::MissingWitness { owner } => {
            json!({"kind":"account","code":"MissingWitness","owner":owner})
        }
        CheckedExecutionError::UnusedWitness { owners } => {
            json!({"kind":"account","code":"UnusedWitness","owners":owners})
        }
        CheckedExecutionError::Archive(error) => {
            json!({"kind":"archive","code":format!("{error:?}")})
        }
        CheckedExecutionError::Relation(code) => json!({"kind":"relation","code":code}),
        other => json!({"kind":"checked","code":format!("{other:?}")}),
    }
}

fn resign(raw: &[u8], sender: u64, edit: impl FnOnce(&mut Envelope)) -> Vec<u8> {
    let mut tx = Envelope::decode(raw).unwrap();
    edit(&mut tx);
    tx.signature = signature(sender, &tx.signing_digest().unwrap());
    tx.encode().unwrap()
}

impl Fixture {
    fn negative_base(
        &self,
        source: &str,
        label: &str,
        expected: CheckedExecutionError,
    ) -> NegativeCase {
        let block = self
            .blocks
            .iter()
            .find(|block| block["label"] == source)
            .unwrap();
        NegativeCase {
            label: label.into(),
            source: source.into(),
            settings: self.settings.clone(),
            parent: serde_json::from_value(block["parent"].clone()).unwrap(),
            checkpoint: serde_json::from_value(block["parent_checkpoint"]["id"].clone()).unwrap(),
            state: serde_json::from_value(block["parent_state"].clone()).unwrap(),
            height: block["height"].as_u64().unwrap(),
            miner: serde_json::from_value(block["miner"].clone()).unwrap(),
            transactions: block["transactions_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|raw| hex::decode(raw.as_str().unwrap()).unwrap())
                .collect(),
            witnesses: serde_json::from_value(block["witnesses"].clone()).unwrap(),
            cancel_at: None,
            expected,
        }
    }

    fn reject(&mut self, case: NegativeCase) -> Value {
        let before_state = case.state.clone();
        let before_native = self.node.read_active().unwrap();
        let before_active = self.archive.active().unwrap();
        let before_storage = self.archive.observation().unwrap();
        let before_rows = rows(&self.archive_path);
        let rows_hash = hash(
            b"account-execution-observed-rows-v1",
            &[&serde_json::to_vec(&before_rows).unwrap()],
        );
        let stages = Mutex::new(Vec::<String>::new());
        let observed = account_archive_execution::execute_with_progress(
            &case.settings,
            &self.archive,
            case.checkpoint,
            &case.state,
            BlockInput {
                transactions: &case.transactions,
                height: case.height,
                miner: case.miner,
                parent_id: case.parent,
            },
            &case.witnesses,
            &|stage| {
                stages.lock().unwrap().push(format!("{stage:?}"));
                if Some(stage) == case.cancel_at {
                    Err(CheckedExecutionError::Cancelled)
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert_eq!(observed, case.expected, "{}", case.label);
        let node_preview_code = if let CheckedExecutionError::Relation(code) = &observed {
            let error = self
                .node
                .make_consensus_maintenance(
                    case.parent,
                    case.transactions.clone(),
                    case.miner,
                    1 + case.height * 10,
                    4096,
                )
                .unwrap_err();
            assert_eq!(error.to_string(), *code);
            Some(error.to_string())
        } else {
            None
        };
        let after_native = self.node.read_active().unwrap();
        let after_active = self.archive.active().unwrap();
        let after_storage = self.archive.observation().unwrap();
        let after_rows = rows(&self.archive_path);
        assert_eq!(case.state, before_state);
        assert_eq!(after_native, before_native);
        assert_eq!(after_active, before_active);
        assert_eq!(after_storage, before_storage);
        assert_eq!(after_rows, before_rows);
        let before_observation = json!({"native_active":before_native.0,"native_height":before_native.1,
            "native_state_root":pon_executor::root(&before_native.2).unwrap(),"archive_active":before_active,
            "archive_storage":before_storage,"archive_rows_hash":rows_hash});
        let after_observation = json!({"native_active":after_native.0,"native_height":after_native.1,
            "native_state_root":pon_executor::root(&after_native.2).unwrap(),"archive_active":after_active,
            "archive_storage":after_storage,"archive_rows_hash":hash(b"account-execution-observed-rows-v1", &[&serde_json::to_vec(&after_rows).unwrap()])});
        let checkpoint = self
            .archive
            .checkpoint(case.checkpoint)
            .ok()
            .map(|value| json!(value));
        let mut requested: Vec<_> = case.witnesses.iter().map(|w| w.owner).collect();
        requested.sort_unstable();
        json!({"label":case.label,"source_positive_label":case.source,"settings_context":{"network":case.settings.network(),"parameters":case.settings.parameters(),"genesis":case.settings.genesis()},
            "parent":case.parent,"height":case.height,"miner":case.miner,"parent_state":case.state,
            "parent_checkpoint_id":case.checkpoint,"parent_checkpoint":checkpoint,"requested":requested,"witnesses":case.witnesses,
            "transactions_hex":case.transactions.iter().map(hex::encode).collect::<Vec<_>>(),"cancel_at":case.cancel_at.map(|v|format!("{v:?}")),
            "outcome":outcome(&observed),"node_preview_code":node_preview_code,"progress":stages.into_inner().unwrap(),
            "before":before_observation,"after":after_observation,"parent_unchanged":true,"archive_unchanged":true})
    }

    fn rejection_cases(&mut self) -> Vec<Value> {
        let mut cases = Vec::new();
        for (source, label, owner) in [
            ("main-01", "missing-sender", 0),
            ("main-01", "missing-new-recipient", 10),
            ("main-01", "missing-intrablock-owner", 11),
            ("main-02", "missing-future-reward-recipient", MINER),
            ("main-02", "missing-quota-provider", 12),
            ("main-05", "missing-expiry-recipient", 11),
            ("main-21", "missing-matured-reward-recipient", MINER),
        ] {
            let mut case = self.negative_base(
                source,
                label,
                CheckedExecutionError::MissingWitness { owner: key(owner) },
            );
            let count = case.witnesses.len();
            case.witnesses.retain(|w| w.owner != key(owner));
            assert_eq!(case.witnesses.len() + 1, count);
            cases.push(case);
        }
        let mut case = self.negative_base(
            "main-01",
            "unused-witness",
            CheckedExecutionError::UnusedWitness {
                owners: vec![key(99_999)],
            },
        );
        case.witnesses.push(
            self.archive
                .witness(case.checkpoint, key(99_999))
                .unwrap()
                .0,
        );
        cases.push(case);
        let invalid = CheckedExecutionError::Archive(ArchiveError::InvalidWitness);
        let mut case = self.negative_base("main-01", "duplicate-witness", invalid.clone());
        case.witnesses.push(case.witnesses[0].clone());
        cases.push(case);
        let mut case = self.negative_base("main-01", "forged-account-value", invalid.clone());
        case.witnesses
            .iter_mut()
            .find(|w| w.owner == key(0))
            .unwrap()
            .account
            .as_mut()
            .unwrap()
            .balance += 1;
        cases.push(case);
        let mut case = self.negative_base("main-04", "forged-account-absence", invalid.clone());
        case.witnesses
            .iter_mut()
            .find(|w| w.owner == key(10))
            .unwrap()
            .account = None;
        cases.push(case);
        let mut case = self.negative_base("main-04", "witness-from-old-branch", invalid.clone());
        let old_parent = self
            .blocks
            .iter()
            .find(|block| block["label"] == "main-02")
            .unwrap()["id"]
            .clone();
        let old_parent: Hash = serde_json::from_value(old_parent).unwrap();
        *case
            .witnesses
            .iter_mut()
            .find(|w| w.owner == key(10))
            .unwrap() = self
            .archive
            .witness(self.checkpoints[&old_parent].id(), key(10))
            .unwrap()
            .0;
        cases.push(case);
        let mut case = self.negative_base("main-01", "forged-witness-root", invalid.clone());
        case.witnesses[0].siblings[0][0] ^= 1;
        cases.push(case);
        let mut case = self.negative_base("main-01", "malformed-witness", invalid);
        case.witnesses[0].siblings.pop();
        cases.push(case);
        let mut case =
            self.negative_base("main-01", "witness-budget", CheckedExecutionError::Budget);
        case.witnesses = (100_000..100_033)
            .map(|owner| self.archive.witness(case.checkpoint, key(owner)).unwrap().0)
            .collect();
        cases.push(case);
        let mut case = self.negative_base("main-01", "wrong-parent", CheckedExecutionError::Parent);
        case.parent = [9; 32];
        cases.push(case);
        let mut case = self.negative_base("main-01", "wrong-height", CheckedExecutionError::Height);
        case.height += 1;
        cases.push(case);
        let mut case =
            self.negative_base("main-01", "wrong-context", CheckedExecutionError::Context);
        case.settings =
            Settings::development_with_profiles(Some(2), POLICY, continuity_v1::PROFILE).unwrap();
        cases.push(case);
        let mut case = self.negative_base(
            "main-01",
            "wrong-source-state-root",
            CheckedExecutionError::SourceRoot,
        );
        case.state
            .get_mut(&format!("account:{}", hex::encode(key(0))))
            .unwrap()["nonce"] = json!(1);
        cases.push(case);
        let mut case = self.negative_base(
            "main-01",
            "wrong-nonaccount-source-state-root",
            CheckedExecutionError::SourceRoot,
        );
        let issued = case.state["meta:issued"].as_u64().unwrap();
        case.state.insert("meta:issued".into(), json!(issued + 1));
        cases.push(case);
        let mut case = self.negative_base(
            "main-01",
            "missing-checkpoint",
            CheckedExecutionError::Archive(ArchiveError::MissingCheckpoint),
        );
        case.checkpoint = [8; 32];
        cases.push(case);
        let mut case = self.negative_base(
            "main-01",
            "main-signature",
            CheckedExecutionError::Relation("SIGNATURE"),
        );
        let last = case.transactions[0].len() - 1;
        case.transactions[0][last] ^= 1;
        cases.push(case);
        let mut case = self.negative_base(
            "main-04",
            "recredited-nonce-replay",
            CheckedExecutionError::Relation("NONCE"),
        );
        case.transactions[0] = resign(&case.transactions[0], 10, |tx| tx.nonce = 1);
        cases.push(case);
        let mut case = self.negative_base(
            "main-04",
            "fee-limit",
            CheckedExecutionError::Relation("FEE"),
        );
        case.transactions[0] = resign(&case.transactions[0], 10, |tx| tx.fee_limit = 0);
        cases.push(case);
        let mut case = self.negative_base(
            "main-04",
            "insufficient-funds",
            CheckedExecutionError::Relation("FUNDS"),
        );
        case.transactions[0] = transfer(&self.settings, 10, 2, 2, u64::MAX);
        cases.push(case);
        let mut case = self.negative_base(
            "main-02",
            "consumer-signature",
            CheckedExecutionError::Relation("SIGNATURE"),
        );
        case.transactions[4] = resign(&case.transactions[4], 12, |tx| {
            let last = tx.payload.len() - 1;
            tx.payload[last] ^= 1;
        });
        cases.push(case);
        let mut case = self.negative_base(
            "main-01",
            "resource-id",
            CheckedExecutionError::Relation("RESOURCE_ID"),
        );
        case.transactions[4] = resign(&case.transactions[4], 2, |tx| tx.payload[0] ^= 1);
        cases.push(case);
        let mut case = self.negative_base(
            "main-04",
            "canonical-nonce-before-later-signature",
            CheckedExecutionError::Relation("NONCE"),
        );
        case.transactions[0] = resign(&case.transactions[0], 10, |tx| tx.nonce = 1);
        let mut later = transfer(&self.settings, 0, 5, 10, 1);
        let last = later.len() - 1;
        later[last] ^= 1;
        case.transactions.push(later);
        cases.push(case);
        let mut case = self.negative_base(
            "main-01",
            "cancel-before-output",
            CheckedExecutionError::Cancelled,
        );
        case.cancel_at = Some(ExecutionProgress::BeforeOutput);
        cases.push(case);
        assert_eq!(cases.len(), 29);
        cases.into_iter().map(|case| self.reject(case)).collect()
    }

    fn add(&mut self, label: &str, parent: Hash, transactions: Vec<Vec<u8>>, miner: Hash) -> Hash {
        let height = self.node.parent_height(parent).unwrap() + 1;
        let before = self.node.state_at(parent).unwrap();
        let parent_checkpoint = self.checkpoints[&parent].clone();
        let requested = expected_owners(&before, &transactions, miner);
        let proof_rows: Vec<_> = requested
            .iter()
            .map(|owner| {
                self.archive
                    .witness(parent_checkpoint.id(), *owner)
                    .unwrap()
            })
            .collect();
        let witnesses: Vec<_> = proof_rows
            .iter()
            .map(|(witness, _)| witness.clone())
            .collect();
        let node_reads: Vec<_> = proof_rows.iter().map(|(_, reads)| *reads).collect();
        let active_before_checked = self.archive.active().unwrap();
        let storage_before_checked = self.archive.observation().unwrap();
        let checked = account_archive_execution::execute(
            &self.settings,
            &self.archive,
            parent_checkpoint.id(),
            &before,
            BlockInput {
                transactions: &transactions,
                height,
                miner,
                parent_id: parent,
            },
            &witnesses,
        )
        .unwrap();
        let observation = serde_json::to_value(&checked.observation).unwrap();
        assert_eq!(observation["used_owners"], json!(requested));
        assert_eq!(self.archive.active().unwrap(), active_before_checked);
        assert_eq!(self.archive.observation().unwrap(), storage_before_checked);
        assert_eq!(self.node.state_at(parent).unwrap(), before);
        let reference =
            pon_executor::execute(&before, &transactions, height, miner, parent, 4, &self.cfg)
                .unwrap();
        assert_eq!(checked.output.state, reference.state);
        assert_eq!(checked.output.root, reference.root);
        assert_eq!(checked.output.receipts, reference.receipts);
        let packet = self
            .node
            .make_consensus_maintenance(parent, transactions.clone(), miner, 1 + height * 10, 4096)
            .unwrap();
        assert_eq!(packet.header.state, checked.output.root);
        assert_eq!(
            packet.header.transactions,
            sequence_root("transactions", &transactions)
        );
        assert_eq!(
            packet.header.receipts,
            sequence_root("receipts", &checked.output.receipts)
        );
        let id = self.node.admit(&packet, 100_000).unwrap();
        let after = self.node.state_at(id).unwrap();
        assert_eq!(after, checked.output.state);
        let successor = self
            .archive
            .project_successor(
                parent_checkpoint.id(),
                &before,
                &after,
                id,
                height,
                &mut || Ok(()),
            )
            .unwrap();
        self.checkpoints.insert(id, successor.clone());
        let selected_before = self.node.active().unwrap().0;
        let selected = self.node.activate(id).unwrap();
        if selected != selected_before && selected_before != parent {
            self.reorganizations += 1;
        }
        let desired = self.checkpoints[&selected].id();
        let active = self.archive.active().unwrap();
        if active.is_none_or(|value| value.checkpoint != desired) {
            self.archive
                .activate(active, desired, &mut || Ok(()))
                .unwrap();
        }
        self.blocks.push(json!({"label":label,"id":id,"parent":parent,"height":height,"miner":miner,
            "parent_state":before,"parent_checkpoint":parent_checkpoint,"requested":requested,"witnesses":witnesses,
            "witness_node_reads":node_reads,"witnesses_hex":witnesses.iter().map(|w|hex::encode(w.encode().unwrap())).collect::<Vec<_>>(),
            "transactions_hex":transactions.iter().map(hex::encode).collect::<Vec<_>>(),"packet_hex":hex::encode(packet.encode().unwrap()),
            "header_hex":hex::encode(packet.header.encode()),"capacity_before":capacity(&before,height-1,&self.cfg),
            "capacity_after":capacity(&after,height,&self.cfg),
            "native_output":{"state":after,"root":checked.output.root,"receipts_hex":checked.output.receipts.iter().map(hex::encode).collect::<Vec<_>>(),
                "used_owners":observation["used_owners"],"observation":observation},
            "successor_checkpoint":successor,"selected_before":selected_before,"selected_after":selected,
            "archive_active_after":self.archive.active().unwrap(),"archive_storage_after":self.archive.observation().unwrap(),
            "native_admitted":true,"normal_worker4_equal":true,"checked_execution_mutated_archive":false}));
        id
    }

    fn reopen(mut self, label: &str) -> Self {
        let before = self.node.read_active().unwrap();
        let active = self.archive.active().unwrap();
        let storage = self.archive.observation().unwrap();
        let before_rows = rows(&self.archive_path);
        drop(self.node);
        drop(self.archive);
        self.node = Node::open(&self.node_path, self.settings.clone(), 4).unwrap();
        self.archive =
            AccountArchive::open(&self.archive_path, self.context, Limits::default()).unwrap();
        assert_eq!(self.node.read_active().unwrap(), before);
        assert_eq!(self.archive.active().unwrap(), active);
        assert_eq!(self.archive.observation().unwrap(), storage);
        assert_eq!(rows(&self.archive_path), before_rows);
        self.reopens.push(json!({"label":label,"active":before.0,"height":before.1,"state":before.2,
            "checkpoint":active.unwrap().checkpoint,"archive_active":active,"archive_storage":storage,"unchanged":true}));
        self
    }
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(
        args.len(),
        2,
        "usage: account_execution_vectors NEW_OUTPUT_DIRECTORY"
    );
    let output = PathBuf::from(&args[1]);
    fs::create_dir(&output).expect("output directory must not already exist");
    let archive_path = create_working_archive_path(&output).unwrap();
    let node_path = archive_path.parent().unwrap().join("native-node");
    let settings =
        Settings::development_with_profiles(Some(1), POLICY, continuity_v1::PROFILE).unwrap();
    let cfg = fixture_config(&settings);
    let context = Context {
        network: settings.network(),
        parameters: settings.parameters(),
        genesis: settings.genesis(),
    };
    let node = Node::open(&node_path, settings.clone(), 4).unwrap();
    let genesis = node.read_active().unwrap();
    let mut archive = AccountArchive::open(&archive_path, context, Limits::default()).unwrap();
    let genesis_checkpoint = archive
        .project_initial(&genesis.2, pon_executor::root(&genesis.2).unwrap())
        .unwrap();
    archive
        .activate(None, genesis_checkpoint.id(), &mut || Ok(()))
        .unwrap();
    let mut fixture = Fixture {
        settings: settings.clone(),
        cfg: cfg.clone(),
        context,
        node,
        archive,
        node_path,
        archive_path,
        checkpoints: BTreeMap::from([(genesis.0, genesis_checkpoint.clone())]),
        blocks: Vec::new(),
        reopens: Vec::new(),
        reorganizations: 0,
    };
    let spend10 = transfer(&settings, 10, 1, 2, 37);
    let spend11 = transfer(&settings, 11, 1, 2, 19);
    let later10 = transfer(&settings, 10, 2, 2, 7);
    let (settled, reserve_settled) = task(&settings, 2, 1, 5000, 12);
    let (cancelled, reserve_cancelled) = task(&settings, 2, 2, 3000, 12);
    let (_, reserve_expired) = task(&settings, 2, 3, 7000, 5);
    let (_, reserve_refund_spend) = task(&settings, 11, 2, 7000, 5);
    let quota = hash(
        b"quota-instance-v3",
        &[
            &settings.network(),
            &settings.parameters(),
            &key(1),
            &2_u64.to_le_bytes(),
            &key(2),
            &key(12),
            &10_u64.to_le_bytes(),
            &6_u64.to_le_bytes(),
        ],
    );
    let mut quota_payload = quota.to_vec();
    quota_payload.extend(key(2));
    quota_payload.extend(key(12));
    quota_payload.extend(10_u64.to_le_bytes());
    quota_payload.extend(6_u64.to_le_bytes());
    let output_hash = hash(
        b"checked-account-execution-fixture-output-v1",
        &[b"settlement"],
    );
    let mut receipt_payload = settled.to_vec();
    receipt_payload.extend(output_hash);
    let result_hash = hash(
        b"checked-account-execution-fixture-output-v1",
        &[b"quota-use"],
    );
    let use_digest = hash(
        b"use",
        &[
            &settings.network(),
            &settings.parameters(),
            &quota,
            &key(12),
            &1_u64.to_le_bytes(),
            &5_u64.to_le_bytes(),
            &result_hash,
        ],
    );
    let mut use_payload = quota.to_vec();
    use_payload.extend(5_u64.to_le_bytes());
    use_payload.extend(result_hash);
    use_payload.extend(signature(2, &use_digest));
    let refund_spend_fee = fee(&cfg, &transfer(&settings, 11, 3, 2, 1));
    let mut main_tip = genesis.0;
    let mut fork_parent = genesis.0;
    for height in 1..=21 {
        let transactions = match height {
            1 => vec![
                transfer(&settings, 0, 1, 10, fee(&cfg, &spend10) + 37),
                transfer(&settings, 0, 2, 11, fee(&cfg, &spend11) + 19),
                spend11.clone(),
                transfer(&settings, 1, 1, 1, 5),
                reserve_settled.clone(),
                reserve_cancelled.clone(),
                reserve_expired.clone(),
                envelope(&settings, 1, 2, 10, quota_payload.clone()),
            ],
            2 => vec![
                spend10.clone(),
                envelope(&settings, 3, 1, 4, receipt_payload.clone()),
                envelope(&settings, 2, 4, 5, receipt_payload.clone()),
                envelope(&settings, 2, 5, 3, cancelled.to_vec()),
                envelope(&settings, 12, 1, 11, use_payload.clone()),
            ],
            3 => vec![
                transfer(&settings, 0, 3, 10, fee(&cfg, &later10) + 7),
                transfer(&settings, 0, 4, 11, 7000 + fee(&cfg, &reserve_refund_spend)),
                reserve_refund_spend.clone(),
            ],
            4 => vec![later10.clone()],
            5 => vec![transfer(&settings, 11, 3, 2, 7000 - refund_spend_fee)],
            6 => vec![transfer(&settings, 1, 3, 2, 9)],
            21 => {
                let before = fixture.node.state_at(main_tip).unwrap();
                assert!(!before.contains_key(&format!("account:{}", hex::encode(key(MINER)))));
                let reward = before
                    .iter()
                    .find(|(name, value)| {
                        name.starts_with("reward:")
                            && value["owner"] == json!(hex::encode(key(MINER)))
                    })
                    .unwrap()
                    .1["amount"]
                    .as_u64()
                    .unwrap();
                let charge = fee(&cfg, &transfer(&settings, MINER, 1, 2, 1));
                vec![transfer(&settings, MINER, 1, 2, reward - charge)]
            }
            _ => vec![],
        };
        main_tip = fixture.add(
            &format!("main-{height:02}"),
            main_tip,
            transactions,
            key(if height == 1 { MINER } else { 0 }),
        );
        if height == 2 {
            fork_parent = main_tip;
        }
    }
    let main_state = fixture.node.state_at(main_tip).unwrap();
    for (owner, nonce) in [(10, 2), (11, 3), (MINER, 1)] {
        assert_eq!(
            main_state[&format!("account:{}", hex::encode(key(owner)))],
            json!({"balance":0,"nonce":nonce})
        );
    }
    fixture = fixture.reopen("main-21");
    let mut fork_tip = fork_parent;
    for height in 3..=22 {
        fork_tip = fixture.add(&format!("fork-{height:02}"), fork_tip, vec![], key(0));
    }
    assert_eq!(fixture.node.active().unwrap().0, fork_tip);
    let fork_state = fixture.node.state_at(fork_tip).unwrap();
    assert_eq!(
        fork_state[&format!("account:{}", hex::encode(key(10)))]["nonce"],
        1
    );
    assert_eq!(
        fork_state[&format!("account:{}", hex::encode(key(11)))]["nonce"],
        1
    );
    fixture = fixture.reopen("fork-22");
    let restored22 = fixture.add("restored-22", main_tip, vec![], key(0));
    let restored23 = fixture.add("restored-23", restored22, vec![], key(0));
    assert_eq!(fixture.node.active().unwrap().0, restored23);
    fixture = fixture.reopen("restored-23");
    assert_eq!(fixture.blocks.len(), 43);
    assert_eq!(fixture.reorganizations, 2);
    let signed_transactions: usize = fixture
        .blocks
        .iter()
        .map(|block| block["transactions_hex"].as_array().unwrap().len())
        .sum();
    assert_eq!(signed_transactions, 20);
    let negative_cases = fixture.rejection_cases();
    let final_state = fixture.node.read_active().unwrap();
    let final_active = fixture.archive.active().unwrap();
    let final_storage = fixture.archive.observation().unwrap();
    let final_rows = rows(&fixture.archive_path);
    drop(fixture.node);
    drop(fixture.archive);
    let finalization = finish_archive_artifact(
        Connection::open(&fixture.archive_path).unwrap(),
        &fixture.archive_path,
        &output,
    )
    .unwrap();
    let observed = json!({"schema":"pon-account-execution-native-observation-v1","context":context,"params":cfg.params,
        "genesis_timestamp":1,"genesis_state":genesis.2,"genesis_checkpoint":genesis_checkpoint,"blocks":fixture.blocks,
        "reopens":fixture.reopens,"accepted_native_packets":43,"accepted_signed_transactions":signed_transactions,
        "native_reorganizations":fixture.reorganizations,"cold_reopens":3,"final_native_active":final_state.0,
        "final_native_height":final_state.1,"final_native_state":final_state.2,"final_active":final_active,"final_storage":final_storage,
        "final_rows":final_rows,"database":finalization.export_database,"working_database":fixture.archive_path,"finalization":finalization,
        "negative_cases":negative_cases,"scope":{"complete_state_retained":true,"research_account_access_execution":true,"serial_execution_only":true,
        "production_backend_changed":false,"protocol_capacity_changed":false,"public_data_availability_accepted":false,"production_activation":false}});
    let bytes = serde_json::to_vec(&observed).unwrap();
    fs::write(output.join("observation.json"), &bytes).unwrap();
    println!("{}", String::from_utf8(bytes).unwrap());
}
