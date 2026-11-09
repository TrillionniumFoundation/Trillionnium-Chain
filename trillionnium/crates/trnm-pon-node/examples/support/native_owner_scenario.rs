//! Actual native calls in two fresh temporary owner namespaces. The schedule
//! and validation timestamps are controlled test inputs, not a network model.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Instant;
use trnm_crypto_primitives::{pon_work, sign_hex, signing_key_from_hex};
use trnm_pon_node::{development_public, Error, ErrorCode, Node, Packet, Result, Settings};
use trnm_pon_node::{OwnerCensusLimits, OwnerCensusProgress};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

pub struct Artifact {
    pub id: Hash,
    pub kind: &'static str,
    pub bytes: Vec<u8>,
}

pub struct Run {
    pub report: Value,
    pub artifacts: Vec<Artifact>,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

struct Trace {
    epoch: Instant,
    operations: Vec<Value>,
    snapshots: Vec<Value>,
    artifacts: Vec<Artifact>,
}
impl Trace {
    fn now(&self) -> Result<u64> {
        u64::try_from(self.epoch.elapsed().as_nanos()).map_err(|_| "TRACE_CLOCK_RANGE".into())
    }
    fn call<T>(
        &mut self,
        node_name: &str,
        operation: &str,
        input: Value,
        perform: impl FnOnce() -> Result<T>,
        describe: impl FnOnce(&T) -> Result<Value>,
    ) -> Result<T> {
        let started = self.now()?;
        let result = perform();
        let ended = self.now()?;
        let result_json = match &result {
            Ok(value) => json!({"accepted":true,"value":describe(value)?}),
            Err(error) => json!({"accepted":false,"error":error.to_string(),
                "error_kind":format!("{:?}",error.kind()),"requires_owner_stop":error.requires_owner_stop()}),
        };
        self.operations.push(json!({
            "sequence":self.operations.len()+1,"node":node_name,"operation":operation,
            "started_ns":started,"ended_ns":ended,"input":input,"result":result_json,
            "clock_scope":"one process invocation Instant; call interval only",
            "global_ready_time":null,"final_parent_binding_time":null
        }));
        result
    }
    fn make(
        &mut self,
        node_name: &str,
        node: &Node,
        parent: Hash,
        timestamp: u64,
        miner: u64,
        transactions: Vec<Vec<u8>>,
    ) -> Result<Packet> {
        let packet = self.call(node_name,"Node::make",json!({"parent":hex::encode(parent),"header_timestamp":timestamp}),
            || node.make(parent,transactions,development_public(miner)?,timestamp,4096),
            |packet| Ok(json!({"block":hex::encode(packet.id()?),"packet_sha256":digest(&packet.encode()?)})))?;
        self.artifacts.push(Artifact {
            id: packet.id()?,
            kind: "native_produced_packet",
            bytes: packet.encode()?,
        });
        Ok(packet)
    }
    fn admit(
        &mut self,
        node_name: &str,
        node: &mut Node,
        packet: &Packet,
        now: u64,
    ) -> Result<Hash> {
        self.call(node_name,"Node::admit",json!({"block":hex::encode(packet.id()?),"validation_now":now,"packet_sha256":digest(&packet.encode()?)}),
            || node.admit(packet,now),|id| Ok(json!({"admitted":hex::encode(id)})))
    }
    fn activate(
        &mut self,
        node_name: &str,
        node: &mut Node,
        target: Hash,
        now: u64,
    ) -> Result<Hash> {
        let before = node.active()?;
        self.call(
            node_name,
            "Node::activate_observed",
            json!({"target":hex::encode(target),"validation_now":now,
                "incumbent":hex::encode(before.0),"generation_before":before.1}),
            || {
                let selected = node.activate_observed(target, now)?;
                Ok((selected, node.active()?.1))
            },
            |(tip, generation)| {
                Ok(json!({"selected":hex::encode(tip),"generation_after":generation}))
            },
        )
        .map(|value| value.0)
    }
    fn snapshot(&mut self, name: &str, node_name: &str, node: &Node, now: u64) -> Result<usize> {
        let observed = self.call(
            node_name,
            "Node::native_owner_census",
            json!({"name":name,"validation_now":now}),
            || node.native_owner_census(now, OwnerCensusLimits::default()),
            |value| Ok(serde_json::to_value(value)?),
        )?;
        let index = self.snapshots.len();
        self.snapshots
            .push(json!({"name":name,"node":node_name,"census":observed}));
        Ok(index)
    }
}

fn signed_transfer(settings: &Settings) -> Result<Vec<u8>> {
    let mut payload = development_public(1)?.to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut transaction = Envelope {
        network: settings.network(),
        sender: development_public(0)?,
        nonce: 1,
        expiry: 1000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key = signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()])))
        .map_err(|e| Error::from(format!("TEST_KEY:{e:?}")))?;
    transaction.signature = hex::decode(sign_hex(
        &key,
        &transaction
            .signing_digest()
            .map_err(|e| Error::from(format!("TEST_SIGN:{e:?}")))?,
    ))
    .map_err(|error| Error::from(format!("TEST_SIGNATURE_HEX:{error}")))?
    .try_into()
    .map_err(|_| "TEST_SIGNATURE")?;
    transaction
        .encode()
        .map_err(|e| Error::from(format!("TEST_TRANSACTION:{e:?}")))
}

pub fn run() -> Result<Run> {
    const NOW: u64 = 100;
    const FUTURE: u64 = 100_000;
    let settings = Settings::development(Some(1))?;
    let alice_dir = tempfile::tempdir()?;
    let bob_dir = tempfile::tempdir()?;
    let mut alice = Node::open(alice_dir.path(), settings.clone(), 1)?;
    let mut bob = Node::open(bob_dir.path(), settings.clone(), 1)?;
    let mut trace = Trace {
        epoch: Instant::now(),
        operations: vec![],
        snapshots: vec![],
        artifacts: vec![],
    };
    let genesis = settings.genesis();
    let transaction = signed_transfer(&settings)?;
    let transaction_id = hash(b"tx-id", &[&transaction]);
    let mut alice_packets = Vec::new();
    let mut tip = genesis;
    for height in 1..=7 {
        let packet = trace.make(
            "alice",
            &alice,
            tip,
            height * 10 + 1,
            0,
            if height == 1 {
                vec![transaction.clone()]
            } else {
                vec![]
            },
        )?;
        tip = trace.admit("alice", &mut alice, &packet, NOW)?;
        trace.activate("alice", &mut alice, tip, NOW)?;
        alice_packets.push(packet);
    }
    let b = alice_packets[0].id()?;
    let a7 = tip;
    let confirmed=trace.call("alice","Node::confirmation",json!({"block":hex::encode(b),"transaction":hex::encode(transaction_id),"validation_now":NOW}),
        || alice.confirmation(transaction_id,b,NOW),|value| Ok(serde_json::to_value(value)?))?;
    if !confirmed.confirmed {
        return Err("TEST_SIX_SUCCESSORS_NOT_CONFIRMED".into());
    }
    trace.snapshot("alice_confirmed_a7", "alice", &alice, NOW)?;
    trace.snapshot("bob_unseen_a1", "bob", &bob, NOW)?;
    let before_hidden = trace.snapshot("alice_before_hidden_branch", "alice", &alice, NOW)?;
    let mut bob_packets = Vec::new();
    tip = genesis;
    for height in 1..=8 {
        let packet = trace.make("bob", &bob, tip, height * 10 + 2, 2, vec![])?;
        tip = trace.admit("bob", &mut bob, &packet, NOW)?;
        trace.activate("bob", &mut bob, tip, NOW)?;
        bob_packets.push(packet);
    }
    let b8 = tip;
    trace.snapshot("bob_hidden_b8", "bob", &bob, NOW)?;
    let after_hidden = trace.snapshot("alice_after_hidden_branch", "alice", &alice, NOW)?;
    if trace.snapshots[before_hidden]["census"]["local_view_commitment"]
        != trace.snapshots[after_hidden]["census"]["local_view_commitment"]
    {
        return Err("TEST_HIDDEN_BRANCH_CHANGED_LOCAL_VIEW".into());
    }
    // This is an actual full W1 Product failure, before this block is admitted
    // at Alice. Mutating C keeps A/B TaskId and the claimed ticket unchanged.
    let mut malformed = bob_packets[0].clone();
    malformed.proof[4 + 2 * pon_work::CELLS * 4] ^= 1;
    trace.artifacts.push(Artifact {
        id: malformed.id()?,
        kind: "invalid_product_control",
        bytes: malformed.encode()?,
    });
    let bad = trace
        .admit("alice", &mut alice, &malformed, NOW)
        .expect_err("invalid product must be refused");
    if !bad.to_string().starts_with("WORK:") {
        return Err("TEST_EXPECTED_NATIVE_WORK_REFUSAL".into());
    }
    tip = a7;
    for height in 8..=9 {
        let packet = trace.make("alice", &alice, tip, height * 10 + 1, 0, vec![])?;
        tip = trace.admit("alice", &mut alice, &packet, NOW)?;
        alice_packets.push(packet);
    }
    let a9 = tip;
    trace.snapshot("alice_a9_admitted_not_active", "alice", &alice, NOW)?;
    let future = trace.make("alice", &alice, a9, FUTURE, 0, vec![])?;
    trace
        .admit("alice", &mut alice, &future, NOW)
        .expect_err("future admission must defer");
    let future_id = trace.admit("alice", &mut alice, &future, FUTURE)?;
    let current_child = trace.make("alice", &alice, future_id, 105, 0, vec![])?;
    let current_child_id = trace.admit("alice", &mut alice, &current_child, FUTURE)?;
    trace.snapshot("alice_future_ancestor_deferred", "alice", &alice, NOW)?;
    let deferred = trace
        .activate("alice", &mut alice, current_child_id, NOW)
        .expect_err("future ancestor must defer activation");
    if deferred.to_string() != "TIME_DEFERRED" {
        return Err("TEST_EXPECTED_TIME_DEFERRED".into());
    }
    for packet in &bob_packets {
        trace.admit("alice", &mut alice, packet, NOW)?;
    }
    trace.snapshot("alice_after_b8_admitted", "alice", &alice, NOW)?;
    // B7 ties A7: the real activation rule retains the incumbent.
    let tie = trace.activate("alice", &mut alice, bob_packets[6].id()?, NOW)?;
    if tie != a7 {
        return Err("TEST_NATIVE_TIE_REPLACED".into());
    }
    // A9 is eligible and heavier than B8, but activating submitted B8 only
    // compares it to the score-7 incumbent. The census exposes residual lag.
    let selected = trace.activate("alice", &mut alice, b8, NOW)?;
    if selected != b8 {
        return Err("TEST_NATIVE_REORG_NOT_EXECUTED".into());
    }
    trace.snapshot("alice_after_strict_reorg_b8", "alice", &alice, NOW)?;
    let reorged=trace.call("alice","Node::confirmation",json!({"block":hex::encode(b),"transaction":hex::encode(transaction_id),"validation_now":NOW}),
        || alice.confirmation(transaction_id,b,NOW),|value| Ok(serde_json::to_value(value)?))?;
    if reorged.confirmed || !reorged.reorged {
        return Err("TEST_NATIVE_REORG_OBSERVATION".into());
    }
    trace.snapshot("alice_future_mature_pending", "alice", &alice, FUTURE)?;
    trace.activate("alice", &mut alice, current_child_id, FUTURE)?;
    trace.snapshot("alice_after_select_mature", "alice", &alice, FUTURE)?;

    let before = alice.active()?;
    let cancelled = trace
        .call(
            "alice",
            "Node::native_owner_census cancelled",
            json!({"injected_control":"LegacyRequestDeadline at BeforeOutput"}),
            || {
                alice.native_owner_census_with_progress(
                    FUTURE,
                    OwnerCensusLimits::default(),
                    &|point| {
                        if matches!(point, OwnerCensusProgress::BeforeOutput) {
                            Err(Error::new(ErrorCode::LegacyRequestDeadline))
                        } else {
                            Ok(())
                        }
                    },
                )
            },
            |value| Ok(serde_json::to_value(value)?),
        )
        .expect_err("cancelled census cannot return partial success");
    if !cancelled.is(ErrorCode::LegacyRequestDeadline)
        || cancelled.requires_owner_stop()
        || alice.active()? != before
    {
        return Err("TEST_CANCELLED_CENSUS_BOUNDARY".into());
    }
    trace
        .call(
            "alice",
            "Node::native_owner_census exhausted",
            json!({"maximum_blocks":1}),
            || {
                alice.native_owner_census(
                    FUTURE,
                    OwnerCensusLimits {
                        maximum_blocks: 1,
                        ..OwnerCensusLimits::default()
                    },
                )
            },
            |value| Ok(serde_json::to_value(value)?),
        )
        .expect_err("incomplete census cannot succeed");

    let packet_artifacts=trace.artifacts.iter().map(|artifact| json!({
        "id":hex::encode(artifact.id),"kind":artifact.kind,"sha256":digest(&artifact.bytes),"bytes":artifact.bytes.len(),
        "path":format!("packets/{}.{}.pnp1",hex::encode(artifact.id),digest(&artifact.bytes))
    })).collect::<Vec<_>>();
    let report = json!({
        "schema":"pon-native-owner-observation-run-v1",
        "starting_source_commit":"f8362822b406463ac3dfcc911a0c3eda1686e32d",
        "native_execution_exercised":true,
        "execution_scope":"two fresh in-process native Legacy PNP1 owners, controlled calls and validation clocks",
        "source_of_packets":"actual Node::make with complete native PNW1; then Node::admit and native state execution",
        "network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),"genesis":hex::encode(genesis),
        "references":{"target_block":hex::encode(b),"target_transaction":hex::encode(transaction_id),
            "confirmation_tip":hex::encode(a7),"known_heavier_b_tip":hex::encode(a9),
            "hidden_competing_tip":hex::encode(b8),"future_ancestor":hex::encode(future_id),"current_time_child":hex::encode(current_child_id),
            "initial_confirmation_index":0,"post_reorg_confirmation_index":1,
            "hidden_before_snapshot":"alice_before_hidden_branch","hidden_after_snapshot":"alice_after_hidden_branch"},
        "confirmations":[confirmed,reorged],"snapshots":trace.snapshots,"operations":trace.operations,"packet_artifacts":packet_artifacts,
        "scenarios":[
            {"name":"early_unseen_target","reference_snapshot":"alice_confirmed_a7","confirmation_index":0,"competing_snapshot":"bob_unseen_a1"},
            {"name":"strict_reorg_with_known_heavier_b_chain","reference_snapshot":"alice_confirmed_a7","confirmation_index":0,"competing_snapshot":"alice_after_strict_reorg_b8"},
            {"name":"mature_b_chain_not_yet_selected","reference_snapshot":"alice_confirmed_a7","confirmation_index":0,"competing_snapshot":"alice_future_mature_pending"}
        ],
        "native_runtime_attested":false,"exported_artifact_authenticated":false,
        "global_ready_attested":false,"world_coverage_attested":false,"physical_clock_authenticated":false,
        "probabilistic_environment_bound":false,"six_successor_risk_qualified":false,"probability_bound":null,
        "unknowns":["unadmitted bytes/jobs at either owner","remote branches and helper preprocessing",
            "global first-ready times","final parent-binding and stale-completion envelope",
            "initial residual state","network clock/delivery/availability envelopes","trusted export attestation"]
    });
    Ok(Run {
        report,
        artifacts: trace.artifacts,
    })
}
