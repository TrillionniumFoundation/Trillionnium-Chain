//! Native revision-3 application transitions. No work/fork/Hepta authority is implied.
//! Parallel workers speculate against one immutable snapshot; exact key and prefix
//! reads are validated in canonical order. Conflict or speculative rejection is
//! re-executed ONCE against that order's current state, never an unbounded retry loop.
use crate::public_evaluation;
use crate::qualified_task_lifecycle;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use trnm_crypto_primitives::qualified_work_task::{verify_development_statement, AdmissionContext};
use trnm_crypto_primitives::verify_hex_strict;
use trnm_protocol::pon_wire::{hash, state_root, Envelope, Hash};
use trnm_protocol::qualified_work_task::lifecycle_v2::PROFILE as LIFECYCLE_TASK_PROFILE;
use trnm_protocol::qualified_work_task::{SignedQualifiedWorkTask, TaskPurpose};

pub const SIGNED_TASK_PROFILE: &str = "signed-task-dev-v1";
pub const LEGACY_TASK_PROFILE: &str = "legacy-task-v1";
pub const QUALIFIED_DEMANDS: u64 = 16;

pub type State = BTreeMap<String, Value>;
pub type Result<T> = std::result::Result<T, &'static str>;
const ZERO: Hash = [0; 32];
fn require(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
fn num(v: &Value) -> Result<u64> {
    v.as_u64().ok_or("RANGE")
}
fn field(v: &Value, k: &str) -> Result<u64> {
    num(v.get(k).ok_or("STATE")?)
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k).and_then(Value::as_str).ok_or("STATE")
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or("RANGE")
}
fn hash32(s: &str) -> Result<Hash> {
    require(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "NONCANONICAL",
    )?;
    let mut h = [0; 32];
    hex::decode_to_slice(s, &mut h).map_err(|_| "NONCANONICAL")?;
    Ok(h)
}
fn canonical(v: &Value) -> Result<Vec<u8>> {
    fn visit(v: &Value) -> Result<()> {
        match v {
            Value::Null | Value::Bool(_) => Ok(()),
            Value::Number(n) => require(n.is_u64() || n.is_i64(), "RANGE"),
            Value::String(s) => require(s.is_ascii(), "NONCANONICAL"),
            Value::Array(xs) => {
                for x in xs {
                    visit(x)?;
                }
                Ok(())
            }
            Value::Object(m) => {
                for (k, v) in m {
                    require(k.is_ascii(), "NONCANONICAL")?;
                    visit(v)?;
                }
                Ok(())
            }
        }
    }
    visit(v)?;
    serde_json::to_vec(v).map_err(|_| "NONCANONICAL")
}
pub fn root(state: &State) -> Result<Hash> {
    let mut bytes = BTreeMap::new();
    for (k, v) in state {
        bytes.insert(k.as_bytes().to_vec(), canonical(v)?);
    }
    state_root(&bytes).map_err(|_| "LIMIT")
}

#[derive(Clone)]
pub struct Config {
    pub network: Hash,
    pub parameters: Hash,
    pub family: Hash,
    pub plan: Hash,
    pub evaluators: BTreeSet<String>,
    pub fees: [u64; 22],
    pub params: Value,
    pub model_registry: Value,
}
impl Config {
    /// Installed experimental genesis context, not caller-supplied authority booleans.
    pub fn installed() -> Result<Self> {
        Self::installed_with_evaluation_policy("legacy-first-two-v3")
    }
    /// Explicit successor selects different network/parameter commitments. The default
    /// revision3 bytes and economics remain unchanged; this is not a hot upgrade.
    pub fn installed_with_evaluation_policy(policy: &str) -> Result<Self> {
        Self::installed_with_profiles(policy, LEGACY_TASK_PROFILE)
    }
    pub fn installed_with_profiles(policy: &str, task_profile: &str) -> Result<Self> {
        Self::installed_with_model_profiles(policy, task_profile, "linear-expert-dev-v1")
    }
    pub fn installed_with_model_profiles(
        policy: &str,
        task_profile: &str,
        model_profile: &str,
    ) -> Result<Self> {
        let mut params: Value =
            serde_json::from_str(include_str!("../../../../config/pon/devnet-v1.json"))
                .map_err(|_| "CONFIG")?;
        require(
            params["consensus_revision"] == 3 && params["production_activation"] == false,
            "CONFIG",
        )?;
        match policy {
            "legacy-first-two-v3" => {}
            trnm_verification_profiles::closed_round::PROFILE => {
                let policy: Value = serde_json::from_str(include_str!(
                    "../../../../config/pon/evaluation-round-v1.json"
                ))
                .map_err(|_| "CONFIG")?;
                require(policy["production_activation"] == false, "CONFIG")?;
                for (key, value) in policy["genesis_overrides"].as_object().ok_or("CONFIG")? {
                    params[key] = value.clone();
                }
                params["evaluation_policy_hash"] = json!(hex::encode(hash(
                    b"evaluation-policy",
                    &[&canonical(&policy)?]
                )));
            }
            public_evaluation::PROFILE => {
                let policy: Value = serde_json::from_str(include_str!(
                    "../../../../config/pon/public-evaluation-native-v1.json"
                ))
                .map_err(|_| "CONFIG")?;
                require(
                    policy["production_activation"] == false
                        && policy["independent_governance_accepted"] == false
                        && policy["objective_model_quality"] == false,
                    "CONFIG",
                )?;
                require(
                    policy["storage_revision"] == public_evaluation::STORAGE_REVISION
                        && policy["maximum_record_bytes"] == 4096,
                    "CONFIG",
                )?;
                for (name, expected) in [
                    ("candidate_end_offset", public_evaluation::CANDIDATE_END),
                    ("commit_end_offset", public_evaluation::COMMIT_END),
                    ("reveal_end_offset", public_evaluation::REVEAL_END),
                    ("adoption_start_offset", public_evaluation::ADOPTION_START),
                    ("appeal_limit_per_candidate", 16),
                    ("archive_retention_blocks", 256),
                    ("round_blocks", 128),
                    ("maximum_candidates_per_round", 512),
                ] {
                    require(field(&policy, name)? == expected, "CONFIG")?;
                }
                for tag in 14..=17 {
                    require(
                        field(&policy["base_fee_units"], &tag.to_string())? == 160,
                        "CONFIG",
                    )?;
                }
                require(
                    field(&params, "candidate_round_blocks")? == 128
                        && field(&params, "max_candidate_history_per_round")? == 512,
                    "CONFIG",
                )?;
                for (key, value) in policy["genesis_overrides"].as_object().ok_or("CONFIG")? {
                    params[key] = value.clone();
                }
                params["evaluation_policy_hash"] = json!(hex::encode(hash(
                    b"evaluation-policy",
                    &[&canonical(&policy)?]
                )));
            }
            _ => return Err("EVALUATION_POLICY"),
        }
        match task_profile {
            LEGACY_TASK_PROFILE => {}
            SIGNED_TASK_PROFILE => {
                let registry: Value = serde_json::from_str(include_str!(
                    "../../../../config/pon/qualified-work-task-v1.json"
                ))
                .map_err(|_| "CONFIG")?;
                require(
                    registry["production_eligible"] == false
                        && registry["hardness_accepted"] == false,
                    "CONFIG",
                )?;
                let revision = if policy == public_evaluation::PROFILE {
                    6
                } else {
                    5
                };
                params["consensus_revision"] = json!(revision);
                params["chain_label"] =
                    json!(format!("trnm-pon-signed-task-devnet-{revision}-{policy}"));
                params["work_task_profile"] = json!(SIGNED_TASK_PROFILE);
                params["qualified_task_registry_hash"] = json!(hex::encode(hash(
                    b"qualified-task-registry-v1",
                    &[&canonical(&registry)?]
                )));
            }
            LIFECYCLE_TASK_PROFILE => {
                let registry: Value = serde_json::from_str(include_str!(
                    "../../../../config/pon/qualified-task-lifecycle-v2.json"
                ))
                .map_err(|_| "CONFIG")?;
                require(
                    registry["production_eligible"] == false
                        && registry["hardness_accepted"] == false,
                    "CONFIG",
                )?;
                params["consensus_revision"] = json!(7);
                params["chain_label"] = json!(format!("trnm-pon-task-lifecycle-devnet-7-{policy}"));
                params["work_task_profile"] = json!(LIFECYCLE_TASK_PROFILE);
                params["qualified_task_registry_hash"] = json!(hex::encode(hash(
                    b"qualified-task-registry-v2",
                    &[&canonical(&registry)?]
                )));
            }
            _ => return Err("WORK_TASK_PROFILE"),
        }
        if policy == public_evaluation::PROFILE {
            params["chain_label"] = json!(format!(
                "{}-evaluation-storage{}",
                text(&params, "chain_label")?,
                public_evaluation::STORAGE_REVISION
            ));
        }
        let model: Value = match model_profile {
            "linear-expert-dev-v1" => {
                serde_json::from_str(include_str!("../../../../config/pon/model-family-v1.json"))
                    .map_err(|_| "CONFIG")?
            }
            "smollm2-135m-cpu-dev-v1" => {
                require(policy == public_evaluation::PROFILE, "MODEL_PROFILE_POLICY")?;
                params["model_profile"] = json!(model_profile);
                params["chain_label"] =
                    json!(format!("{}-{model_profile}", text(&params, "chain_label")?));
                serde_json::from_str(include_str!(
                    "../../../../config/pon/model-family-smollm2-135m-v1.json"
                ))
                .map_err(|_| "CONFIG")?
            }
            _ => return Err("MODEL_PROFILE"),
        };
        if model_profile != "linear-expert-dev-v1" {
            let maximum = field(&model, "artifact_max_bytes")?;
            require(
                maximum > 0 && maximum <= field(&params, "max_artifact_bytes")?,
                "MODEL_PROFILE_LIMIT",
            )?;
            params["max_artifact_bytes"] = json!(maximum);
        }
        let wire: Value =
            serde_json::from_str(include_str!("../../../../config/pon/ledger-v1.json"))
                .map_err(|_| "CONFIG")?;
        let network = hash(b"network", &[text(&params, "chain_label")?.as_bytes()]);
        let work: Value =
            serde_json::from_str(include_str!("../../../../config/pon/work-profile-v1.json"))
                .map_err(|_| "CONFIG")?;
        let parameters = hash(
            b"parameters",
            &[
                &canonical(&params)?,
                &canonical(&wire)?,
                &canonical(&work)?,
                &canonical(&model)?,
            ],
        );
        let family = hash(b"family", &[&canonical(&model)?]);
        let plan = if model_profile != "linear-expert-dev-v1" {
            hash(
                b"plan",
                &[
                    b"native-llm-strong-baseline-dev-v1",
                    &family,
                    &hash32(text(&params, "evaluation_policy_hash")?)?,
                ],
            )
        } else if policy == "legacy-first-two-v3" {
            hash(b"plan", &[b"public-source-file-disjoint-v1"])
        } else {
            hash(
                b"plan",
                &[
                    b"public-source-file-disjoint-v1",
                    &hash32(text(&params, "evaluation_policy_hash")?)?,
                ],
            )
        };
        let mut fees = [0; 22];
        let mut tags = BTreeSet::new();
        for c in wire["commands"].as_array().ok_or("CONFIG")? {
            let tag = field(c, "tag")? as usize;
            require((1..=12).contains(&tag) && tags.insert(tag), "CONFIG")?;
            fees[tag] = field(c, "base_fee_units")?;
        }
        require(tags.len() == 12, "CONFIG")?;
        // The signed-task extension has an explicit fixed development base fee.
        // It is refused under every historical context even though its codec exists.
        fees[13] = 100;
        for fee in &mut fees[14..=17] {
            *fee = 160;
        }
        for fee in &mut fees[18..=21] {
            *fee = 100;
        }
        let mut evaluators = BTreeSet::new();
        for i in 0_u64..3 {
            let seed = hash(b"DEV-ONLY-KEY", &[&i.to_le_bytes()]);
            let key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(seed))
                .map_err(|_| "CONFIG")?;
            evaluators.insert(trnm_crypto_primitives::public_key_hex(&key));
        }
        Ok(Self {
            network,
            parameters,
            family,
            plan,
            evaluators,
            fees,
            params,
            model_registry: model,
        })
    }
    fn limit(&self, name: &str) -> Result<u64> {
        field(&self.params, name)
    }
    pub fn task_profile(&self) -> &str {
        self.params["work_task_profile"]
            .as_str()
            .unwrap_or(LEGACY_TASK_PROFILE)
    }
    pub fn qualified_demand_id(&self, index: u64) -> Result<Hash> {
        require(
            self.task_profile() == SIGNED_TASK_PROFILE && index < QUALIFIED_DEMANDS,
            "TASK_DEMAND",
        )?;
        Ok(hash(
            b"qualified-development-demand-v1",
            &[&self.network, &self.parameters, &index.to_le_bytes()],
        ))
    }
    pub fn qualified_demand_purpose(index: u64) -> Result<TaskPurpose> {
        require(index < QUALIFIED_DEMANDS, "TASK_DEMAND")?;
        Ok(if index == 0 {
            TaskPurpose::Maintenance
        } else {
            match index % 3 {
                1 => TaskPurpose::InferenceContraction,
                2 => TaskPurpose::EvaluationContraction,
                _ => TaskPurpose::AdapterContraction,
            }
        })
    }
    pub fn qualified_task_context(&self, demand_id: Hash, height: u64) -> Result<AdmissionContext> {
        require(
            self.task_profile() == SIGNED_TASK_PROFILE,
            "WORK_TASK_PROFILE",
        )?;
        let mut known = false;
        for index in 0..QUALIFIED_DEMANDS {
            known |= self.qualified_demand_id(index)? == demand_id;
        }
        require(known, "TASK_DEMAND")?;
        let seed = hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]);
        let key = trnm_crypto_primitives::signing_key_from_hex(&hex::encode(seed))
            .map_err(|_| "CONFIG")?;
        let source = key.verifying_key().to_bytes();
        Ok(AdmissionContext {
            network: self.network,
            parameters: self.parameters,
            source,
            demand_id,
            source_record: hash(
                b"qualified-development-source-record-v1",
                &[&demand_id, b"public-fixture-not-real-user-demand"],
            ),
            authorization_scope: hash(
                b"qualified-development-authorization-v1",
                &[
                    &self.network,
                    &self.parameters,
                    b"development-attestation-not-local-permission",
                ],
            ),
            withdrawal_head: hash(
                b"qualified-development-withdrawal-v1",
                &[&self.network, &self.parameters, &0_u64.to_le_bytes()],
            ),
            availability_manifest: hash(b"qualified-development-da-manifest-v1", &[&demand_id]),
            availability_root: hash(b"qualified-development-da-attestation-v1", &[&demand_id]),
            height,
            required_retention_blocks: 100,
        })
    }
}

#[derive(Default, Clone, Debug)]
pub struct Metrics {
    pub workers: usize,
    pub speculative: usize,
    pub reexecuted: usize,
    pub committed_without_replay: usize,
    pub peak_inflight: usize,
    pub serial_conflict_batches: usize,
    pub workers_spawned: usize,
    pub signature_verifications: usize,
    pub state_transition_ns: u128,
    pub state_root_ns: u128,
}
#[derive(Clone, Debug)]
pub struct Output {
    pub state: State,
    pub receipts: Vec<Vec<u8>>,
    pub root: Hash,
    pub metrics: Metrics,
}
#[derive(Clone, Debug)]
struct Patch {
    writes: BTreeMap<String, Value>,
    reads: BTreeMap<String, Option<Value>>,
    scans: BTreeMap<String, State>,
    fee: u64,
    receipt: Vec<u8>,
}
struct View<'a> {
    base: &'a State,
    writes: BTreeMap<String, Value>,
    reads: BTreeMap<String, Option<Value>>,
    scans: BTreeMap<String, State>,
}
impl<'a> View<'a> {
    fn new(base: &'a State) -> Self {
        Self {
            base,
            writes: BTreeMap::new(),
            reads: BTreeMap::new(),
            scans: BTreeMap::new(),
        }
    }
    fn get(&mut self, key: &str) -> Option<Value> {
        self.reads
            .entry(key.to_owned())
            .or_insert_with(|| self.base.get(key).cloned());
        self.writes.get(key).or_else(|| self.base.get(key)).cloned()
    }
    fn put(&mut self, key: String, value: Value) {
        self.reads
            .entry(key.clone())
            .or_insert_with(|| self.base.get(&key).cloned());
        self.writes.insert(key, value);
    }
    fn scan(&mut self, prefix: &str) -> State {
        self.scans.entry(prefix.to_owned()).or_insert_with(|| {
            self.base
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        });
        let mut rows = self.scans[prefix].clone();
        rows.extend(
            self.writes
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        rows
    }
    fn account(&mut self, who: &str) -> Value {
        self.get(&format!("account:{who}"))
            .unwrap_or_else(|| json!({"balance":0,"nonce":0}))
    }
    fn credit(&mut self, who: &str, amount: u64) -> Result<()> {
        let mut a = self.account(who);
        a["balance"] = json!(add(field(&a, "balance")?, amount)?);
        self.put(format!("account:{who}"), a);
        Ok(())
    }
    fn debit(&mut self, who: &str, amount: u64) -> Result<()> {
        let mut a = self.account(who);
        let b = field(&a, "balance")?;
        require(amount > 0 && b >= amount, "FUNDS")?;
        a["balance"] = json!(b - amount);
        self.put(format!("account:{who}"), a);
        Ok(())
    }
    fn object(&mut self, prefix: &str, id: Hash) -> Result<(String, Value)> {
        let k = format!("{prefix}{}", hex::encode(id));
        let v = self.get(&k).ok_or("STATE")?;
        Ok((k, v))
    }
    fn deadline(&mut self, cfg: &Config, d: u64, height: u64) -> Result<()> {
        self.deadline_with_lifetime(cfg, d, height, cfg.limit("max_task_lifetime_blocks")?)
    }
    fn deadline_with_lifetime(
        &mut self,
        cfg: &Config,
        d: u64,
        height: u64,
        lifetime: u64,
    ) -> Result<()> {
        require(height < d && d <= add(height, lifetime)?, "EXPIRED")?;
        let mut all = self.scan("task:");
        all.extend(self.scan("quota:"));
        all.extend(self.scan("release:"));
        let mut pending = 0;
        let mut due = 0;
        for v in all.values() {
            if field(v, "remaining")? > 0 {
                pending += 1;
                if field(v, "deadline")? == d {
                    due += 1;
                }
            }
        }
        require(
            pending < cfg.limit("max_pending_tasks")?
                && due < cfg.limit("mandatory_expiry_per_block")?,
            "LIMIT",
        )
    }
}
impl qualified_task_lifecycle::LifecycleState for View<'_> {
    fn get(&mut self, key: &str) -> Option<Value> {
        self.get(key)
    }
    fn put(&mut self, key: String, value: Value) {
        self.put(key, value);
    }
    fn scan(&mut self, prefix: &str) -> State {
        self.scan(prefix)
    }
}
impl Patch {
    fn current(&self, state: &State) -> bool {
        self.reads.iter().all(|(k, v)| state.get(k) == v.as_ref())
            && self.scans.iter().all(|(prefix, old)| {
                state
                    .iter()
                    .filter(|(k, _)| k.starts_with(prefix))
                    .eq(old.iter())
            })
    }
    fn apply(self, state: &mut State) {
        state.extend(self.writes);
    }
}
struct Payload<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Payload<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.pos.checked_add(N).ok_or("LENGTH")?;
        let out = self
            .bytes
            .get(self.pos..end)
            .ok_or("LENGTH")?
            .try_into()
            .map_err(|_| "LENGTH")?;
        self.pos = end;
        Ok(out)
    }
    fn n(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take()?))
    }
    fn h(&mut self) -> Result<Hash> {
        self.take()
    }
    fn blob(&mut self) -> Result<&'a [u8]> {
        let length = u16::from_le_bytes(self.take()?) as usize;
        let end = self.pos.checked_add(length).ok_or("LENGTH")?;
        let value = self.bytes.get(self.pos..end).ok_or("LENGTH")?;
        self.pos = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take::<1>()?[0])
    }
}
fn allocation_leaf(cid: Hash, payee: Hash, score: u64) -> Hash {
    hash(b"allocation-leaf", &[&cid, &payee, &score.to_le_bytes()])
}
fn pair(a: Hash, b: Hash) -> Hash {
    if a < b {
        hash(b"allocation-node", &[&a, &b])
    } else {
        hash(b"allocation-node", &[&b, &a])
    }
}
fn allocation_root(mut leaves: Vec<Hash>) -> Result<Hash> {
    require(!leaves.is_empty(), "ROOT")?;
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            leaves.push(*leaves.last().ok_or("ROOT")?);
        }
        leaves = leaves.chunks_exact(2).map(|x| pair(x[0], x[1])).collect();
    }
    Ok(leaves[0])
}
fn active_candidate(v: &Value, current: &str, height: u64, cfg: &Config) -> Result<bool> {
    let status = text(v, "status")?;
    let submitted = v
        .get("submitted_height")
        .map(num)
        .transpose()?
        .unwrap_or(height);
    Ok(text(v, "parent")? == current
        && v.get("submission_round").map(num).transpose()?.unwrap_or(0)
            == height / cfg.limit("candidate_round_blocks")?
        && (status == "submitted" || status == "evaluated")
        && (status != "evaluated" || field(v, "score")? > 0)
        && height <= add(submitted, cfg.limit("candidate_lifetime_blocks")?)?)
}

// This carrier is private and tied to the exact immutable input and installed context.
// Main-envelope verification is independent of branch state and is done only once.
// Consumer-use signatures still depend on the actual quota state and are checked there.
struct Prepared {
    envelope: Envelope,
    sender: String,
    encoded_len: usize,
}
fn prepare(raw: &[u8], height: u64, cfg: &Config, signatures: &AtomicUsize) -> Result<Prepared> {
    let tx = Envelope::decode(raw).map_err(|_| "ENCODING")?;
    require(
        !(18..=21).contains(&tx.tag) || cfg.task_profile() == LIFECYCLE_TASK_PROFILE,
        "WORK_TASK_PROFILE",
    )?;
    require(
        !(14..=17).contains(&tx.tag) || public_evaluation::enabled(cfg),
        "PUBLIC_EVAL_PROFILE",
    )?;
    require(
        tx.tag != 7 || !public_evaluation::enabled(cfg),
        "PUBLIC_EVAL_PROFILE",
    )?;
    require(
        tx.tag != 13 || cfg.task_profile() == SIGNED_TASK_PROFILE,
        "WORK_TASK_PROFILE",
    )?;
    require(
        tx.tag != 12 || cfg.task_profile() == LEGACY_TASK_PROFILE,
        "WORK_TASK_PROFILE",
    )?;
    require(tx.network == cfg.network, "NETWORK")?;
    require(height <= tx.expiry, "EXPIRED")?;
    let sender = hex::encode(tx.sender);
    signatures.fetch_add(1, Ordering::Relaxed);
    verify_hex_strict(
        &sender,
        &tx.signing_digest().map_err(|_| "ENCODING")?,
        &hex::encode(tx.signature),
    )
    .map_err(|_| "SIGNATURE")?;
    Ok(Prepared {
        envelope: tx,
        sender,
        encoded_len: raw.len(),
    })
}
fn apply_prepared(base: &State, prepared: &Prepared, height: u64, cfg: &Config) -> Result<Patch> {
    let tx = &prepared.envelope;
    let sender = prepared.sender.clone();
    let mut s = View::new(base);
    let acct = s.account(&sender);
    require(tx.nonce == add(field(&acct, "nonce")?, 1)?, "NONCE")?;
    let fee = add(
        cfg.fees[tx.tag as usize],
        (prepared.encoded_len as u64)
            .checked_mul(cfg.limit("byte_fee_units")?)
            .ok_or("RANGE")?,
    )?;
    require(tx.fee_limit >= fee, "FEE")?;
    if tx.tag != 11 {
        s.debit(&sender, fee)?;
    } else {
        s.put(format!("account:{sender}"), acct);
    }
    let mut p = Payload {
        bytes: &tx.payload,
        pos: 0,
    };
    match tx.tag {
        1 => {
            let recipient = hex::encode(p.h()?);
            let amount = p.n()?;
            s.debit(&sender, amount)?;
            s.credit(&recipient, amount)?;
        }
        2 => {
            let task = p.h()?;
            let provider = hex::encode(p.h()?);
            let budget = p.n()?;
            let deadline = p.n()?;
            require(
                task == hash(
                    b"task-instance-v3",
                    &[
                        &cfg.network,
                        &cfg.parameters,
                        &tx.sender,
                        &tx.nonce.to_le_bytes(),
                        &hash32(&provider)?,
                        &budget.to_le_bytes(),
                        &deadline.to_le_bytes(),
                    ],
                ),
                "RESOURCE_ID",
            )?;
            let k = format!("task:{}", hex::encode(task));
            require(s.get(&k).is_none(), "DUPLICATE")?;
            s.deadline(cfg, deadline, height)?;
            s.debit(&sender, budget)?;
            s.put(k,json!({"owner":sender,"provider":provider,"remaining":budget,"deadline":deadline,"status":"reserved","output":null}));
        }
        3 => {
            let (k, mut o) = s.object("task:", p.h()?)?;
            require(text(&o, "owner")? == sender, "AUTHORITY")?;
            require(text(&o, "status")? == "reserved", "STATE")?;
            s.credit(&sender, field(&o, "remaining")?)?;
            o["remaining"] = json!(0);
            o["status"] = json!("cancelled");
            s.put(k, o);
        }
        4 => {
            let (k, mut o) = s.object("task:", p.h()?)?;
            let output = p.h()?;
            require(text(&o, "provider")? == sender, "AUTHORITY")?;
            require(
                text(&o, "status")? == "reserved" && height < field(&o, "deadline")?,
                "STATE",
            )?;
            require(output != ZERO, "EVIDENCE")?;
            o["output"] = json!(hex::encode(output));
            o["status"] = json!("receipt");
            s.put(k, o);
        }
        5 => {
            let (k, mut o) = s.object("task:", p.h()?)?;
            let output = hex::encode(p.h()?);
            require(text(&o, "owner")? == sender, "AUTHORITY")?;
            require(
                text(&o, "status")? == "receipt"
                    && height < field(&o, "deadline")?
                    && text(&o, "output")? == output,
                "STATE",
            )?;
            s.credit(text(&o, "provider")?, field(&o, "remaining")?)?;
            o["remaining"] = json!(0);
            o["status"] = json!("settled");
            s.put(k, o);
        }
        6 => {
            let cid = p.h()?;
            let family = p.h()?;
            let parent = p.h()?;
            let artifact = p.h()?;
            let size = p.n()?;
            let components = p.h()?;
            let round = p.n()?;
            require(
                round == height / cfg.limit("candidate_round_blocks")?,
                "SUBMISSION_ROUND",
            )?;
            require(
                cid == hash(
                    b"contribution-v3",
                    &[
                        &tx.sender,
                        &family,
                        &parent,
                        &artifact,
                        &components,
                        &round.to_le_bytes(),
                    ],
                ),
                "ROOT",
            )?;
            let current = s
                .get("model:current")
                .and_then(|v| v.as_str().map(str::to_owned))
                .ok_or("STATE")?;
            require(
                family == cfg.family && hex::encode(parent) == current,
                "STATE",
            )?;
            require(
                size > 0 && size <= cfg.limit("max_artifact_bytes")?,
                "LIMIT",
            )?;
            require(artifact != ZERO, "EVIDENCE")?;
            let history = s.scan("contribution:");
            require(
                (history.len() as u64) < cfg.limit("max_candidate_history_per_round")?,
                "CANDIDATE_WINDOW_FULL",
            )?;
            let mut count = 0;
            for v in history.values() {
                if active_candidate(v, &current, height, cfg)? {
                    count += 1;
                }
            }
            require(count < cfg.limit("max_model_candidates")?, "LIMIT")?;
            let k = format!("contribution:{}", hex::encode(cid));
            let duplicate = format!(
                "artifact:{}:{}:{}",
                hex::encode(parent),
                round,
                hex::encode(artifact)
            );
            require(
                s.get(&k).is_none() && s.get(&duplicate).is_none(),
                "DUPLICATE",
            )?;
            let mut contribution = json!({"owner":sender,"artifact":hex::encode(artifact),"components_root":hex::encode(components),"family":hex::encode(family),"parent":hex::encode(parent),"votes":{},"score":0,"status":"submitted","submitted_height":height,"submission_round":round});
            if public_evaluation::enabled(cfg) {
                let excluded = public_evaluation::excluded(&s.scan("evaluation-disqualified:"));
                contribution["public_evaluation"] =
                    public_evaluation::freeze(cfg, cid, &contribution, height, &excluded)?;
            }
            s.put(k, contribution);
            s.put(duplicate, json!(hex::encode(cid)));
        }
        7 => {
            let (k, mut o) = s.object("contribution:", p.h()?)?;
            let plan = p.h()?;
            let evidence = p.h()?;
            let score = p.n()?;
            require(
                cfg.evaluators.contains(&sender) && text(&o, "owner")? != sender,
                "AUTHORITY",
            )?;
            let current = s.get("model:current").ok_or("STATE")?;
            require(
                text(&o, "status")? == "submitted" && o["parent"] == current,
                "STATE",
            )?;
            require(o["votes"].get(&sender).is_none(), "DUPLICATE")?;
            require(
                plan == cfg.plan && evidence != ZERO && score <= cfg.limit("max_evidence_score")?,
                "EVIDENCE",
            )?;
            o["votes"][&sender] = json!({"score":score,"evidence":hex::encode(evidence)});
            let votes = o["votes"].as_object().ok_or("STATE")?;
            let complete = match text(&cfg.params, "evaluation_profile")? {
                "explicit-attested-dev-profile-not-permissionless-utility" => {
                    votes.len() as u64 >= cfg.limit("evaluation_threshold")?
                }
                trnm_verification_profiles::closed_round::PROFILE => {
                    let author = text(&o, "owner")?;
                    let eligible = cfg
                        .evaluators
                        .iter()
                        .filter(|s| s.as_str() != author)
                        .cloned()
                        .collect();
                    let scores = votes
                        .iter()
                        .map(|(signer, vote)| Ok((signer.clone(), field(vote, "score")?)))
                        .collect::<Result<BTreeMap<_, _>>>()?;
                    trnm_verification_profiles::closed_round::complete_score(
                        &eligible,
                        &scores,
                        cfg.limit("max_evidence_score")?,
                    )?
                    .is_some()
                }
                _ => return Err("EVALUATION_POLICY"),
            };
            if complete {
                let minimum = votes
                    .values()
                    .map(|v| field(v, "score"))
                    .collect::<Result<Vec<_>>>()?
                    .into_iter()
                    .min()
                    .ok_or("STATE")?;
                o["score"] = json!(minimum);
                o["status"] = json!("evaluated");
            }
            s.put(k, o);
        }
        8 => {
            let release = p.h()?;
            let parent = p.h()?;
            let bundle_id = p.h()?;
            let budget = p.n()?;
            let supplied_root = p.h()?;
            let supplied_total = p.n()?;
            let count = p.byte()?;
            let current = s.get("model:current").ok_or("STATE")?;
            require(current == json!(hex::encode(parent)), "STATE")?;
            let (bk, mut bundle) = s.object("contribution:", bundle_id)?;
            if public_evaluation::enabled(cfg) {
                let records = s.scan(&public_evaluation::record_prefix(bundle_id));
                let evaluation =
                    public_evaluation::hydrate(&bundle["public_evaluation"], bundle_id, &records)?;
                public_evaluation::adoption_allowed(&evaluation, height)?;
            }
            require(
                text(&bundle, "status")? == "evaluated"
                    && field(&bundle, "score")? >= cfg.limit("minimum_adoption_score")?,
                "EVIDENCE",
            )?;
            require(
                bundle["parent"] == current
                    && text(&bundle, "components_root")? == hex::encode(supplied_root),
                "ROOT",
            )?;
            let mut leaves = Vec::new();
            let mut adopted = Vec::new();
            let mut total = 0_u64;
            for _ in 0..count {
                let cid = p.h()?;
                let score = p.n()?;
                let (k, mut o) = s.object("contribution:", cid)?;
                if public_evaluation::enabled(cfg) {
                    let records = s.scan(&public_evaluation::record_prefix(cid));
                    let evaluation =
                        public_evaluation::hydrate(&o["public_evaluation"], cid, &records)?;
                    public_evaluation::adoption_allowed(&evaluation, height)?;
                }
                require(
                    text(&o, "status")? == "evaluated"
                        && o["parent"] == current
                        && field(&o, "score")? == score
                        && score > 0,
                    "EVIDENCE",
                )?;
                leaves.push(allocation_leaf(cid, hash32(text(&o, "owner")?)?, score));
                total = add(total, score)?;
                o["status"] = json!("adopted");
                adopted.push((k, o));
            }
            require(
                allocation_root(leaves)? == supplied_root && total == supplied_total,
                "ROOT",
            )?;
            require(
                release
                    == hash(
                        b"release",
                        &[
                            &parent,
                            &bundle_id,
                            &budget.to_le_bytes(),
                            &supplied_root,
                            &total.to_le_bytes(),
                        ],
                    ),
                "ROOT",
            )?;
            let rk = format!("release:{}", hex::encode(release));
            require(s.get(&rk).is_none(), "DUPLICATE")?;
            let horizon = add(
                cfg.limit("reward_maturity_blocks")?,
                cfg.limit("release_claim_window_blocks")?,
            )?;
            let expiry = add(height, horizon)?;
            s.deadline_with_lifetime(cfg, expiry, height, horizon)?;
            s.debit(&sender, budget)?;
            s.put(rk,json!({"owner":sender,"remaining":budget,"budget":budget,"total":total,"root":hex::encode(supplied_root),"maturity":add(height,cfg.limit("reward_maturity_blocks")?)?,"bundle":hex::encode(bundle_id),"artifact":bundle["artifact"].clone(),"family":bundle["family"].clone(),"components_root":bundle["components_root"].clone(),"parent":hex::encode(parent),"leaf_count":count,"claims":{},"deadline":expiry,"status":"open"}));
            for (k, o) in adopted {
                s.put(k, o);
            }
            bundle["status"] = json!("adopted");
            s.put(bk, bundle);
            s.put("model:current".into(), json!(hex::encode(release)));
        }
        9 => {
            let (rk, mut rel) = s.object("release:", p.h()?)?;
            let cid = p.h()?;
            let score = p.n()?;
            let count = p.byte()?;
            let c = hex::encode(cid);
            require(
                height >= field(&rel, "maturity")?
                    && height < field(&rel, "deadline")?
                    && text(&rel, "status")? == "open",
                "STATE",
            )?;
            require(rel["claims"].get(&c).is_none(), "DUPLICATE")?;
            let leaves = field(&rel, "leaf_count")?;
            require(leaves > 0, "ROOT")?;
            require(count as u32 == 64 - (leaves - 1).leading_zeros(), "ROOT")?;
            let mut leaf = allocation_leaf(cid, tx.sender, score);
            for _ in 0..count {
                leaf = pair(leaf, p.h()?);
            }
            require(leaf == hash32(text(&rel, "root")?)?, "ROOT")?;
            let total = field(&rel, "total")?;
            require(total > 0, "ROOT")?;
            let amount =
                u64::try_from((field(&rel, "budget")? as u128) * (score as u128) / (total as u128))
                    .map_err(|_| "RANGE")?;
            require(amount <= field(&rel, "remaining")?, "FUNDS")?;
            s.credit(&sender, amount)?;
            rel["remaining"] = json!(field(&rel, "remaining")? - amount);
            rel["claims"][&c] = json!(amount);
            s.put(rk, rel);
        }
        10 => {
            let quota = p.h()?;
            let consumer = hex::encode(p.h()?);
            let provider = hex::encode(p.h()?);
            let units = p.n()?;
            let deadline = p.n()?;
            require(
                quota
                    == hash(
                        b"quota-instance-v3",
                        &[
                            &cfg.network,
                            &cfg.parameters,
                            &tx.sender,
                            &tx.nonce.to_le_bytes(),
                            &hash32(&consumer)?,
                            &hash32(&provider)?,
                            &units.to_le_bytes(),
                            &deadline.to_le_bytes(),
                        ],
                    ),
                "RESOURCE_ID",
            )?;
            let k = format!("quota:{}", hex::encode(quota));
            require(s.get(&k).is_none(), "DUPLICATE")?;
            s.deadline(cfg, deadline, height)?;
            require(units > 0 && units <= cfg.limit("max_quota_units")?, "LIMIT")?;
            let cost = units
                .checked_mul(cfg.limit("quota_unit_price")?)
                .ok_or("RANGE")?;
            s.debit(&sender, cost)?;
            s.put(k,json!({"owner":sender,"consumer":consumer,"provider":provider,"remaining":cost,"units":units,"deadline":deadline,"status":"reserved"}));
        }
        11 => {
            let quota = p.h()?;
            let (k, mut o) = s.object("quota:", quota)?;
            let units = p.n()?;
            let result = p.h()?;
            let signature = p.take::<64>()?;
            require(text(&o, "provider")? == sender, "AUTHORITY")?;
            require(
                text(&o, "status")? == "reserved" && height < field(&o, "deadline")?,
                "STATE",
            )?;
            require(
                units > 0 && units <= field(&o, "units")? && result != ZERO,
                "LIMIT",
            )?;
            let digest = hash(
                b"use",
                &[
                    &cfg.network,
                    &cfg.parameters,
                    &quota,
                    &tx.sender,
                    &tx.nonce.to_le_bytes(),
                    &units.to_le_bytes(),
                    &result,
                ],
            );
            verify_hex_strict(text(&o, "consumer")?, &digest, &hex::encode(signature))
                .map_err(|_| "SIGNATURE")?;
            let cost = units
                .checked_mul(cfg.limit("quota_unit_price")?)
                .ok_or("RANGE")?;
            require(cost >= fee && field(&o, "remaining")? >= cost, "FUNDS")?;
            o["remaining"] = json!(field(&o, "remaining")? - cost);
            o["units"] = json!(field(&o, "units")? - units);
            s.credit(&sender, cost - fee)?;
            if field(&o, "units")? == 0 {
                o["status"] = json!("spent");
            }
            s.put(k, o);
        }
        12 => {
            let task = p.h()?;
            let k = format!("work:{}", hex::encode(task));
            require(task != ZERO && s.get(&k).is_none(), "DUPLICATE")?;
            s.put(k, json!(true));
        }
        13 => {
            let signed =
                SignedQualifiedWorkTask::decode(&tx.payload).map_err(|_| "TASK_MANIFEST")?;
            let manifest = &signed.manifest;
            let context = cfg.qualified_task_context(manifest.demand_id, height)?;
            require(tx.sender == context.source, "TASK_SOURCE")?;
            let statement = verify_development_statement(&tx.payload, &context)
                .map_err(|_| "TASK_STATEMENT")?;
            let registry_key = format!("work-demand-registry:{}", hex::encode(manifest.demand_id));
            let registered = s.get(&registry_key).ok_or("TASK_DEMAND")?;
            require(
                field(&registered, "purpose")? == manifest.purpose as u64,
                "TASK_PURPOSE",
            )?;
            let withdrawal_key = format!("work-withdrawal:{}", hex::encode(context.source));
            require(
                s.get(&withdrawal_key) == Some(json!(hex::encode(context.withdrawal_head))),
                "TASK_WITHDRAWAL",
            )?;
            let sequence_key = format!("work-source:{}", hex::encode(context.source));
            let previous_sequence = s.get(&sequence_key).ok_or("TASK_SOURCE")?;
            require(
                manifest.demand_nonce == add(num(&previous_sequence)?, 1)?,
                "TASK_SOURCE_NONCE",
            )?;
            let demand_key = format!("work-demand:{}", hex::encode(manifest.demand_id));
            let work_key = format!("work:{}", hex::encode(manifest.matrix_task));
            require(
                s.get(&demand_key).is_none() && s.get(&work_key).is_none(),
                "TASK_REPLAY",
            )?;
            s.put(sequence_key, json!(manifest.demand_nonce));
            s.put(demand_key, json!(hex::encode(statement.manifest_id())));
            s.put(work_key, json!({"schema":"qualified-work-registration-v1","manifest":hex::encode(&tx.payload),"admitted_height":height,"manifest_id":hex::encode(statement.manifest_id())}));
            p.pos = p.bytes.len();
        }
        18..=21 => {
            qualified_task_lifecycle::apply_verified_command(&mut s, tx, height, cfg)?;
            p.pos = tx.payload.len();
        }
        14..=17 => {
            let cid = p.h()?;
            let active_key = format!("contribution:{}", hex::encode(cid));
            let archive_key = format!("evaluation-archive:{}", hex::encode(cid));
            let (key, mut contribution) = if let Some(value) = s.get(&active_key) {
                (active_key, value)
            } else {
                require(matches!(tx.tag, 16 | 17), "STATE")?;
                (archive_key.clone(), s.get(&archive_key).ok_or("STATE")?)
            };
            let records = s.scan(&public_evaluation::record_prefix(cid));
            contribution["public_evaluation"] =
                public_evaluation::hydrate(&contribution["public_evaluation"], cid, &records)?;
            let evaluation = &mut contribution["public_evaluation"];
            require(
                public_evaluation::enabled(cfg) && !evaluation.is_null(),
                "PUBLIC_EVAL_PROFILE",
            )?;
            match tx.tag {
                14 => public_evaluation::commit(evaluation, &sender, p.h()?, p.h()?, height)?,
                15 => {
                    let value = public_evaluation::Reveal {
                        candidate: cid,
                        round: p.h()?,
                        evaluator: tx.sender,
                        plan: p.h()?,
                        evidence: p.h()?,
                        score: p.n()?,
                        salt: p.h()?,
                    };
                    public_evaluation::reveal(evaluation, value, height)?;
                }
                16 => {
                    let first = p.blob()?;
                    let second = p.blob()?;
                    let disqualified =
                        public_evaluation::conflict(evaluation, cfg, cid, first, second)?;
                    s.put(format!("evaluation-disqualified:{disqualified}"),json!({"evidence_candidate":hex::encode(cid),"height":height,"scope":"exact development key; no hidden-controller independence claim"}));
                }
                17 => {
                    let author = contribution["owner"].as_str().ok_or("STATE")?.to_owned();
                    public_evaluation::appeal(
                        &mut contribution["public_evaluation"],
                        &author,
                        &sender,
                        p.h()?,
                        p.h()?,
                        p.h()?,
                        height,
                    )?;
                }
                _ => unreachable!(),
            }
            for (record_key, value) in
                public_evaluation::record_rows(cid, &contribution["public_evaluation"])?
            {
                if let Some(previous) = records.get(&record_key) {
                    require(previous == &value, "PUBLIC_EVAL_RECORD_MUTATION")?;
                } else {
                    s.put(record_key, value);
                }
            }
            contribution["public_evaluation"] =
                public_evaluation::compact(&contribution["public_evaluation"])?;
            if !contribution["public_evaluation"]["closed"].is_null() {
                s.put(archive_key, contribution.clone());
            }
            s.put(key, contribution);
        }
        _ => return Err("VERSION"),
    }
    require(p.pos == p.bytes.len(), "LENGTH")?;
    let mut a = s.account(&sender);
    a["nonce"] = json!(tx.nonce);
    s.put(format!("account:{sender}"), a);
    let receipt = canonical(
        &json!({"tx":hex::encode(tx.id().map_err(|_|"ENCODING")?),"fee":fee,"status":"applied"}),
    )?;
    Ok(Patch {
        writes: s.writes,
        reads: s.reads,
        scans: s.scans,
        fee,
        receipt,
    })
}

fn funds(state: &State) -> Result<u64> {
    let mut total = 0_u64;
    for (k, v) in state {
        let amount = if k.starts_with("account:") {
            field(v, "balance")?
        } else if k.starts_with("task:") || k.starts_with("quota:") || k.starts_with("release:") {
            field(v, "remaining")?
        } else if k.starts_with("reward:") {
            field(v, "amount")?
        } else {
            0
        };
        total = add(total, amount)?;
    }
    Ok(total)
}
fn credit_state(state: &mut State, who: &str, amount: u64) -> Result<()> {
    let key = format!("account:{who}");
    let mut account = state
        .get(&key)
        .cloned()
        .unwrap_or_else(|| json!({"balance":0,"nonce":0}));
    account["balance"] = json!(add(field(&account, "balance")?, amount)?);
    state.insert(key, account);
    Ok(())
}
fn mandatory(state: &mut State, height: u64, cfg: &Config) -> Result<Vec<Vec<u8>>> {
    let current = state
        .get("model:current")
        .and_then(Value::as_str)
        .ok_or("STATE")?
        .to_owned();
    let keys: Vec<_> = state.keys().cloned().collect();
    if public_evaluation::enabled(cfg) {
        let candidates: Vec<_> = keys
            .iter()
            .filter(|key| key.starts_with("contribution:"))
            .cloned()
            .collect();
        for key in candidates {
            let cid = hash32(key.strip_prefix("contribution:").ok_or("STATE")?)?;
            let mut evaluation = public_evaluation::read_evaluation(state, cid)?;
            let closed = public_evaluation::close(&mut evaluation, height)?;
            let value = state.get_mut(&key).ok_or("STATE")?;
            value["public_evaluation"] = public_evaluation::compact(&evaluation)?;
            if let Some(score) = closed {
                value["score"] = json!(score);
                value["status"] = json!("evaluated");
            } else if value["public_evaluation"]["closed"]["status"] == "aborted" {
                value["score"] = json!(0);
                value["status"] = json!("evaluation-aborted");
            }
            if !value["public_evaluation"]["closed"].is_null() {
                let archive = value.clone();
                state.insert(
                    format!(
                        "evaluation-archive:{}",
                        key.strip_prefix("contribution:").ok_or("STATE")?
                    ),
                    archive,
                );
            }
        }
    }
    for k in keys {
        if k.starts_with("contribution:") {
            let v = state.get_mut(&k).ok_or("STATE")?;
            if text(v, "parent")? != current
                || v.get("submission_round").map(num).transpose()?.unwrap_or(0)
                    != height / cfg.limit("candidate_round_blocks")?
            {
                state.remove(&k);
            } else {
                let submitted = v
                    .get("submitted_height")
                    .map(num)
                    .transpose()?
                    .unwrap_or(height);
                if height > add(submitted, cfg.limit("candidate_lifetime_blocks")?)?
                    && matches!(text(v, "status")?, "submitted" | "evaluated")
                {
                    v["status"] = json!("expired");
                    v["votes"] = json!({});
                    v["score"] = json!(0);
                }
            }
        } else if k.starts_with("evaluation-archive:") {
            let value = state.get(&k).ok_or("STATE")?;
            let closed = field(&value["public_evaluation"]["closed"], "closed_height")?;
            if height.saturating_sub(closed) > 256 {
                state.remove(&k);
            }
        } else if k.starts_with("task:") || k.starts_with("quota:") {
            let value = state.get(&k).ok_or("STATE")?;
            if field(value, "remaining")? == 0 && field(value, "deadline")? < height {
                state.remove(&k);
            }
        } else if k.starts_with("artifact:") {
            let parts: Vec<_> = k.split(':').collect();
            let round = (height / cfg.limit("candidate_round_blocks")?).to_string();
            if parts.len() != 4 || parts[1] != current || parts[2] != round {
                state.remove(&k);
            }
        }
    }
    if public_evaluation::enabled(cfg) {
        // Remove records only after both active candidate and retained archive vanish.
        // Branch state cleanup never touches physical/local operation journals.
        let orphaned: Vec<_> = state
            .keys()
            .filter(|key| key.starts_with(&format!("{}:", public_evaluation::RECORD_NAMESPACE)))
            .filter(|key| {
                key.strip_prefix(&format!("{}:", public_evaluation::RECORD_NAMESPACE))
                    .and_then(|suffix| suffix.split_once(':'))
                    .is_some_and(|(candidate, _)| {
                        !state.contains_key(&format!("contribution:{candidate}"))
                            && !state.contains_key(&format!("evaluation-archive:{candidate}"))
                    })
            })
            .cloned()
            .collect();
        for key in orphaned {
            state.remove(&key);
        }
    }
    let retired: Vec<_> = state
        .iter()
        .filter_map(|(k, v)| {
            if k.starts_with("release:") && &k[8..] != current.as_str() && v["remaining"] == 0 {
                Some(k.clone())
            } else {
                None
            }
        })
        .collect();
    for k in retired {
        state.remove(&k);
    }
    let mut due = Vec::new();
    for (k, v) in state.iter() {
        if (k.starts_with("task:") || k.starts_with("quota:") || k.starts_with("release:"))
            && field(v, "remaining")? > 0
            && field(v, "deadline")? <= height
        {
            due.push((field(v, "deadline")?, k.clone()));
        }
    }
    due.sort();
    let mut receipts = Vec::new();
    for (_, k) in due
        .into_iter()
        .take(cfg.limit("mandatory_expiry_per_block")? as usize)
    {
        let mut v = state.get(&k).cloned().ok_or("STATE")?;
        credit_state(state, text(&v, "owner")?, field(&v, "remaining")?)?;
        v["remaining"] = json!(0);
        v["status"] = json!("expired");
        state.insert(k.clone(), v);
        receipts.push(canonical(&json!({"expiry":k}))?);
    }
    let mature = state
        .iter()
        .filter(|(k, _)| k.starts_with("reward:"))
        .map(|(k, v)| Ok((k.clone(), field(v, "maturity")?)))
        .collect::<Result<Vec<_>>>()?;
    for (k, maturity) in mature {
        if maturity <= height {
            let reward = state.remove(&k).ok_or("STATE")?;
            credit_state(state, text(&reward, "owner")?, field(&reward, "amount")?)?;
        }
    }
    Ok(receipts)
}

/// Execute context-selected signed commands in exact ledger order. Failed blocks never
/// mutate `parent`. Only observed dependencies cause one canonical re-execution.
pub fn execute(
    parent: &State,
    transactions: &[Vec<u8>],
    height: u64,
    miner: Hash,
    parent_id: Hash,
    workers: usize,
    cfg: &Config,
) -> Result<Output> {
    execute_with_commitment(
        parent,
        BlockExecution {
            transactions,
            height,
            miner,
            parent_id,
            workers,
        },
        cfg,
        |_, next| root(next),
    )
}
struct BlockExecution<'a> {
    transactions: &'a [Vec<u8>],
    height: u64,
    miner: Hash,
    parent_id: Hash,
    workers: usize,
}
fn execute_with_commitment(
    parent: &State,
    block: BlockExecution<'_>,
    cfg: &Config,
    mut commitment: impl FnMut(&State, &State) -> Result<Hash>,
) -> Result<Output> {
    let BlockExecution {
        transactions,
        height,
        miner,
        parent_id,
        workers,
    } = block;
    require([1, 2, 4, 8].contains(&workers), "WORKERS")?;
    require(
        transactions.len() as u64 <= cfg.limit("max_transactions")?,
        "LIMIT",
    )?;
    let mut state = parent.clone();
    let mut receipts = mandatory(&mut state, height, cfg)?;
    let mut fees = 0;
    let mut metrics = Metrics {
        workers,
        ..Metrics::default()
    };
    let transition_start = std::time::Instant::now();
    let signatures = AtomicUsize::new(0);
    // Same sender means every transaction writes the same nonce. Preserve a serial
    // state path, while independent cryptographic checks may still use the bounded pool.
    let serial_state = workers == 1
        || (transactions.len() > 1
            && transactions[0].len() >= 68
            && transactions
                .iter()
                .all(|raw| raw.get(36..68) == transactions[0].get(36..68)));
    struct Predicted {
        prepared: Result<Prepared>,
        patch: Option<Result<Patch>>,
    }
    let predict = |raw: &[u8]| {
        let prepared = prepare(raw, height, cfg, &signatures);
        let range_command = prepared
            .as_ref()
            .is_ok_and(|p| matches!(p.envelope.tag, 2 | 6 | 8 | 10));
        // Prefix-capacity operations remain canonical: do not retain one full
        // prefix snapshot per transaction merely to parallelize shared budgets.
        let patch = if serial_state || range_command {
            None
        } else {
            Some(
                prepared
                    .as_ref()
                    .map_err(|e| *e)
                    .and_then(|tx| apply_prepared(&state, tx, height, cfg)),
            )
        };
        Predicted { prepared, patch }
    };
    let count = workers.min(transactions.len());
    let predicted = if count <= 1 {
        transactions
            .iter()
            .map(|raw| predict(raw))
            .collect::<Vec<_>>()
    } else {
        // One bounded group of scoped workers PER BLOCK, not per short batch.
        // No clone of the full state per worker; everyone reads the same snapshot.
        metrics.workers_spawned = count;
        std::thread::scope(|scope| -> Result<Vec<Predicted>> {
            let mut handles = Vec::with_capacity(count);
            for worker in 0..count {
                let work = &predict;
                let handle = std::thread::Builder::new()
                    .name(format!("pon-exec-{worker}"))
                    .spawn_scoped(scope, move || {
                        (worker..transactions.len())
                            .step_by(count)
                            .map(|index| (index, work(&transactions[index])))
                            .collect::<Vec<_>>()
                    });
                match handle {
                    Ok(h) => handles.push(h),
                    Err(_) => {
                        // Join already started workers on partial-spawn failure too.
                        for h in handles {
                            let _ = h.join();
                        }
                        return Err("WORKER_START");
                    }
                }
            }
            let mut rows = Vec::with_capacity(transactions.len());
            let mut panicked = false;
            for handle in handles {
                match handle.join() {
                    Ok(mut values) => rows.append(&mut values),
                    Err(_) => panicked = true,
                }
            }
            require(!panicked, "WORKER_PANIC")?;
            rows.sort_by_key(|(index, _)| *index);
            require(rows.len() == transactions.len(), "WORKER_RESULT")?;
            Ok(rows.into_iter().map(|(_, result)| result).collect())
        })?
    };
    metrics.signature_verifications = signatures.load(Ordering::Relaxed);
    metrics.peak_inflight = if serial_state {
        usize::from(!transactions.is_empty())
    } else {
        count
    };
    if serial_state && workers > 1 && !transactions.is_empty() {
        metrics.serial_conflict_batches = 1;
    }
    for result in predicted {
        // Consume failures at their canonical transaction position. A bad later
        // signature never bypasses an earlier state error or mutates the parent.
        let prepared = result.prepared?;
        let patch = if serial_state || result.patch.is_none() {
            metrics.committed_without_replay += 1;
            apply_prepared(&state, &prepared, height, cfg)?
        } else {
            metrics.speculative += 1;
            match result.patch.ok_or("WORKER_RESULT")? {
                Ok(patch) if patch.current(&state) => {
                    metrics.committed_without_replay += 1;
                    patch
                }
                _ => {
                    metrics.reexecuted += 1;
                    // Exactly one canonical state replay, no duplicate main-signature work.
                    apply_prepared(&state, &prepared, height, cfg)?
                }
            }
        };
        fees = add(fees, patch.fee)?;
        receipts.push(patch.receipt.clone());
        patch.apply(&mut state);
    }
    metrics.state_transition_ns = transition_start.elapsed().as_nanos();
    let halvings = (height / cfg.limit("subsidy_halving_interval")?).min(64);
    let subsidy = cfg
        .limit("block_subsidy_units")?
        .checked_shr(halvings as u32)
        .unwrap_or(0);
    let reward = hash(b"reward", &[&parent_id, &height.to_le_bytes(), &miner]);
    state.insert(format!("reward:{}",hex::encode(reward)),json!({"owner":hex::encode(miner),"amount":add(fees,subsidy)?,"maturity":add(height,cfg.limit("reward_maturity_blocks")?)?}));
    let issued = add(num(state.get("meta:issued").ok_or("STATE")?)?, subsidy)?;
    state.insert("meta:issued".into(), json!(issued));
    require(funds(&state)? == issued, "CONSERVATION")?;
    let root_start = std::time::Instant::now();
    let root = commitment(parent, &state)?;
    metrics.state_root_ns = root_start.elapsed().as_nanos();
    Ok(Output {
        state,
        receipts,
        root,
        metrics,
    })
}

/// Compute cache only. The caller remains the sole authoritative ledger owner.
/// A request must name the exact predecessor root and monotonically increasing sequence.
/// Every failed transaction, commitment check or sequence mismatch preserves this session.
pub struct ExecutionSession {
    state: State,
    tree: trnm_protocol::pon_state::StateTree,
    config: Config,
    sequence: u64,
}
#[derive(Debug)]
pub struct SessionOutput {
    pub predecessor: Hash,
    pub root: Hash,
    pub sequence: u64,
    pub changes: Vec<(String, Option<Value>, Option<Value>)>,
    pub receipts: Vec<Vec<u8>>,
    pub metrics: Metrics,
    pub commitment_nodes: usize,
}
impl ExecutionSession {
    pub fn new(state: State, expected_root: Hash, config: Config) -> Result<Self> {
        let mut bytes = BTreeMap::new();
        for (key, value) in &state {
            bytes.insert(key.as_bytes().to_vec(), canonical(value)?);
        }
        let tree =
            trnm_protocol::pon_state::StateTree::from_values(&bytes).map_err(|_| "STATE_TREE")?;
        require(tree.root() == expected_root, "SESSION_ROOT")?;
        Ok(Self {
            state,
            tree,
            config,
            sequence: 0,
        })
    }
    pub fn root(&self) -> Hash {
        self.tree.root()
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn execute(
        &mut self,
        predecessor: (u64, Hash),
        transactions: &[Vec<u8>],
        height: u64,
        miner: Hash,
        parent_id: Hash,
        workers: usize,
    ) -> Result<SessionOutput> {
        require(
            predecessor == (self.sequence, self.tree.root()),
            "SESSION_PREDECESSOR",
        )?;
        let sequence = self.sequence.checked_add(1).ok_or("SESSION_SEQUENCE")?;
        let mut staged = None;
        let mut changes = Vec::new();
        let output = execute_with_commitment(
            &self.state,
            BlockExecution {
                transactions,
                height,
                miner,
                parent_id,
                workers,
            },
            &self.config,
            |before, after| {
                use trnm_protocol::pon_state::Change;
                let keys: BTreeSet<_> = before.keys().chain(after.keys()).collect();
                let mut updates = Vec::new();
                for key in keys {
                    let old = before.get(key);
                    let new = after.get(key);
                    if old != new {
                        updates.push(Change {
                            key: key.as_bytes().to_vec(),
                            before: old.map(canonical).transpose()?,
                            after: new.map(canonical).transpose()?,
                        });
                        changes.push((key.clone(), old.cloned(), new.cloned()));
                    }
                }
                let next = self
                    .tree
                    .apply(predecessor.1, &updates)
                    .map_err(|_| "STATE_TREE")?;
                let root = next.root();
                staged = Some(next);
                Ok(root)
            },
        )?;
        let tree = staged.ok_or("STATE_TREE")?;
        let result = SessionOutput {
            predecessor: predecessor.1,
            root: output.root,
            sequence,
            changes,
            receipts: output.receipts,
            metrics: output.metrics,
            commitment_nodes: tree.allocated_nodes(),
        };
        self.state = output.state;
        self.tree = tree;
        self.sequence = sequence;
        Ok(result)
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;

    fn initial() -> State {
        BTreeMap::from([
            ("meta:issued".into(), json!(0)),
            ("model:current".into(), json!(hex::encode([0; 32]))),
        ])
    }

    #[test]
    fn session_state_and_receipts_equal_existing_complete_builder() {
        let state = initial();
        let cfg = Config::installed().unwrap();
        let old_root = root(&state).unwrap();
        let mut session = ExecutionSession::new(state.clone(), old_root, cfg.clone()).unwrap();
        for height in 1..=8 {
            let expected = execute(
                session.state(),
                &[],
                height,
                [1; 32],
                [height as u8; 32],
                4,
                &cfg,
            )
            .unwrap();
            let observed = session
                .execute(
                    (session.sequence(), session.root()),
                    &[],
                    height,
                    [1; 32],
                    [height as u8; 32],
                    4,
                )
                .unwrap();
            assert_eq!(observed.root, expected.root);
            assert_eq!(observed.receipts, expected.receipts);
            assert_eq!(session.state(), &expected.state);
            assert_eq!(session.sequence(), height);
        }
        assert_eq!(root(&state).unwrap(), old_root);
    }

    #[test]
    fn invalid_context_transaction_and_sequence_never_publish_session_state() {
        let state = initial();
        let old_root = root(&state).unwrap();
        let mut session =
            ExecutionSession::new(state.clone(), old_root, Config::installed().unwrap()).unwrap();
        assert_eq!(
            session
                .execute((99, old_root), &[], 1, [1; 32], [2; 32], 1)
                .unwrap_err(),
            "SESSION_PREDECESSOR"
        );
        assert_eq!(
            session
                .execute((0, [9; 32]), &[], 1, [1; 32], [2; 32], 1)
                .unwrap_err(),
            "SESSION_PREDECESSOR"
        );
        assert!(session
            .execute((0, old_root), &[vec![0; 159]], 1, [1; 32], [2; 32], 8)
            .is_err());
        assert_eq!(session.sequence(), 0);
        assert_eq!(session.root(), old_root);
        assert_eq!(session.state(), &state);
        session.sequence = u64::MAX;
        assert_eq!(
            session
                .execute((u64::MAX, old_root), &[], 1, [1; 32], [2; 32], 1)
                .unwrap_err(),
            "SESSION_SEQUENCE"
        );
        assert_eq!(session.state(), &state);
    }
}
