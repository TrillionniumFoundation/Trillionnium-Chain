//! Native revision-2 application transitions. No work/fork/Hepta authority is implied.
//! Parallel workers speculate against one immutable snapshot; exact key and prefix
//! reads are validated in canonical order. Conflict or speculative rejection is
//! re-executed ONCE against that order's current state, never an unbounded retry loop.
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use trnm_crypto_primitives::verify_hex_strict;
use trnm_protocol::pon_wire::{hash, state_root, Envelope, Hash};

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
    pub fees: [u64; 13],
    pub params: Value,
}
impl Config {
    /// Installed experimental genesis context, not caller-supplied authority booleans.
    pub fn installed() -> Result<Self> {
        let params: Value =
            serde_json::from_str(include_str!("../../../../config/pon/devnet-v1.json"))
                .map_err(|_| "CONFIG")?;
        require(
            params["consensus_revision"] == 2 && params["production_activation"] == false,
            "CONFIG",
        )?;
        let model: Value =
            serde_json::from_str(include_str!("../../../../config/pon/model-family-v1.json"))
                .map_err(|_| "CONFIG")?;
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
        let plan = hash(b"plan", &[b"public-source-file-disjoint-v1"]);
        let mut fees = [0; 13];
        let mut tags = BTreeSet::new();
        for c in wire["commands"].as_array().ok_or("CONFIG")? {
            let tag = field(c, "tag")? as usize;
            require((1..=12).contains(&tag) && tags.insert(tag), "CONFIG")?;
            fees[tag] = field(c, "base_fee_units")?;
        }
        require(tags.len() == 12, "CONFIG")?;
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
        })
    }
    fn limit(&self, name: &str) -> Result<u64> {
        field(&self.params, name)
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
        && (status == "submitted" || status == "evaluated")
        && (status != "evaluated" || field(v, "score")? > 0)
        && height <= add(submitted, cfg.limit("candidate_lifetime_blocks")?)?)
}

fn apply_one(base: &State, raw: &[u8], height: u64, cfg: &Config) -> Result<Patch> {
    let tx = Envelope::decode(raw).map_err(|_| "ENCODING")?;
    require(tx.network == cfg.network, "NETWORK")?;
    require(height <= tx.expiry, "EXPIRED")?;
    let sender = hex::encode(tx.sender);
    verify_hex_strict(
        &sender,
        &tx.signing_digest().map_err(|_| "ENCODING")?,
        &hex::encode(tx.signature),
    )
    .map_err(|_| "SIGNATURE")?;
    let mut s = View::new(base);
    let acct = s.account(&sender);
    require(tx.nonce == add(field(&acct, "nonce")?, 1)?, "NONCE")?;
    let fee = add(
        cfg.fees[tx.tag as usize],
        (raw.len() as u64)
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
            require(
                cid == hash(
                    b"contribution",
                    &[&tx.sender, &family, &parent, &artifact, &components],
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
            let mut count = 0;
            for v in s.scan("contribution:").values() {
                if active_candidate(v, &current, height, cfg)? {
                    count += 1;
                }
            }
            require(count < cfg.limit("max_model_candidates")?, "LIMIT")?;
            let k = format!("contribution:{}", hex::encode(cid));
            let duplicate = format!("artifact:{}:{}", hex::encode(parent), hex::encode(artifact));
            require(
                s.get(&k).is_none() && s.get(&duplicate).is_none(),
                "DUPLICATE",
            )?;
            s.put(k,json!({"owner":sender,"artifact":hex::encode(artifact),"components_root":hex::encode(components),"family":hex::encode(family),"parent":hex::encode(parent),"votes":{},"score":0,"status":"submitted","submitted_height":height}));
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
            if votes.len() as u64 >= cfg.limit("evaluation_threshold")? {
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
            s.put(rk,json!({"owner":sender,"remaining":budget,"budget":budget,"total":total,"root":hex::encode(supplied_root),"maturity":add(height,cfg.limit("reward_maturity_blocks")?)?,"bundle":hex::encode(bundle_id),"leaf_count":count,"claims":{},"deadline":expiry,"status":"open"}));
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
    for k in keys {
        if k.starts_with("contribution:") {
            let v = state.get_mut(&k).ok_or("STATE")?;
            if text(v, "parent")? != current {
                state.remove(&k);
            } else {
                let submitted = v
                    .get("submitted_height")
                    .map(num)
                    .transpose()?
                    .unwrap_or(height);
                if height > add(submitted, cfg.limit("candidate_lifetime_blocks")?)?
                    && text(v, "status")? == "submitted"
                {
                    v["status"] = json!("expired");
                    v["votes"] = json!({});
                }
            }
        } else if k.starts_with("artifact:") && k.split(':').nth(1) != Some(current.as_str()) {
            state.remove(&k);
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

/// Execute all twelve signed commands in exact ledger order. Failed blocks never
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
    for batch in transactions.chunks(workers) {
        // Sender is a mandatory nonce write in every command. Identical fixed
        // sender bytes can only choose a cheaper schedule, never skip validation.
        let same_sender = batch.len() > 1
            && batch[0].len() >= 68
            && batch
                .iter()
                .all(|raw| raw.get(36..68) == batch[0].get(36..68));
        if workers == 1 || same_sender {
            metrics.peak_inflight = metrics.peak_inflight.max(1);
            if same_sender {
                metrics.serial_conflict_batches += 1;
            }
            for raw in batch {
                let patch = apply_one(&state, raw, height, cfg)?;
                fees = add(fees, patch.fee)?;
                receipts.push(patch.receipt.clone());
                patch.apply(&mut state);
                metrics.committed_without_replay += 1;
            }
            continue;
        }
        metrics.peak_inflight = metrics.peak_inflight.max(batch.len());
        let predicted = std::thread::scope(|scope| {
            let base = &state;
            let handles: Vec<_> = batch
                .iter()
                .map(|raw| scope.spawn(move || apply_one(base, raw, height, cfg)))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or(Err("WORKER_PANIC")))
                .collect::<Vec<_>>()
        });
        metrics.speculative += batch.len();
        for (raw, result) in batch.iter().zip(predicted) {
            let patch = match result {
                Ok(p) if p.current(&state) => {
                    metrics.committed_without_replay += 1;
                    p
                }
                _ => {
                    metrics.reexecuted += 1;
                    apply_one(&state, raw, height, cfg)?
                }
            };
            fees = add(fees, patch.fee)?;
            receipts.push(patch.receipt.clone());
            patch.apply(&mut state);
        }
    }
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
    let root = root(&state)?;
    Ok(Output {
        state,
        receipts,
        root,
        metrics,
    })
}
