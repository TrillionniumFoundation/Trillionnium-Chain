//! Explicit native factor admission for a fresh, bounded integer model family.
//! All models and duplicate records are ordinary reorg-reversible M06 State.
use crate::pon_executor::{canonical, Config, Result, State};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use trnm_protocol::integer_factor_v2::{FactorWitnessV2, COLUMNS, ROWS};
use trnm_protocol::pon_wire::{hash, Hash};
use trnm_verification_profiles::exact_integer_linear_v1::{
    verify_integer_linear_v1, IntegerLinearContextV1, INTEGER_LINEAR_FAMILY_V1,
};

pub const PROFILE: &str = "linear-factor-witness-dev-v2";
pub const MODEL_BYTES: usize = 46 + 2 * (ROWS * COLUMNS * 5);
pub const CHUNK_BYTES: usize = 1024;
pub const MAX_MODEL_BYTES: usize = 65536;
pub const NUMERIC: &[u8] = b"exact-i16-BA-add-delta-scale1024-v2";
fn ensure(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error)
    }
}
fn h(value: &str) -> Result<Hash> {
    ensure(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "FACTOR_HASH",
    )?;
    let mut out = [0; 32];
    hex::decode_to_slice(value, &mut out).map_err(|_| "FACTOR_HASH")?;
    Ok(out)
}
pub fn enabled(cfg: &Config) -> bool {
    cfg.params["model_profile"] == PROFILE || crate::model_evidence_v3::enabled(cfg)
}

/// Complete canonical model: header, base, router, three delta slots. No hash-only parent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegerModelV2 {
    family: Hash,
    coefficients: Vec<i16>,
}
impl IntegerModelV2 {
    pub fn from_coefficients(family: Hash, coefficients: Vec<i16>) -> Result<Self> {
        ensure(
            coefficients.len() == ROWS * COLUMNS * 5,
            "FACTOR_MODEL_LENGTH",
        )?;
        ensure(!coefficients.contains(&i16::MIN), "FACTOR_MODEL_RANGE")?;
        Ok(Self {
            family,
            coefficients,
        })
    }
    pub fn genesis(family: Hash) -> Self {
        Self {
            family,
            coefficients: vec![0; ROWS * COLUMNS * 5],
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MODEL_BYTES);
        out.extend(b"ILM2");
        out.extend(2_u16.to_le_bytes());
        out.extend(self.family);
        for n in [1024_u16, 3, 257, 3] {
            out.extend(n.to_le_bytes());
        }
        for c in &self.coefficients {
            out.extend(c.to_le_bytes());
        }
        out
    }
    pub fn decode(raw: &[u8], family: Hash) -> Result<Self> {
        ensure(
            raw.len() == MODEL_BYTES && raw.len() <= MAX_MODEL_BYTES,
            "FACTOR_MODEL_LENGTH",
        )?;
        ensure(
            raw[..4] == *b"ILM2" && raw[4..6] == 2_u16.to_le_bytes(),
            "FACTOR_MODEL_VERSION",
        )?;
        ensure(
            raw[6..38] == family && raw[38..46] == [0, 4, 3, 0, 1, 1, 3, 0],
            "FACTOR_MODEL_CONTEXT",
        )?;
        let coefficients: Vec<_> = raw[46..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| chunk.as_slice())
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        ensure(!coefficients.contains(&i16::MIN), "FACTOR_MODEL_RANGE")?;
        let model = Self {
            family,
            coefficients,
        };
        ensure(model.encode() == raw, "FACTOR_MODEL_CANONICAL")?;
        Ok(model)
    }
    pub fn id(&self) -> Hash {
        hash(b"integer-linear-model-artifact-v2", &[&self.encode()])
    }
    pub fn coefficients(&self) -> &[i16] {
        &self.coefficients
    }
}

pub trait FactorState {
    fn get(&mut self, key: &str) -> Option<Value>;
    fn put(&mut self, key: String, value: Value);
    fn scan(&mut self, prefix: &str) -> State;
}
struct ReadState<'a>(&'a State);
impl FactorState for ReadState<'_> {
    fn get(&mut self, key: &str) -> Option<Value> {
        self.0.get(key).cloned()
    }
    fn put(&mut self, _: String, _: Value) {
        unreachable!("read-only builder")
    }
    fn scan(&mut self, prefix: &str) -> State {
        self.0
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}
fn prefix(id: Hash) -> String {
    format!("linear-model-v2:{}:", hex::encode(id))
}
fn store_model(s: &mut impl FactorState, model: &IntegerModelV2) -> Result<()> {
    let id = model.id();
    let raw = model.encode();
    let p = prefix(id);
    let old = s.scan(&p);
    if !old.is_empty() {
        ensure(
            load_model(s, id, model.family)?.encode() == raw,
            "FACTOR_MODEL_COLLISION",
        )?;
        return Ok(());
    }
    let chunks = raw.len().div_ceil(CHUNK_BYTES);
    ensure(
        chunks <= 64 && raw.len() <= MAX_MODEL_BYTES,
        "FACTOR_MODEL_LIMIT",
    )?;
    s.put(format!("{p}meta"),json!({"schema":"integer-model-chunks-v2","bytes":raw.len(),"chunks":chunks,"family":hex::encode(model.family)}));
    for (i, c) in raw.chunks(CHUNK_BYTES).enumerate() {
        s.put(format!("{p}{i:02}"), json!(hex::encode(c)));
    }
    Ok(())
}
pub(crate) fn load_model(
    s: &mut impl FactorState,
    id: Hash,
    family: Hash,
) -> Result<IntegerModelV2> {
    let p = prefix(id);
    let entries = s.scan(&p);
    let meta = entries
        .get(&format!("{p}meta"))
        .ok_or("FACTOR_MODEL_MISSING")?;
    let size = meta["bytes"].as_u64().ok_or("FACTOR_MODEL_METADATA")? as usize;
    let chunks = meta["chunks"].as_u64().ok_or("FACTOR_MODEL_METADATA")? as usize;
    ensure(
        size == MODEL_BYTES
            && size <= MAX_MODEL_BYTES
            && chunks == size.div_ceil(CHUNK_BYTES)
            && chunks <= 64
            && entries.len() == chunks + 1,
        "FACTOR_MODEL_METADATA",
    )?;
    ensure(
        meta == &json!({"schema":"integer-model-chunks-v2","bytes":size,"chunks":chunks,"family":hex::encode(family)}),
        "FACTOR_MODEL_METADATA",
    )?;
    let mut raw = Vec::with_capacity(size);
    for i in 0..chunks {
        let c = entries
            .get(&format!("{p}{i:02}"))
            .and_then(Value::as_str)
            .ok_or("FACTOR_MODEL_CHUNK")?;
        let expected = CHUNK_BYTES.min(size - i * CHUNK_BYTES);
        ensure(
            c.len() == 2 * expected
                && c.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "FACTOR_MODEL_CHUNK",
        )?;
        raw.extend(hex::decode(c).map_err(|_| "FACTOR_MODEL_CHUNK")?);
    }
    let model = IntegerModelV2::decode(&raw, family)?;
    ensure(model.id() == id, "FACTOR_MODEL_HASH")?;
    Ok(model)
}
pub(crate) fn parent(s: &mut impl FactorState, cfg: &Config) -> Result<(Hash, IntegerModelV2)> {
    let current = s
        .get("model:current")
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or("FACTOR_PARENT")?;
    let reference = h(&current)?;
    let id = if current
        == cfg.params["factor_genesis_artifact"]
            .as_str()
            .ok_or("CONFIG")?
    {
        reference
    } else {
        let release = s
            .get(&format!("release:{current}"))
            .ok_or("FACTOR_PARENT_RELEASE")?;
        ensure(
            release["family"] == hex::encode(cfg.family),
            "FACTOR_PARENT_FAMILY",
        )?;
        h(release["artifact"]
            .as_str()
            .ok_or("FACTOR_PARENT_RELEASE")?)?
    };
    Ok((reference, load_model(s, id, cfg.family)?))
}
pub fn bootstrap_state(cfg: &Config) -> Result<State> {
    ensure(enabled(cfg), "FACTOR_PROFILE")?;
    let model = IntegerModelV2::genesis(cfg.family);
    ensure(
        cfg.params["factor_genesis_artifact"] == hex::encode(model.id()),
        "FACTOR_GENESIS",
    )?;
    struct Writer(State);
    impl FactorState for Writer {
        fn get(&mut self, k: &str) -> Option<Value> {
            self.0.get(k).cloned()
        }
        fn put(&mut self, k: String, v: Value) {
            self.0.insert(k, v);
        }
        fn scan(&mut self, p: &str) -> State {
            self.0
                .iter()
                .filter(|(k, _)| k.starts_with(p))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        }
    }
    let mut state = Writer(State::new());
    store_model(&mut state, &model)?;
    if crate::model_evidence_v3::enabled(cfg) {
        for control in crate::model_evidence_v3::controls(cfg)? {
            store_model(&mut state, &control)?;
        }
    }
    state.put("model:current".into(), json!(hex::encode(model.id())));
    Ok(state.0)
}

struct Derived {
    model: IntegerModelV2,
    normal: Vec<i16>,
    update: Hash,
    parent_ref: Hash,
    parent_artifact: Hash,
}
fn derive(s: &mut impl FactorState, cfg: &Config, w: &FactorWitnessV2) -> Result<Derived> {
    ensure(enabled(cfg) && w.family == cfg.family, "FACTOR_FAMILY")?;
    w.encode().map_err(|_| "FACTOR_ENCODING")?;
    let (reference, mut model) = parent(s, cfg)?;
    let parent_artifact = model.id();
    ensure(
        w.parent_ref == reference && w.parent_artifact == parent_artifact,
        "FACTOR_PARENT",
    )?;
    // Frozen v1 authenticates only its old arithmetic substrate. New family, loaded
    // model and outer context are independently checked here, never by that kernel.
    let ctx = IntegerLinearContextV1::new(INTEGER_LINEAR_FAMILY_V1, parent_artifact, w.slot)
        .map_err(|_| "FACTOR_CONTEXT")?;
    let rank = usize::from(w.rank);
    let b: Vec<Vec<i16>> = w.factors[..ROWS * rank]
        .chunks_exact(rank)
        .map(<[i16]>::to_vec)
        .collect();
    let a: Vec<Vec<i16>> = w.factors[ROWS * rank..]
        .as_chunks::<COLUMNS>()
        .0
        .iter()
        .map(|chunk| chunk.as_slice())
        .map(<[i16]>::to_vec)
        .collect();
    let raw = canonical(
        &json!({"A":a,"B":b,"contract":hex::encode(ctx.contract_id()),"schema":"pon-integer-linear-adapter-v1"}),
    )?;
    let checked = verify_integer_linear_v1(&ctx, &raw, ROWS * COLUMNS * 2)
        .map_err(|_| "FACTOR_ARITHMETIC")?;
    let normal: Vec<i16> = checked
        .delta()
        .iter()
        .flatten()
        .map(|&n| i16::try_from(n).map_err(|_| "FACTOR_RANGE"))
        .collect::<Result<_>>()?;
    ensure(normal.iter().any(|&n| n != 0), "FACTOR_NOOP")?;
    let offset = (2 + usize::from(w.slot)) * ROWS * COLUMNS;
    for (c, d) in model.coefficients[offset..offset + ROWS * COLUMNS]
        .iter_mut()
        .zip(&normal)
    {
        let next = i32::from(*c)
            .checked_add(i32::from(*d))
            .ok_or("FACTOR_RANGE")?;
        ensure((-32767..=32767).contains(&next), "FACTOR_MODEL_RANGE")?;
        *c = next as i16;
    }
    ensure(model.id() != parent_artifact, "FACTOR_NOOP")?;
    let full: Vec<u8> = normal.iter().flat_map(|v| v.to_le_bytes()).collect();
    let update = hash(
        b"integer-linear-function-update-v2",
        &[
            &cfg.network,
            &cfg.parameters,
            &cfg.family,
            &reference,
            &parent_artifact,
            &w.round.to_le_bytes(),
            &[w.slot],
            &1024_u16.to_le_bytes(),
            NUMERIC,
            &full,
        ],
    );
    Ok(Derived {
        model,
        normal,
        update,
        parent_ref: reference,
        parent_artifact,
    })
}
pub fn contribution_id(cfg: &Config, sender: Hash, w: &FactorWitnessV2) -> Hash {
    hash(
        b"integer-factor-contribution-v2",
        &[
            &cfg.network,
            &cfg.parameters,
            &sender,
            &w.family,
            &w.parent_ref,
            &w.parent_artifact,
            &w.candidate_artifact,
            &w.update_id,
            &w.components_root,
            &w.round.to_le_bytes(),
        ],
    )
}
#[derive(Clone, Debug)]
pub struct FactorInputV2 {
    pub slot: u8,
    pub rank: u8,
    pub coefficients: Vec<i16>,
}
/// Producer convenience only. Native admission independently repeats full loading/BA.
pub fn build_witness(
    state: &State,
    cfg: &Config,
    sender: Hash,
    round: u64,
    input: FactorInputV2,
    components: Hash,
) -> Result<FactorWitnessV2> {
    let FactorInputV2 {
        slot,
        rank,
        coefficients: factors,
    } = input;
    let mut view = ReadState(state);
    let (reference, model) = parent(&mut view, cfg)?;
    let mut w = FactorWitnessV2 {
        rank,
        slot,
        family: cfg.family,
        parent_ref: reference,
        parent_artifact: model.id(),
        candidate_artifact: [0; 32],
        update_id: [0; 32],
        contribution_id: [0; 32],
        components_root: components,
        round,
        factors,
    };
    let derived = derive(&mut view, cfg, &w)?;
    w.candidate_artifact = derived.model.id();
    w.update_id = derived.update;
    w.contribution_id = contribution_id(cfg, sender, &w);
    Ok(w)
}
pub fn admit(
    s: &mut impl FactorState,
    cfg: &Config,
    sender: Hash,
    height: u64,
    w: &FactorWitnessV2,
) -> Result<Value> {
    ensure(
        w.round
            == height
                / cfg.params["candidate_round_blocks"]
                    .as_u64()
                    .ok_or("CONFIG")?,
        "SUBMISSION_ROUND",
    )?;
    let derived = derive(s, cfg, w)?;
    ensure(
        w.candidate_artifact == derived.model.id()
            && w.update_id == derived.update
            && w.contribution_id == contribution_id(cfg, sender, w),
        "FACTOR_COMPUTED_HASH",
    )?;
    let marker = format!("linear-update-v2:{}", hex::encode(derived.update));
    let metadata = json!({"parent":hex::encode(derived.parent_ref),"parent_artifact":hex::encode(derived.parent_artifact),"round":w.round,"slot":w.slot,"family":hex::encode(cfg.family),"numeric":"exact-i16-BA-add-delta-scale1024-v2","contribution":hex::encode(w.contribution_id)});
    let rows: Vec<_> = derived
        .normal
        .as_chunks::<COLUMNS>()
        .0
        .iter()
        .map(|chunk| chunk.as_slice())
        .map(|c| json!(c))
        .collect();
    let rowprefix = format!("linear-normal-v2:{}:", hex::encode(derived.update));
    if let Some(old) = s.get(&marker) {
        ensure(
            old.as_object().is_some_and(|m| m.len() == 7),
            "FACTOR_NORMAL_STATE",
        )?;
        h(old["contribution"].as_str().ok_or("FACTOR_NORMAL_STATE")?)?;
        for key in [
            "parent",
            "parent_artifact",
            "round",
            "slot",
            "family",
            "numeric",
        ] {
            ensure(old[key] == metadata[key], "FACTOR_UPDATE_COLLISION")?;
        }
        let stored = s.scan(&rowprefix);
        ensure(stored.len() == ROWS, "FACTOR_NORMAL_STATE")?;
        for (i, row) in rows.iter().enumerate() {
            ensure(
                stored.get(&format!("{rowprefix}{i}")) == Some(row),
                "FACTOR_UPDATE_COLLISION",
            )?;
        }
        return Err("DUPLICATE_FUNCTION_UPDATE");
    }
    ensure(s.scan(&rowprefix).is_empty(), "FACTOR_NORMAL_STATE")?;
    store_model(s, &derived.model)?;
    s.put(marker, metadata);
    for (i, row) in rows.into_iter().enumerate() {
        s.put(format!("{rowprefix}{i}"), row);
    }
    Ok(
        json!({"owner":hex::encode(sender),"artifact":hex::encode(w.candidate_artifact),"artifact_bytes":MODEL_BYTES,"components_root":hex::encode(w.components_root),"family":hex::encode(cfg.family),"parent":hex::encode(w.parent_ref),"votes":{},"score":0,"status":"submitted","submitted_height":height,"submission_round":w.round,"factor_profile":PROFILE,"factor_parent_artifact":hex::encode(w.parent_artifact),"function_update_id":hex::encode(w.update_id),"slot":w.slot}),
    )
}
/// Same-round markers survive candidate/archive removal. A new round or current
/// parent closes their duplicate window; paid/current model references stay retained.
pub fn cleanup(state: &mut State, height: u64, cfg: &Config) -> Result<()> {
    if !enabled(cfg) {
        return Ok(());
    }
    let current = state
        .get("model:current")
        .and_then(Value::as_str)
        .ok_or("FACTOR_PARENT")?
        .to_owned();
    let round = height
        / cfg.params["candidate_round_blocks"]
            .as_u64()
            .ok_or("CONFIG")?;
    let removed: Vec<_> = state
        .iter()
        .filter(|(k, _)| k.starts_with("linear-update-v2:"))
        .filter(|(_, v)| v["parent"] != current || v["round"] != round)
        .map(|(k, _)| k.clone())
        .collect();
    for key in removed {
        let id = key.strip_prefix("linear-update-v2:").ok_or("STATE")?;
        let p = format!("linear-normal-v2:{id}:");
        state.retain(|k, _| !k.starts_with(&p));
        state.remove(&key);
    }
    let mut needed = BTreeSet::new();
    needed.insert(
        cfg.params["factor_genesis_artifact"]
            .as_str()
            .ok_or("CONFIG")?
            .to_owned(),
    );
    let mut view = ReadState(state);
    let (_, currentmodel) = parent(&mut view, cfg)?;
    needed.insert(hex::encode(currentmodel.id()));
    if crate::model_evidence_v3::enabled(cfg) {
        for control in crate::model_evidence_v3::controls(cfg)? {
            needed.insert(hex::encode(control.id()));
        }
    }
    for (k, v) in state.iter() {
        if (k.starts_with("contribution:")
            || k.starts_with("evaluation-archive:")
            || k.starts_with("release:"))
            && v["family"] == hex::encode(cfg.family)
        {
            for name in ["artifact", "factor_parent_artifact"] {
                if let Some(value) = v[name].as_str() {
                    needed.insert(value.to_owned());
                }
            }
        }
    }
    state.retain(|k, _| {
        !k.starts_with("linear-model-v2:")
            || k.split(':').nth(1).is_some_and(|id| needed.contains(id))
    });
    Ok(())
}
