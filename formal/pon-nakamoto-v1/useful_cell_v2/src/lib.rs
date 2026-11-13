//! A versioned postprocessing relation over the existing routed int257 Cell.
//!
//! The producer calls the existing direct or rectangular grouped kernel. The
//! verifier calls its independent original-coefficient scalar verifier, then
//! checks every quantization, activation and STOP witness. This is full native
//! recomputation, not a succinct proof, consensus work profile or model adoption.
#![forbid(unsafe_code)]

pub mod task_json;

pub use trnm_crypto_primitives::pon_routed_int257_grouped::{
    Context, Model, Observation, PreparedModel, Product, Request, CLASSES, DIM, EXPERTS, MAX_BATCH,
    MAX_MERGED_OUTPUT,
};
use trnm_crypto_primitives::{hash_domain, Hash32};

pub const PROFILE: &str = "pon-useful-cell-int257-postprocess-research-v2";
pub const MAX_SHIFT: u8 = 30;
pub const MAX_CLAMP: i32 = 32_767;
pub const MAX_STOP_MARGIN: u32 = 65_534;
pub const MAX_ROUTER_OUTPUT: i64 = MAX_MERGED_OUTPUT / 2;
/// Exact binary frame bound: fixed header/trailer plus at most 64 complete rows.
pub const MAX_CLAIM_BYTES: usize = 297 + 130 * MAX_BATCH;
const MAGIC: &[u8; 8] = b"UCELLV2\0";
pub type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activation {
    Identity,
    Relu,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopRule {
    Disabled,
    /// STOP iff the largest and second-largest activated outputs differ by at
    /// least this integer threshold. It is not a calibrated confidence score.
    MarginAtLeast(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub shift: u8,
    pub clamp_abs: i32,
    pub activation: Activation,
    pub stop_rule: StopRule,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        if self.shift > MAX_SHIFT || !(1..=MAX_CLAMP).contains(&self.clamp_abs) {
            return Err("QUANTIZATION_POLICY");
        }
        if let StopRule::MarginAtLeast(m) = self.stop_rule {
            if !(1..=MAX_STOP_MARGIN).contains(&m) {
                return Err("STOP_POLICY");
            }
        }
        Ok(())
    }
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.shift);
        bytes.extend_from_slice(&self.clamp_abs.to_be_bytes());
        bytes.push(match self.activation {
            Activation::Identity => 0,
            Activation::Relu => 1,
        });
        match self.stop_rule {
            StopRule::Disabled => bytes.extend_from_slice(&[0; 5]),
            StopRule::MarginAtLeast(m) => {
                bytes.push(1);
                bytes.extend_from_slice(&m.to_be_bytes());
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadOnlyState {
    pub cell_id: Hash32,
    pub generation: u64,
    pub snapshot_root: Hash32,
    pub model_commitment: Hash32,
}
impl ReadOnlyState {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.cell_id);
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.snapshot_root);
        bytes.extend_from_slice(&self.model_commitment);
    }
}

/// Caller-owned provenance and use restrictions. Hash equality binds bytes; it
/// does not authenticate source replay, demand, CURRENT, FinalUse or an owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bindings {
    pub program_digest: Hash32,
    pub extractor_digest: Hash32,
    pub source_inputs_digest: Hash32,
    pub consumer: Hash32,
    pub allowed_use: Hash32,
    pub candidate_artifact: Hash32,
}
impl Bindings {
    fn encode(&self, bytes: &mut Vec<u8>) {
        for digest in [
            self.program_digest,
            self.extractor_digest,
            self.source_inputs_digest,
            self.consumer,
            self.allowed_use,
            self.candidate_artifact,
        ] {
            bytes.extend_from_slice(&digest);
        }
    }
}

/// An independently retained expected task. Construct it at the consumer from
/// already admitted data; never reconstruct it from a producer's claim.
/// Fields are private to keep validation and the ID inseparable after creation.
#[derive(Clone, Debug)]
pub struct TaskContract {
    context: Context,
    requests: Vec<Request>,
    state: ReadOnlyState,
    bindings: Bindings,
    policy: Policy,
    issued_at_ns: u64,
    valid_until_ns: u64,
    input_commitment: Hash32,
    id: Hash32,
}

impl TaskContract {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        model: &PreparedModel,
        context: Context,
        requests: Vec<Request>,
        state: ReadOnlyState,
        bindings: Bindings,
        policy: Policy,
        issued_at_ns: u64,
        valid_until_ns: u64,
    ) -> Result<Self> {
        policy.validate()?;
        if issued_at_ns >= valid_until_ns {
            return Err("CONTRACT_WINDOW");
        }
        if state.model_commitment != model.commitment() {
            return Err("STATE_MODEL");
        }
        // Reuse the original operator's strict coefficient/input/bias/ID/time
        // contract. Creating a contract also rejects already expired requests.
        model.prepare_batch(&context, &requests, issued_at_ns)?;
        let input_commitment = input_commitment(&context, &requests);
        let mut contract = Self {
            context,
            requests,
            state,
            bindings,
            policy,
            issued_at_ns,
            valid_until_ns,
            input_commitment,
            id: [0; 32],
        };
        contract.id = contract.calculate_id();
        Ok(contract)
    }
    pub fn id(&self) -> Hash32 {
        self.id
    }
    pub fn input_commitment(&self) -> Hash32 {
        self.input_commitment
    }
    pub fn policy(&self) -> Policy {
        self.policy
    }
    pub fn requests(&self) -> &[Request] {
        &self.requests
    }
    pub fn state(&self) -> &ReadOnlyState {
        &self.state
    }
    fn calculate_id(&self) -> Hash32 {
        let mut bytes = Vec::with_capacity(400);
        self.state.encode(&mut bytes);
        self.bindings.encode(&mut bytes);
        self.policy.encode(&mut bytes);
        bytes.extend_from_slice(&self.issued_at_ns.to_be_bytes());
        bytes.extend_from_slice(&self.valid_until_ns.to_be_bytes());
        hash_domain(
            "pon-useful-cell-contract-v2",
            &[PROFILE.as_bytes(), &self.input_commitment, &bytes],
        )
    }
    fn check_live(&self, now_ns: u64) -> Result<()> {
        if now_ns < self.issued_at_ns || now_ns >= self.valid_until_ns {
            return Err("CONTRACT_DEADLINE");
        }
        if self
            .requests
            .iter()
            .any(|r| now_ns < r.arrival_ns || now_ns >= r.deadline_ns)
        {
            return Err("REQUEST_DEADLINE");
        }
        Ok(())
    }
}

fn input_commitment(context: &Context, requests: &[Request]) -> Hash32 {
    let mut bytes = Vec::with_capacity(130 + requests.len() * (80 + DIM * 4));
    for digest in [
        context.chain,
        context.parent,
        context.challenge,
        context.batch_id,
    ] {
        bytes.extend_from_slice(&digest);
    }
    bytes.extend_from_slice(&(requests.len() as u16).to_be_bytes());
    for request in requests {
        bytes.extend_from_slice(&request.id);
        bytes.extend_from_slice(&request.scope);
        bytes.extend_from_slice(&request.arrival_ns.to_be_bytes());
        bytes.extend_from_slice(&request.deadline_ns.to_be_bytes());
        for x in request.x {
            bytes.extend_from_slice(&x.to_be_bytes());
        }
    }
    hash_domain("pon-useful-cell-input-v2", &[PROFILE.as_bytes(), &bytes])
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowWitness {
    pub quotient: [i64; CLASSES],
    pub remainder: [i64; CLASSES],
    pub clamped: [i32; CLASSES],
    pub activated: [i32; CLASSES],
    pub prediction: u8,
    pub margin: u32,
    pub stop: bool,
}

/// Signed division truncates toward zero (not arithmetic right shift). The
/// exact quotient/remainder is exposed for a future algebraic constraint system.
pub fn postprocess(raw: [i64; CLASSES], policy: Policy) -> Result<RowWitness> {
    policy.validate()?;
    if raw
        .iter()
        .any(|x| !(-MAX_MERGED_OUTPUT..=MAX_MERGED_OUTPUT).contains(x))
    {
        return Err("RAW_OUTPUT_RANGE");
    }
    let divisor = 1_i64 << policy.shift;
    let quotient = raw.map(|x| x / divisor);
    let remainder = raw.map(|x| x % divisor);
    let clamped =
        quotient.map(|x| x.clamp(-i64::from(policy.clamp_abs), i64::from(policy.clamp_abs)) as i32);
    let activated = clamped.map(|x| match policy.activation {
        Activation::Identity => x,
        Activation::Relu => x.max(0),
    });
    let mut winner = 0;
    for i in 1..CLASSES {
        if activated[i] > activated[winner] {
            winner = i;
        }
    }
    let second = (0..CLASSES)
        .filter(|&i| i != winner)
        .map(|i| activated[i])
        .max()
        .expect("three classes");
    let margin = (activated[winner] - second) as u32;
    let stop = match policy.stop_rule {
        StopRule::Disabled => false,
        StopRule::MarginAtLeast(threshold) => margin >= threshold,
    };
    Ok(RowWitness {
        quotient,
        remainder,
        clamped,
        activated,
        prediction: winner as u8,
        margin,
        stop,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub contract_id: Hash32,
    pub after_state: ReadOnlyState,
    pub linear: Observation,
    pub rows: Vec<RowWitness>,
    pub statement_commitment: Hash32,
}

#[derive(Clone, Copy, Debug)]
pub enum Kernel {
    Direct,
    Grouped,
}

/// Complete native producer, explicitly reusing the established Cell kernel.
pub fn produce(
    model: &PreparedModel,
    expected: &TaskContract,
    now_ns: u64,
    kernel: Kernel,
) -> Result<Claim> {
    expected.check_live(now_ns)?;
    if model.commitment() != expected.state.model_commitment {
        return Err("EXPECTED_MODEL");
    }
    let (batch, _) = model.prepare_batch(&expected.context, &expected.requests, now_ns)?;
    let linear = match kernel {
        Kernel::Direct => model.observe_direct(&batch)?.0,
        Kernel::Grouped => model.observe(&batch)?.0,
    };
    let rows = linear
        .product
        .logits
        .iter()
        .map(|&raw| postprocess(raw, expected.policy))
        .collect::<Result<_>>()?;
    let mut claim = Claim {
        contract_id: expected.id,
        after_state: expected.state.clone(),
        linear,
        rows,
        statement_commitment: [0; 32],
    };
    claim.statement_commitment = claim.commitment()?;
    Ok(claim)
}

/// Returned only after full recomputation and the completion-time clock check.
/// It certifies this read-only relation at observed completion, not later use.
#[derive(Debug)]
pub struct VerifiedCell {
    contract_id: Hash32,
    statement_commitment: Hash32,
    after_state: ReadOnlyState,
    rows: Vec<RowWitness>,
    completed_at_ns: u64,
}
impl VerifiedCell {
    pub fn contract_id(&self) -> Hash32 {
        self.contract_id
    }
    pub fn statement_commitment(&self) -> Hash32 {
        self.statement_commitment
    }
    pub fn after_state(&self) -> &ReadOnlyState {
        &self.after_state
    }
    pub fn rows(&self) -> &[RowWitness] {
        &self.rows
    }
    pub fn completed_at_ns(&self) -> u64 {
        self.completed_at_ns
    }
}

pub fn verify(
    model: &PreparedModel,
    expected: &TaskContract,
    claim: &Claim,
    mut clock: impl FnMut() -> u64,
) -> Result<VerifiedCell> {
    let start = clock();
    expected.check_live(start)?;
    if model.commitment() != expected.state.model_commitment {
        return Err("EXPECTED_MODEL");
    }
    if claim.contract_id != expected.id {
        return Err("EXPECTED_CONTRACT");
    }
    if claim.after_state != expected.state {
        return Err("READ_ONLY_STATE");
    }
    claim.check_shape()?;
    if claim.rows.len() != expected.requests.len() {
        return Err("EXPECTED_SHAPE");
    }
    // This intentionally remains the existing independent scalar recomputation;
    // the new outer hash does not turn it into a low-cost algebraic proof.
    let verified = model.verify(&expected.context, &expected.requests, start, &claim.linear)?;
    for (row, &raw) in claim.rows.iter().zip(&verified.product().logits) {
        if *row != postprocess(raw, expected.policy)? {
            return Err("POSTPROCESS_RELATION");
        }
    }
    if claim.statement_commitment != claim.commitment()? {
        return Err("CELL_STATEMENT");
    }
    let completed_at_ns = clock();
    if completed_at_ns < start {
        return Err("CLOCK_REGRESSION");
    }
    expected.check_live(completed_at_ns)?;
    Ok(VerifiedCell {
        contract_id: expected.id,
        statement_commitment: claim.statement_commitment,
        after_state: claim.after_state.clone(),
        rows: claim.rows.clone(),
        completed_at_ns,
    })
}

impl Claim {
    fn check_shape(&self) -> Result<()> {
        let n = self.rows.len();
        let p = &self.linear.product;
        if !(1..=MAX_BATCH).contains(&n)
            || p.router_outputs.len() != n
            || p.routes.len() != n
            || p.logits.len() != n
            || p.predictions.len() != n
            || p.groups.iter().any(|g| g.len() > n)
            || p.groups.iter().map(Vec::len).sum::<usize>() != n
            || p.groups.iter().flatten().any(|&i| i >= n)
            || p.routes.iter().any(|&r| r >= EXPERTS)
            || p.predictions.iter().any(|&r| r >= CLASSES)
            || self
                .rows
                .iter()
                .any(|r| usize::from(r.prediction) >= CLASSES)
            || p.nonempty_expert_groups > EXPERTS
        {
            return Err("CLAIM_SHAPE");
        }
        Ok(())
    }
    fn body(&self) -> Result<Vec<u8>> {
        self.check_shape()?;
        let n = self.rows.len();
        let mut bytes = Vec::with_capacity(297 + 130 * n);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(n as u16).to_be_bytes());
        bytes.extend_from_slice(&self.contract_id);
        self.after_state.encode(&mut bytes);
        for digest in [
            self.linear.model_commitment,
            self.linear.input_commitment,
            self.linear.statement_commitment,
        ] {
            bytes.extend_from_slice(&digest);
        }
        let p = &self.linear.product;
        for i in 0..n {
            for x in p.router_outputs[i] {
                bytes.extend_from_slice(&x.to_be_bytes());
            }
            bytes.push(p.routes[i] as u8);
            for x in p.logits[i] {
                bytes.extend_from_slice(&x.to_be_bytes());
            }
            bytes.push(p.predictions[i] as u8);
        }
        for group in &p.groups {
            bytes.extend_from_slice(&(group.len() as u16).to_be_bytes());
            for &i in group {
                bytes.extend_from_slice(&(i as u16).to_be_bytes());
            }
        }
        bytes.extend_from_slice(&p.useful_dense_macs.to_be_bytes());
        bytes.extend_from_slice(&p.padded_macs.to_be_bytes());
        bytes.push(p.nonempty_expert_groups as u8);
        for row in &self.rows {
            for x in row.quotient {
                bytes.extend_from_slice(&x.to_be_bytes());
            }
            for x in row.remainder {
                bytes.extend_from_slice(&x.to_be_bytes());
            }
            for x in row.clamped {
                bytes.extend_from_slice(&x.to_be_bytes());
            }
            for x in row.activated {
                bytes.extend_from_slice(&x.to_be_bytes());
            }
            bytes.push(row.prediction);
            bytes.extend_from_slice(&row.margin.to_be_bytes());
            bytes.push(u8::from(row.stop));
        }
        Ok(bytes)
    }
    /// A publicly recomputable binding. Rehashing false data never repairs it.
    pub fn commitment(&self) -> Result<Hash32> {
        Ok(hash_domain(
            "pon-useful-cell-statement-v2",
            &[PROFILE.as_bytes(), &self.body()?],
        ))
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = self.body()?;
        bytes.extend_from_slice(&self.statement_commitment);
        Ok(bytes)
    }
    /// Bounded exact decoder: frame size and fixed n-derived length are checked
    /// before vector allocation. Reject unknown tags, invalid counts and tails.
    /// Semantic validity still requires `verify` with an independent contract.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 297 || bytes.len() > MAX_CLAIM_BYTES {
            return Err("WIRE_SIZE");
        }
        let mut r = Reader { bytes, offset: 0 };
        if r.read::<8>()? != *MAGIC {
            return Err("WIRE_VERSION");
        }
        let n = usize::from(r.u16()?);
        if !(1..=MAX_BATCH).contains(&n) || bytes.len() != 297 + 130 * n {
            return Err("WIRE_SIZE");
        }
        let contract_id = r.read()?;
        let after_state = ReadOnlyState {
            cell_id: r.read()?,
            generation: r.u64()?,
            snapshot_root: r.read()?,
            model_commitment: r.read()?,
        };
        let model_commitment = r.read()?;
        let input_commitment = r.read()?;
        let linear_statement = r.read()?;
        let mut router_outputs = Vec::with_capacity(n);
        let mut routes = Vec::with_capacity(n);
        let mut logits = Vec::with_capacity(n);
        let mut predictions = Vec::with_capacity(n);
        for _ in 0..n {
            router_outputs.push([r.i64()?, r.i64()?, r.i64()?]);
            routes.push(usize::from(r.byte()?));
            logits.push([r.i64()?, r.i64()?, r.i64()?]);
            predictions.push(usize::from(r.byte()?));
        }
        let mut groups: [Vec<usize>; EXPERTS] = std::array::from_fn(|_| Vec::new());
        let mut total = 0;
        for group in &mut groups {
            let count = usize::from(r.u16()?);
            if count > n || total + count > n {
                return Err("WIRE_GROUP_SIZE");
            }
            total += count;
            for _ in 0..count {
                group.push(usize::from(r.u16()?));
            }
        }
        if total != n {
            return Err("WIRE_GROUP_SIZE");
        }
        let useful_dense_macs = r.u64()?;
        let padded_macs = r.u64()?;
        let nonempty_expert_groups = usize::from(r.byte()?);
        let mut rows = Vec::with_capacity(n);
        for _ in 0..n {
            rows.push(RowWitness {
                quotient: [r.i64()?, r.i64()?, r.i64()?],
                remainder: [r.i64()?, r.i64()?, r.i64()?],
                clamped: [r.i32()?, r.i32()?, r.i32()?],
                activated: [r.i32()?, r.i32()?, r.i32()?],
                prediction: r.byte()?,
                margin: r.u32()?,
                stop: match r.byte()? {
                    0 => false,
                    1 => true,
                    _ => return Err("WIRE_BOOL"),
                },
            });
        }
        let statement_commitment = r.read()?;
        if r.offset != bytes.len() {
            return Err("WIRE_TRAILING");
        }
        let claim = Self {
            contract_id,
            after_state,
            linear: Observation {
                model_commitment,
                input_commitment,
                statement_commitment: linear_statement,
                product: Product {
                    router_outputs,
                    routes,
                    groups,
                    logits,
                    predictions,
                    useful_dense_macs,
                    padded_macs,
                    nonempty_expert_groups,
                },
            },
            rows,
            statement_commitment,
        };
        claim.check_shape()?;
        Ok(claim)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl Reader<'_> {
    fn read<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.offset.checked_add(N).ok_or("WIRE_EOF")?;
        let output = self
            .bytes
            .get(self.offset..end)
            .ok_or("WIRE_EOF")?
            .try_into()
            .map_err(|_| "WIRE_EOF")?;
        self.offset = end;
        Ok(output)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.read::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.read()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.read()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.read()?))
    }
    fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_be_bytes(self.read()?))
    }
    fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(self.read()?))
    }
}
