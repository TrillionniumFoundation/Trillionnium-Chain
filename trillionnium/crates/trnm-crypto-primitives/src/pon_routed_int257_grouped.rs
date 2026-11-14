//! Exact routed integer operator for a separately versioned research profile.
//!
//! This is an algebraic relation with full recomputation, not a PoW certificate,
//! proof of demand, deadline authority, model adoption, or production activation.
//! It never invokes or changes W1. All 257 coordinates (including bias=8) are
//! consumed; the router runs once and only the selected experts are evaluated.
//! Direct selected, packed rectangular and exact factored producers bind the
//! same statement. Packing or expanding an adapter is not a relation requirement.
use crate::{hash_domain, Hash32};
use std::{collections::BTreeSet, time::Instant};

pub const PROFILE: &str = "pon-routed-int257-grouped-research-v0";
pub const DIM: usize = 257;
pub const CLASSES: usize = 3;
pub const EXPERTS: usize = 3;
pub const MAX_BATCH: usize = 64;
pub const MAX_COEFFICIENT: i32 = 32_767;
pub const MAX_INPUT: i32 = 8;
pub const MAX_MERGED_OUTPUT: i64 = 134_737_904;
/// Bounded producer implementation, matching the existing Python comparison.
/// This is not an additional restriction on the verified arithmetic relation.
pub const MAX_FACTOR_RANK: usize = 8;
pub type Matrix = [[i32; DIM]; CLASSES];
pub type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    pub version: Hash32,
    pub base: Matrix,
    pub router: Matrix,
    pub deltas: [Matrix; EXPERTS],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub chain: Hash32,
    pub parent: Hash32,
    pub challenge: Hash32,
    pub batch_id: Hash32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub id: Hash32,
    pub scope: Hash32,
    pub arrival_ns: u64,
    pub deadline_ns: u64,
    pub x: [i32; DIM],
}

#[derive(Clone, Debug)]
pub struct PreparedModel {
    model: Model,
    merged: [Matrix; EXPERTS],
    commitment: Hash32,
}

#[derive(Clone, Debug)]
pub struct PreparedBatch {
    context: Context,
    requests: Vec<Request>,
    model_commitment: Hash32,
    input_commitment: Hash32,
}

/// One exact adapter B A: up is B (3 x rank), down is A (rank x 257).
/// No approximate factorization, scale change or rounding is admitted here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterFactors {
    pub up: [Vec<i32>; CLASSES],
    pub down: Vec<[i32; DIM]>,
}

/// Immutable local preparation, constructible only by complete B A admission.
/// It binds the entire original model, including its version; it is neither a
/// cached request authorization nor a portable cost or consensus certificate.
#[derive(Clone, Debug)]
pub struct PreparedFactors {
    model_commitment: Hash32,
    adapters: [AdapterFactors; EXPERTS],
    preparation_macs: u64,
}

impl PreparedFactors {
    pub fn model_commitment(&self) -> Hash32 {
        self.model_commitment
    }
    /// Actual complete coefficient-comparison positions paid at preparation.
    /// Model preparation and all validation, memory and hashing costs are extra.
    pub fn preparation_macs(&self) -> u64 {
        self.preparation_macs
    }
    pub fn ranks(&self) -> [usize; EXPERTS] {
        std::array::from_fn(|expert| self.adapters[expert].down.len())
    }
}

/// Instrumented arithmetic of one factored producer call, not a cost floor.
/// These counters are deliberately outside the unchanged canonical statement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FactoredCounts {
    router_macs: u64,
    base_macs: u64,
    adapter_macs: u64,
    output_additions: u64,
}

impl FactoredCounts {
    pub fn router_macs(&self) -> u64 {
        self.router_macs
    }
    pub fn base_macs(&self) -> u64 {
        self.base_macs
    }
    pub fn adapter_macs(&self) -> u64 {
        self.adapter_macs
    }
    pub fn output_additions(&self) -> u64 {
        self.output_additions
    }
    pub fn execution_macs(&self) -> u64 {
        // Only the bounded producer constructs nonzero private counters.
        self.router_macs + self.base_macs + self.adapter_macs
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Product {
    pub router_outputs: Vec<[i64; CLASSES]>,
    pub routes: Vec<usize>,
    pub groups: [Vec<usize>; EXPERTS],
    pub logits: Vec<[i64; CLASSES]>,
    pub predictions: Vec<usize>,
    /// Dense algebraic positions in the required router and selected expert.
    /// This is not an attacker-cost lower bound or an entitlement to credit.
    pub useful_dense_macs: u64,
    pub padded_macs: u64,
    /// Logical nonempty groups, not a kernel-launch or physical batch count.
    pub nonempty_expert_groups: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrdinaryOutput {
    pub routes: Vec<usize>,
    pub logits: Vec<[i64; CLASSES]>,
    pub predictions: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub model_commitment: Hash32,
    pub input_commitment: Hash32,
    pub statement_commitment: Hash32,
    pub product: Product,
}

/// Only `verify` can construct this handoff. Expected model, context, requests
/// and current caller clock are external arguments, never taken from the claim.
pub struct VerifiedProduct {
    product: Product,
    statement_commitment: Hash32,
}
impl VerifiedProduct {
    pub fn product(&self) -> &Product {
        &self.product
    }
    pub fn statement_commitment(&self) -> Hash32 {
        self.statement_commitment
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PhaseNs {
    pub validation: u64,
    pub input_commitment: u64,
    pub router: u64,
    pub gather: u64,
    pub expert: u64,
    pub statement_commitment: u64,
}

/// Direct execution includes routing, selected logits and stable group indices.
/// It does not copy activations into packed expert matrices.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirectPhaseNs {
    pub execution: u64,
    pub statement_commitment: u64,
}
fn ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).expect("elapsed interval fits u64 nanoseconds")
}
fn signed(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn count(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u64).to_be_bytes());
}
fn append_context(out: &mut Vec<u8>, context: &Context) {
    for hash in [
        context.chain,
        context.parent,
        context.challenge,
        context.batch_id,
    ] {
        out.extend_from_slice(&hash);
    }
}

impl PreparedModel {
    pub fn new(model: Model) -> Result<Self> {
        for matrix in std::iter::once(&model.base)
            .chain(std::iter::once(&model.router))
            .chain(model.deltas.iter())
        {
            if matrix
                .iter()
                .flatten()
                .any(|&x| !(-MAX_COEFFICIENT..=MAX_COEFFICIENT).contains(&x))
            {
                return Err("MODEL_COEFFICIENT");
            }
        }
        let mut bytes = Vec::with_capacity(32 + 5 * CLASSES * DIM * 8 + 24);
        bytes.extend_from_slice(&model.version);
        count(&mut bytes, DIM);
        count(&mut bytes, CLASSES);
        count(&mut bytes, EXPERTS);
        for matrix in std::iter::once(&model.base)
            .chain(std::iter::once(&model.router))
            .chain(model.deltas.iter())
        {
            for &x in matrix.iter().flatten() {
                signed(&mut bytes, i64::from(x));
            }
        }
        let commitment = hash_domain(
            "pon-routed-int257-grouped-model-v0",
            &[
                PROFILE.as_bytes(),
                b"signed-i32-coeff-i64-accum-bias8-lowest-argmax",
                &bytes,
            ],
        );
        let merged = std::array::from_fn(|e| {
            std::array::from_fn(|r| {
                std::array::from_fn(|k| model.base[r][k] + model.deltas[e][r][k])
            })
        });
        Ok(Self {
            model,
            merged,
            commitment,
        })
    }
    pub fn commitment(&self) -> Hash32 {
        self.commitment
    }

    /// Compare every B A coefficient with every original expert delta once,
    /// including coordinates absent from the later requests. No dense adapter
    /// is materialized or substituted for the original model. Supplied factors
    /// are moved into private immutable preparation after successful admission.
    pub fn prepare_factors(&self, adapters: [AdapterFactors; EXPERTS]) -> Result<PreparedFactors> {
        let mut preparation_macs = 0_u64;
        for (expert, adapter) in adapters.iter().enumerate() {
            let rank = adapter.down.len();
            if !(1..=MAX_FACTOR_RANK).contains(&rank) {
                return Err("FACTOR_RANK");
            }
            if adapter.up.iter().any(|row| row.len() != rank) {
                return Err("FACTOR_SHAPE");
            }
            if adapter
                .up
                .iter()
                .flatten()
                .chain(adapter.down.iter().flatten())
                .any(|&value| !(-MAX_COEFFICIENT..=MAX_COEFFICIENT).contains(&value))
            {
                return Err("FACTOR_COEFFICIENT");
            }
            for (row, up) in adapter.up.iter().enumerate() {
                for column in 0..DIM {
                    let mut coefficient = 0_i64;
                    for (&value, down) in up.iter().zip(&adapter.down) {
                        coefficient = checked_factor_mac(
                            coefficient,
                            i64::from(value),
                            i64::from(down[column]),
                        )?;
                    }
                    if coefficient != i64::from(self.model.deltas[expert][row][column]) {
                        return Err("FACTOR_NOT_SAME_DELTA");
                    }
                }
            }
            preparation_macs += (CLASSES * rank * DIM) as u64;
        }
        Ok(PreparedFactors {
            model_commitment: self.commitment,
            adapters,
            preparation_macs,
        })
    }

    /// Exact base + B(Ax), with the original router and selected expert only.
    /// The hot path does not expand B A or read a cached merged expert. No
    /// activation cache is introduced: distinct scoped requests retain their
    /// own inputs and complete commitments. Existing verifier authority applies.
    pub fn factored(
        &self,
        batch: &PreparedBatch,
        factors: &PreparedFactors,
    ) -> Result<(Product, FactoredCounts)> {
        if batch.model_commitment != self.commitment {
            return Err("PREPARED_MODEL");
        }
        if factors.model_commitment != self.commitment {
            return Err("FACTOR_MODEL");
        }
        let mut counts = FactoredCounts::default();
        let mut router_outputs = Vec::with_capacity(batch.requests.len());
        let mut routes = Vec::with_capacity(batch.requests.len());
        let mut groups: [Vec<usize>; EXPERTS] = std::array::from_fn(|_| Vec::new());
        let mut logits = Vec::with_capacity(batch.requests.len());
        let mut predictions = Vec::with_capacity(batch.requests.len());
        for (index, request) in batch.requests.iter().enumerate() {
            let scores = std::array::from_fn(|row| dot(&self.model.router[row], &request.x));
            let route = argmax(&scores);
            let adapter = &factors.adapters[route];
            let mut hidden = Vec::with_capacity(adapter.down.len());
            for down in &adapter.down {
                let mut value = 0_i64;
                for (&coefficient, &input) in down.iter().zip(&request.x) {
                    value = checked_factor_mac(value, i64::from(coefficient), i64::from(input))?;
                }
                hidden.push(value);
            }
            let mut output = [0_i64; CLASSES];
            for (row, value) in output.iter_mut().enumerate() {
                let mut delta = 0_i64;
                for (&coefficient, &activation) in adapter.up[row].iter().zip(&hidden) {
                    delta = checked_factor_mac(delta, i64::from(coefficient), activation)?;
                }
                *value = dot(&self.model.base[row], &request.x)
                    .checked_add(delta)
                    .ok_or("FACTOR_ARITHMETIC_OVERFLOW")?;
                if value.unsigned_abs() > MAX_MERGED_OUTPUT as u64 {
                    return Err("FACTOR_OUTPUT_BOUND");
                }
            }
            counts.router_macs += (CLASSES * DIM) as u64;
            counts.base_macs += (CLASSES * DIM) as u64;
            counts.adapter_macs += (adapter.down.len() * (DIM + CLASSES)) as u64;
            counts.output_additions += CLASSES as u64;
            predictions.push(argmax(&output));
            router_outputs.push(scores);
            routes.push(route);
            groups[route].push(index);
            logits.push(output);
        }
        Ok((
            Product {
                router_outputs,
                routes,
                nonempty_expert_groups: groups.iter().filter(|group| !group.is_empty()).count(),
                groups,
                logits,
                predictions,
                // Preserve the algebraic statement across all lawful producers.
                // Instrumented execution costs belong only to the separate counts.
                useful_dense_macs: dense_macs(batch.requests.len()),
                padded_macs: 0,
            },
            counts,
        ))
    }

    pub fn observe_factored(
        &self,
        batch: &PreparedBatch,
        factors: &PreparedFactors,
    ) -> Result<(Observation, DirectPhaseNs, FactoredCounts)> {
        let start = Instant::now();
        let (product, counts) = self.factored(batch, factors)?;
        let execution = ns(start);
        let (observation, statement_commitment) = self.commit_observation(batch, product);
        Ok((
            observation,
            DirectPhaseNs {
                execution,
                statement_commitment,
            },
            counts,
        ))
    }

    pub fn prepare_batch(
        &self,
        context: &Context,
        requests: &[Request],
        now_ns: u64,
    ) -> Result<(PreparedBatch, PhaseNs)> {
        let start = Instant::now();
        validate_requests(requests, now_ns)?;
        let mut phase = PhaseNs {
            validation: ns(start),
            ..PhaseNs::default()
        };
        let start = Instant::now();
        let input_commitment = inputs_commitment(self.commitment, context, requests);
        phase.input_commitment = ns(start);
        Ok((
            PreparedBatch {
                context: context.clone(),
                requests: requests.to_vec(),
                model_commitment: self.commitment,
                input_commitment,
            },
            phase,
        ))
    }

    /// Direct selected relation product, using the same cached merged model as
    /// the packed producer. Stable group indices are retained without copying
    /// activations. `ordinary` below is the smaller outputs-only timing control.
    pub fn direct(&self, batch: &PreparedBatch) -> Result<Product> {
        if batch.model_commitment != self.commitment {
            return Err("PREPARED_MODEL");
        }
        let mut router_outputs = Vec::with_capacity(batch.requests.len());
        let mut routes = Vec::with_capacity(batch.requests.len());
        let mut groups: [Vec<usize>; EXPERTS] = std::array::from_fn(|_| Vec::new());
        let mut logits = Vec::with_capacity(batch.requests.len());
        let mut predictions = Vec::with_capacity(batch.requests.len());
        for (index, request) in batch.requests.iter().enumerate() {
            let scores = std::array::from_fn(|row| dot(&self.model.router[row], &request.x));
            let route = argmax(&scores);
            let output = std::array::from_fn(|row| dot(&self.merged[route][row], &request.x));
            predictions.push(argmax(&output));
            router_outputs.push(scores);
            routes.push(route);
            groups[route].push(index);
            logits.push(output);
        }
        Ok(Product {
            router_outputs,
            routes,
            nonempty_expert_groups: groups.iter().filter(|g| !g.is_empty()).count(),
            groups,
            logits,
            predictions,
            useful_dense_macs: dense_macs(batch.requests.len()),
            padded_macs: 0,
        })
    }

    /// Ordinary inference does not create diagnostic groups, transcripts or
    /// retained router outputs. This is the stronger warm timing control.
    pub fn ordinary(&self, batch: &PreparedBatch) -> Result<OrdinaryOutput> {
        if batch.model_commitment != self.commitment {
            return Err("PREPARED_MODEL");
        }
        let mut routes = Vec::with_capacity(batch.requests.len());
        let mut logits = Vec::with_capacity(batch.requests.len());
        let mut predictions = Vec::with_capacity(batch.requests.len());
        for request in &batch.requests {
            let scores = std::array::from_fn(|row| dot(&self.model.router[row], &request.x));
            let route = argmax(&scores);
            let output = std::array::from_fn(|row| dot(&self.merged[route][row], &request.x));
            routes.push(route);
            predictions.push(argmax(&output));
            logits.push(output);
        }
        Ok(OrdinaryOutput {
            routes,
            logits,
            predictions,
        })
    }

    /// Stable grouped rectangular contraction with compact feature-major
    /// activation buffers of exact shape 257 x b_e. No padded columns. Each
    /// selected weight is reused across its contiguous expert-local batch.
    /// Gather is timed separately; scatter is included in expert timing.
    pub fn grouped(&self, batch: &PreparedBatch) -> Result<(Product, PhaseNs)> {
        if batch.model_commitment != self.commitment {
            return Err("PREPARED_MODEL");
        }
        let n = batch.requests.len();
        let mut phase = PhaseNs::default();
        let start = Instant::now();
        let router_outputs: Vec<[i64; CLASSES]> = batch
            .requests
            .iter()
            .map(|request| std::array::from_fn(|row| dot(&self.model.router[row], &request.x)))
            .collect();
        let routes: Vec<usize> = router_outputs.iter().map(argmax).collect();
        phase.router = ns(start);
        let start = Instant::now();
        let mut groups: [Vec<usize>; EXPERTS] = std::array::from_fn(|_| Vec::new());
        for (i, &expert) in routes.iter().enumerate() {
            groups[expert].push(i);
        }
        let gathered: [Vec<i32>; EXPERTS] = std::array::from_fn(|e| {
            let width = groups[e].len();
            let mut inputs = vec![0_i32; DIM * width];
            for k in 0..DIM {
                for (local, &global) in groups[e].iter().enumerate() {
                    inputs[k * width + local] = batch.requests[global].x[k];
                }
            }
            inputs
        });
        phase.gather = ns(start);
        let start = Instant::now();
        let mut logits = vec![[0_i64; CLASSES]; n];
        let mut nonempty_expert_groups = 0;
        for (expert, inputs) in gathered.iter().enumerate() {
            let width = groups[expert].len();
            if width == 0 {
                continue;
            }
            nonempty_expert_groups += 1;
            let mut output = vec![0_i64; CLASSES * width];
            for row in 0..CLASSES {
                let output_row = &mut output[row * width..(row + 1) * width];
                for k in 0..DIM {
                    let coefficient = i64::from(self.merged[expert][row][k]);
                    let input_row = &inputs[k * width..(k + 1) * width];
                    for (sum, &x) in output_row.iter_mut().zip(input_row) {
                        *sum += coefficient * i64::from(x);
                    }
                }
            }
            for (local, &global) in groups[expert].iter().enumerate() {
                for row in 0..CLASSES {
                    logits[global][row] = output[row * width + local];
                }
            }
        }
        let predictions = logits.iter().map(argmax).collect();
        phase.expert = ns(start);
        Ok((
            Product {
                router_outputs,
                routes,
                groups,
                logits,
                predictions,
                useful_dense_macs: dense_macs(n),
                padded_macs: 0,
                nonempty_expert_groups,
            },
            phase,
        ))
    }

    /// Packed rectangular producer. This existing entry point remains packed;
    /// `observe_direct` is an explicit alternative with an identical statement.
    pub fn observe(&self, batch: &PreparedBatch) -> Result<(Observation, PhaseNs)> {
        let (product, mut phase) = self.grouped(batch)?;
        let (observation, commitment_ns) = self.commit_observation(batch, product);
        phase.statement_commitment = commitment_ns;
        Ok((observation, phase))
    }

    /// Direct selected producer avoids the activation packing cost for small
    /// batches. It computes the same relation and uses the same full verifier;
    /// callers choose between producers using measurements of their shapes.
    pub fn observe_direct(&self, batch: &PreparedBatch) -> Result<(Observation, DirectPhaseNs)> {
        let start = Instant::now();
        let product = self.direct(batch)?;
        let execution = ns(start);
        let (observation, statement_commitment) = self.commit_observation(batch, product);
        Ok((
            observation,
            DirectPhaseNs {
                execution,
                statement_commitment,
            },
        ))
    }

    fn commit_observation(&self, batch: &PreparedBatch, product: Product) -> (Observation, u64) {
        let start = Instant::now();
        let statement_commitment = statement_commitment(
            self.commitment,
            batch.input_commitment,
            &batch.context,
            &product,
        );
        let commitment_ns = ns(start);
        (
            Observation {
                model_commitment: self.commitment,
                input_commitment: batch.input_commitment,
                statement_commitment,
                product,
            },
            commitment_ns,
        )
    }

    /// Full scalar recomputation using original base and delta coefficients.
    /// Intentionally independent of the grouped gather and cached merged matrix.
    /// Hashes are binding only; they never replace this O(n*257) verification.
    pub fn verify(
        &self,
        expected_context: &Context,
        expected_requests: &[Request],
        now_ns: u64,
        claim: &Observation,
    ) -> Result<VerifiedProduct> {
        validate_requests(expected_requests, now_ns)?;
        if claim.model_commitment != self.commitment {
            return Err("MODEL_COMMITMENT");
        }
        let expected_input =
            inputs_commitment(self.commitment, expected_context, expected_requests);
        if claim.input_commitment != expected_input {
            return Err("INPUT_COMMITMENT");
        }
        let n = expected_requests.len();
        let p = &claim.product;
        if p.routes.len() != n
            || p.router_outputs.len() != n
            || p.logits.len() != n
            || p.predictions.len() != n
            || p.groups.iter().any(|group| group.len() > n)
            || p.groups.iter().map(Vec::len).sum::<usize>() != n
        {
            return Err("PRODUCT_SHAPE");
        }
        let mut expected_groups: [Vec<usize>; EXPERTS] = std::array::from_fn(|_| Vec::new());
        for (index, request) in expected_requests.iter().enumerate() {
            let mut scores = [0_i64; CLASSES];
            for k in 0..DIM {
                for (r, score) in scores.iter_mut().enumerate() {
                    *score += i64::from(self.model.router[r][k]) * i64::from(request.x[k]);
                }
            }
            let route = reference_argmax(&scores);
            if p.router_outputs[index] != scores || p.routes[index] != route {
                return Err("ROUTER_RELATION");
            }
            expected_groups[route].push(index);
            let mut output = [0_i64; CLASSES];
            for k in 0..DIM {
                for (r, total) in output.iter_mut().enumerate() {
                    *total += i64::from(self.model.base[r][k]) * i64::from(request.x[k]);
                    *total += i64::from(self.model.deltas[route][r][k]) * i64::from(request.x[k]);
                }
            }
            if output.iter().any(|x| x.abs() > MAX_MERGED_OUTPUT)
                || p.logits[index] != output
                || p.predictions[index] != reference_argmax(&output)
            {
                return Err("EXPERT_RELATION");
            }
        }
        if p.groups != expected_groups {
            return Err("GROUP_PARTITION");
        }
        if p.useful_dense_macs != dense_macs(n)
            || p.padded_macs != 0
            || p.nonempty_expert_groups != expected_groups.iter().filter(|g| !g.is_empty()).count()
        {
            return Err("WORK_ACCOUNTING");
        }
        if claim.statement_commitment
            != statement_commitment(self.commitment, expected_input, expected_context, p)
        {
            return Err("STATEMENT_COMMITMENT");
        }
        Ok(VerifiedProduct {
            product: p.clone(),
            statement_commitment: claim.statement_commitment,
        })
    }
}

fn validate_requests(requests: &[Request], now_ns: u64) -> Result<()> {
    if requests.is_empty() || requests.len() > MAX_BATCH {
        return Err("BATCH_SIZE");
    }
    let mut ids = BTreeSet::new();
    for r in requests {
        if !ids.insert(r.id) {
            return Err("DUPLICATE_REQUEST");
        }
        if r.arrival_ns >= r.deadline_ns || r.arrival_ns > now_ns || now_ns >= r.deadline_ns {
            return Err("REQUEST_DEADLINE");
        }
        if r.x[DIM - 1] != MAX_INPUT || r.x.iter().any(|x| !(-MAX_INPUT..=MAX_INPUT).contains(x)) {
            return Err("INPUT_RANGE_BIAS");
        }
    }
    Ok(())
}
fn inputs_commitment(model: Hash32, context: &Context, requests: &[Request]) -> Hash32 {
    let mut bytes = Vec::with_capacity(128 + 8 + requests.len() * (80 + DIM * 8));
    append_context(&mut bytes, context);
    count(&mut bytes, requests.len());
    for request in requests {
        bytes.extend_from_slice(&request.id);
        bytes.extend_from_slice(&request.scope);
        bytes.extend_from_slice(&request.arrival_ns.to_be_bytes());
        bytes.extend_from_slice(&request.deadline_ns.to_be_bytes());
        for &x in &request.x {
            signed(&mut bytes, i64::from(x));
        }
    }
    hash_domain(
        "pon-routed-int257-grouped-input-v0",
        &[PROFILE.as_bytes(), &model, &bytes],
    )
}
fn statement_commitment(model: Hash32, inputs: Hash32, context: &Context, p: &Product) -> Hash32 {
    let mut bytes = Vec::new();
    append_context(&mut bytes, context);
    count(&mut bytes, p.routes.len());
    for values in &p.router_outputs {
        for &x in values {
            signed(&mut bytes, x);
        }
    }
    for &route in &p.routes {
        count(&mut bytes, route);
    }
    for group in &p.groups {
        count(&mut bytes, group.len());
        for &index in group {
            count(&mut bytes, index);
        }
    }
    for values in &p.logits {
        for &x in values {
            signed(&mut bytes, x);
        }
    }
    for &prediction in &p.predictions {
        count(&mut bytes, prediction);
    }
    bytes.extend_from_slice(&p.useful_dense_macs.to_be_bytes());
    bytes.extend_from_slice(&p.padded_macs.to_be_bytes());
    count(&mut bytes, p.nonempty_expert_groups);
    hash_domain(
        "pon-routed-int257-grouped-statement-v0",
        &[PROFILE.as_bytes(), &model, &inputs, &bytes],
    )
}
fn dense_macs(n: usize) -> u64 {
    (2 * CLASSES * DIM * n) as u64
}
fn checked_factor_mac(sum: i64, coefficient: i64, value: i64) -> Result<i64> {
    coefficient
        .checked_mul(value)
        .and_then(|product| sum.checked_add(product))
        .ok_or("FACTOR_ARITHMETIC_OVERFLOW")
}
fn dot(a: &[i32; DIM], b: &[i32; DIM]) -> i64 {
    a.iter()
        .zip(b)
        .map(|(&a, &b)| i64::from(a) * i64::from(b))
        .sum()
}
fn argmax(values: &[i64; CLASSES]) -> usize {
    let mut selected = 0;
    for i in 1..CLASSES {
        if values[i] > values[selected] {
            selected = i;
        }
    }
    selected
}
fn reference_argmax(values: &[i64; CLASSES]) -> usize {
    (0..CLASSES)
        .find(|&i| values.iter().all(|&v| v <= values[i]))
        .expect("nonempty scores")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn factor_fixture(
        rank: usize,
        n: usize,
    ) -> (Model, Context, Vec<Request>, [AdapterFactors; EXPERTS]) {
        let (mut model, context, requests) = fixture(n);
        let adapters = std::array::from_fn(|expert| {
            let down: Vec<[i32; DIM]> = (0..rank)
                .map(|j| std::array::from_fn(|k| ((k + j * 3 + expert) % 5) as i32 - 2))
                .collect();
            let up: [Vec<i32>; CLASSES] = std::array::from_fn(|row| {
                (0..rank)
                    .map(|j| ((row + j + expert) % 5) as i32 - 2)
                    .collect()
            });
            for (row, coefficients) in up.iter().enumerate() {
                for k in 0..DIM {
                    model.deltas[expert][row][k] =
                        coefficients.iter().zip(&down).map(|(&u, d)| u * d[k]).sum();
                }
            }
            AdapterFactors { up, down }
        });
        (model, context, requests, adapters)
    }
    fn fixture(n: usize) -> (Model, Context, Vec<Request>) {
        let mut model = Model {
            version: [4; 32],
            base: [[0; DIM]; 3],
            router: [[0; DIM]; 3],
            deltas: [[[0; DIM]; 3]; 3],
        };
        for r in 0..3 {
            for k in 0..DIM {
                model.base[r][k] = ((r * 17 + k * 7) % 19) as i32 - 9;
                for e in 0..3 {
                    model.deltas[e][r][k] = ((e * 11 + r * 5 + k * 13) % 17) as i32 - 8;
                }
            }
        }
        model.router[0][0] = 1;
        model.router[1][1] = 1;
        model.router[2][2] = 1;
        let context = Context {
            chain: [1; 32],
            parent: [2; 32],
            challenge: [3; 32],
            batch_id: [4; 32],
        };
        let requests = (0..n)
            .map(|i| {
                let mut x = [0; DIM];
                x[i % 3] = 8;
                x[256] = 8;
                let mut id = [0; 32];
                id[..8].copy_from_slice(&(i as u64).to_be_bytes());
                Request {
                    id,
                    scope: [9; 32],
                    arrival_ns: 10,
                    deadline_ns: 1000,
                    x,
                }
            })
            .collect();
        (model, context, requests)
    }
    fn observation(n: usize) -> (PreparedModel, Context, Vec<Request>, Observation) {
        let (m, c, r) = fixture(n);
        let m = PreparedModel::new(m).unwrap();
        let (b, _) = m.prepare_batch(&c, &r, 20).unwrap();
        let (o, _) = m.observe(&b).unwrap();
        (m, c, r, o)
    }
    #[test]
    fn canonical_binary_domains_have_fixed_cross_language_vectors() {
        // Independently derived with Python hashlib + struct.pack big endian.
        let (_, _, _, o) = observation(4);
        assert_eq!(
            hex::encode(o.model_commitment),
            "b5d026559147238e4ea30289a88e15f20ab05880d613989705008b28b7829352"
        );
        assert_eq!(
            hex::encode(o.input_commitment),
            "e015bbb9cb681d63e0d90728f3638aca1b4168f16968a470c0066999420dde29"
        );
        assert_eq!(
            hex::encode(o.statement_commitment),
            "7a54c59624a0a774385e72402a05c8eb14de6504781213512ada6d253d3a06fd"
        );
        assert_eq!(o.product.routes, vec![0, 1, 2, 0]);
        assert_eq!(o.product.groups, [vec![0, 3], vec![1], vec![2]]);
        assert_eq!(
            o.product.logits,
            vec![
                [-120, -56, -8],
                [-56, -8, -232],
                [8, -80, -32],
                [-120, -56, -8]
            ]
        );
        assert_eq!(o.product.predictions, vec![2, 1, 0, 2]);
    }
    #[test]
    fn all_batch_sizes_match_independent_original_coefficient_reference() {
        for n in 1..=64 {
            let (m, c, r, o) = observation(n);
            let (b, _) = m.prepare_batch(&c, &r, 20).unwrap();
            assert_eq!(m.direct(&b).unwrap(), o.product);
            assert_eq!(m.verify(&c, &r, 20, &o).unwrap().product(), &o.product);
            assert_eq!(o.product.useful_dense_macs, 1542 * n as u64);
            assert_eq!(o.product.padded_macs, 0);
        }
    }
    #[test]
    fn both_producers_have_identical_statements_for_every_batch_size() {
        for n in 1..=MAX_BATCH {
            let (m, c, r, packed) = observation(n);
            let (batch, _) = m.prepare_batch(&c, &r, 20).unwrap();
            let (selected, _) = m.observe_direct(&batch).unwrap();
            assert_eq!(selected, packed);
            let selected_verified = m.verify(&c, &r, 20, &selected).unwrap();
            let packed_verified = m.verify(&c, &r, 20, &packed).unwrap();
            assert_eq!(selected_verified.product(), packed_verified.product());
            assert_eq!(
                selected_verified.statement_commitment(),
                packed_verified.statement_commitment()
            );
        }
    }
    #[test]
    fn ties_use_lowest_index_and_empty_groups_do_no_work() {
        let (mut m, c, r) = fixture(64);
        m.router = [[0; DIM]; 3];
        let m = PreparedModel::new(m).unwrap();
        let (b, _) = m.prepare_batch(&c, &r, 20).unwrap();
        let (o, _) = m.observe(&b).unwrap();
        assert_eq!(o.product.routes, vec![0; 64]);
        assert_eq!(o.product.groups[1], Vec::<usize>::new());
        assert_eq!(o.product.nonempty_expert_groups, 1);
        assert_eq!(o.product.useful_dense_macs, 98688);
        assert!(m.verify(&c, &r, 20, &o).is_ok());
    }
    #[test]
    fn extreme_signed_values_and_merged_bounds_are_exact() {
        let (mut model, c, mut r) = fixture(1);
        model.base = [[32767; DIM]; 3];
        model.deltas = [[[32767; DIM]; 3]; 3];
        model.router = [[-32767; DIM]; 3];
        r[0].x = [8; DIM];
        let m = PreparedModel::new(model).unwrap();
        let (b, _) = m.prepare_batch(&c, &r, 20).unwrap();
        let (o, _) = m.observe(&b).unwrap();
        assert_eq!(o.product.logits[0], [MAX_MERGED_OUTPUT; 3]);
        assert!(m.verify(&c, &r, 20, &o).is_ok());
    }
    #[test]
    fn bound_and_bias_violations_refuse_before_execution() {
        let (m, c, r) = fixture(1);
        let mut bad = m.clone();
        bad.base[0][0] = 32768;
        assert!(PreparedModel::new(bad).is_err());
        let m = PreparedModel::new(m).unwrap();
        for k in [0, 256] {
            let mut bad = r.clone();
            bad[0].x[k] = if k == 256 { 1 } else { -9 };
            assert!(m.prepare_batch(&c, &bad, 20).is_err());
        }
        assert!(m.prepare_batch(&c, &[], 20).is_err());
        let (_, _, r) = fixture(65);
        assert!(m.prepare_batch(&c, &r, 20).is_err());
    }
    #[test]
    fn duplicate_request_identity_and_expired_or_future_requests_refuse() {
        let (m, c, r, _) = observation(2);
        let mut bad = r.clone();
        bad[1].id = bad[0].id;
        assert!(m.prepare_batch(&c, &bad, 20).is_err());
        for now in [0, 9, 1000, u64::MAX] {
            assert!(m.prepare_batch(&c, &r, now).is_err());
        }
        let mut bad = r;
        bad[0].arrival_ns = bad[0].deadline_ns;
        assert!(m.prepare_batch(&c, &bad, 1000).is_err());
    }
    #[test]
    fn every_external_context_and_request_field_binds_verification() {
        let (m, c, r, o) = observation(3);
        for index in 0..4 {
            let mut bad = c.clone();
            match index {
                0 => bad.chain[0] ^= 1,
                1 => bad.parent[0] ^= 1,
                2 => bad.challenge[0] ^= 1,
                _ => bad.batch_id[0] ^= 1,
            };
            assert!(m.verify(&bad, &r, 20, &o).is_err());
        }
        for index in 0..5 {
            let mut bad = r.clone();
            match index {
                0 => bad[0].id[0] ^= 1,
                1 => bad[0].scope[0] ^= 1,
                2 => bad[0].arrival_ns += 1,
                3 => bad[0].deadline_ns += 1,
                _ => bad[0].x[5] = 1,
            };
            assert!(m.verify(&c, &bad, 20, &o).is_err());
        }
        let mut bad = r.clone();
        bad.swap(0, 1);
        assert!(m.verify(&c, &bad, 20, &o).is_err());
        assert!(m.verify(&c, &r, 1000, &o).is_err());
    }
    #[test]
    fn mutated_router_group_output_and_accounting_are_rejected_even_if_rehashed() {
        let (m, c, r, o) = observation(6);
        for index in 0..10 {
            let mut bad = o.clone();
            match index {
                0 => bad.product.router_outputs[0][0] += 1,
                1 => bad.product.routes[0] = 2,
                2 => bad.product.groups[0].swap(0, 1),
                3 => bad.product.groups[0][0] = bad.product.groups[1][0],
                4 => bad.product.logits[0][0] += 1,
                5 => bad.product.predictions[0] = (bad.product.predictions[0] + 1) % 3,
                6 => bad.product.useful_dense_macs += 1,
                7 => bad.product.padded_macs = 1,
                8 => bad.product.nonempty_expert_groups = 0,
                _ => {
                    bad.product.groups[0].pop();
                }
            };
            bad.statement_commitment =
                statement_commitment(m.commitment, o.input_commitment, &c, &bad.product);
            assert!(m.verify(&c, &r, 20, &bad).is_err(), "mutation {index}");
        }
    }
    #[test]
    fn model_version_original_matrices_and_prepared_owner_are_bound() {
        let (model, c, r) = fixture(3);
        let m = PreparedModel::new(model.clone()).unwrap();
        let (b, _) = m.prepare_batch(&c, &r, 20).unwrap();
        let (o, _) = m.observe(&b).unwrap();
        for index in 0..4 {
            let mut bad = model.clone();
            match index {
                0 => bad.version[0] ^= 1,
                1 => bad.router[0][0] += 1,
                2 => {
                    bad.base[0][0] += 1;
                    for delta in &mut bad.deltas {
                        delta[0][0] -= 1;
                    }
                }
                _ => bad.deltas[2][0][0] += 1,
            };
            let other = PreparedModel::new(bad).unwrap();
            assert_ne!(m.commitment, other.commitment);
            assert!(other.verify(&c, &r, 20, &o).is_err());
            assert!(other.observe(&b).is_err());
            assert!(other.direct(&b).is_err());
        }
    }
    #[test]
    fn false_statement_or_input_commitments_cannot_yield_typed_product() {
        let (m, c, r, o) = observation(1);
        let mut bad = o.clone();
        bad.statement_commitment[0] ^= 1;
        assert!(m.verify(&c, &r, 20, &bad).is_err());
        bad = o.clone();
        bad.input_commitment[0] ^= 1;
        assert!(m.verify(&c, &r, 20, &bad).is_err());
        bad = o;
        bad.model_commitment[0] ^= 1;
        assert!(m.verify(&c, &r, 20, &bad).is_err());
    }

    #[test]
    fn factored_sampled_ranks_and_all_batch_sizes_preserve_statement_and_verifier() {
        for rank in [1, 3, MAX_FACTOR_RANK] {
            for n in 1..=MAX_BATCH {
                let (model, context, requests, adapters) = factor_fixture(rank, n);
                let prepared = PreparedModel::new(model).unwrap();
                let factors = prepared.prepare_factors(adapters).unwrap();
                let (batch, _) = prepared.prepare_batch(&context, &requests, 20).unwrap();
                let (actual, _, counts) = prepared.observe_factored(&batch, &factors).unwrap();
                let (direct, _) = prepared.observe_direct(&batch).unwrap();
                assert_eq!(actual, direct);
                assert_eq!(
                    prepared
                        .verify(&context, &requests, 20, &actual)
                        .unwrap()
                        .product(),
                    &actual.product
                );
                assert_eq!(factors.ranks(), [rank; EXPERTS]);
                assert_eq!(
                    factors.preparation_macs(),
                    (EXPERTS * CLASSES * rank * DIM) as u64
                );
                assert_eq!(counts.router_macs(), (n * CLASSES * DIM) as u64);
                assert_eq!(counts.base_macs(), (n * CLASSES * DIM) as u64);
                assert_eq!(counts.adapter_macs(), (n * rank * (DIM + CLASSES)) as u64);
                assert_eq!(counts.output_additions(), (n * CLASSES) as u64);
                // A narrow three-output matrix need not favor factor execution.
                assert_eq!(
                    counts.execution_macs(),
                    actual.product.useful_dense_macs + counts.adapter_macs()
                );
            }
        }
    }

    #[test]
    fn factored_preparation_rejects_invalid_rank_shape_and_coefficients() {
        let (model, _, _, adapters) = factor_fixture(1, 1);
        let prepared = PreparedModel::new(model).unwrap();
        for rank in [0, MAX_FACTOR_RANK + 1] {
            let mut invalid = adapters.clone();
            invalid[0].down = vec![[0; DIM]; rank];
            assert_eq!(
                prepared.prepare_factors(invalid).unwrap_err(),
                "FACTOR_RANK"
            );
        }
        let mut invalid = adapters.clone();
        invalid[0].up[0].clear();
        assert_eq!(
            prepared.prepare_factors(invalid).unwrap_err(),
            "FACTOR_SHAPE"
        );
        for up in [true, false] {
            let mut invalid = adapters.clone();
            if up {
                invalid[0].up[0][0] = i32::MAX;
            } else {
                invalid[0].down[0][0] = i32::MIN;
            }
            assert_eq!(
                prepared.prepare_factors(invalid).unwrap_err(),
                "FACTOR_COEFFICIENT"
            );
        }
    }

    #[test]
    fn factored_admission_checks_every_unobserved_model_coordinate() {
        let (model, _, _, mut adapters) = factor_fixture(1, 1);
        // The fixture inputs have zero at coordinate 17, but admission must not
        // rely on sampled outputs. Expert zero's up[0][0] is nonzero.
        adapters[0].down[0][17] += 1;
        let prepared = PreparedModel::new(model).unwrap();
        assert_eq!(
            prepared.prepare_factors(adapters).unwrap_err(),
            "FACTOR_NOT_SAME_DELTA"
        );
    }

    #[test]
    fn factored_model_version_and_original_coefficients_cannot_be_substituted() {
        let (model, context, requests, adapters) = factor_fixture(1, 3);
        let prepared = PreparedModel::new(model.clone()).unwrap();
        let factors = prepared.prepare_factors(adapters).unwrap();
        let (batch, _) = prepared.prepare_batch(&context, &requests, 20).unwrap();
        for index in 0..4 {
            let mut other = model.clone();
            match index {
                0 => other.version[0] ^= 1,
                1 => other.base[0][0] += 1,
                2 => other.router[0][0] += 1,
                _ => other.deltas[0][0][0] += 1,
            }
            let other = PreparedModel::new(other).unwrap();
            assert_eq!(
                other.factored(&batch, &factors).unwrap_err(),
                "PREPARED_MODEL"
            );
            let (other_batch, _) = other.prepare_batch(&context, &requests, 20).unwrap();
            assert_eq!(
                other.factored(&other_batch, &factors).unwrap_err(),
                "FACTOR_MODEL"
            );
        }
    }

    #[test]
    fn factored_reuse_still_requires_fresh_context_scope_and_deadline_binding() {
        let (model, context, requests, adapters) = factor_fixture(3, 2);
        let prepared = PreparedModel::new(model).unwrap();
        let factors = prepared.prepare_factors(adapters).unwrap();
        let (batch, _) = prepared.prepare_batch(&context, &requests, 20).unwrap();
        let (claim, _, _) = prepared.observe_factored(&batch, &factors).unwrap();
        for i in 0..4 {
            let mut next = context.clone();
            match i {
                0 => next.chain[0] ^= 1,
                1 => next.parent[0] ^= 1,
                2 => next.challenge[0] ^= 1,
                _ => next.batch_id[0] ^= 1,
            }
            let (next_batch, _) = prepared.prepare_batch(&next, &requests, 20).unwrap();
            let (next_claim, _, _) = prepared.observe_factored(&next_batch, &factors).unwrap();
            assert_eq!(next_claim.product, claim.product);
            assert_ne!(next_claim.statement_commitment, claim.statement_commitment);
            assert!(prepared.verify(&next, &requests, 20, &claim).is_err());
            assert!(prepared.verify(&next, &requests, 20, &next_claim).is_ok());
        }
        let mut other_scope = requests.clone();
        other_scope[0].scope[0] ^= 1;
        assert!(prepared.verify(&context, &other_scope, 20, &claim).is_err());
        assert!(prepared.verify(&context, &requests, 1000, &claim).is_err());
        assert!(prepared.prepare_batch(&context, &requests, 1000).is_err());
    }

    #[test]
    fn factored_large_cancelling_intermediates_are_exact_i64() {
        let (mut model, context, mut requests) = fixture(1);
        model.base = [[MAX_COEFFICIENT; DIM]; CLASSES];
        model.deltas = [[[0; DIM]; CLASSES]; EXPERTS];
        model.router = [[0; DIM]; CLASSES];
        requests[0].x = [MAX_INPUT; DIM];
        let adapters = std::array::from_fn(|_| AdapterFactors {
            up: std::array::from_fn(|_| {
                (0..MAX_FACTOR_RANK)
                    .map(|j| {
                        if j < MAX_FACTOR_RANK / 2 {
                            MAX_COEFFICIENT
                        } else {
                            -MAX_COEFFICIENT
                        }
                    })
                    .collect()
            }),
            down: vec![[MAX_COEFFICIENT; DIM]; MAX_FACTOR_RANK],
        });
        let prepared = PreparedModel::new(model).unwrap();
        let factors = prepared.prepare_factors(adapters).unwrap();
        let (batch, _) = prepared.prepare_batch(&context, &requests, 20).unwrap();
        let (claim, _, counts) = prepared.observe_factored(&batch, &factors).unwrap();
        assert_eq!(claim.product.logits, vec![[MAX_MERGED_OUTPUT / 2; CLASSES]]);
        assert_eq!(claim.product.routes, [0]);
        assert_eq!(claim.product.nonempty_expert_groups, 1);
        assert_eq!(
            counts.adapter_macs(),
            (MAX_FACTOR_RANK * (DIM + CLASSES)) as u64
        );
        assert!(prepared.verify(&context, &requests, 20, &claim).is_ok());
        assert_eq!(
            checked_factor_mac(0, i64::MAX, 2),
            Err("FACTOR_ARITHMETIC_OVERFLOW")
        );
        assert_eq!(
            checked_factor_mac(i64::MAX, 1, 1),
            Err("FACTOR_ARITHMETIC_OVERFLOW")
        );
    }

    #[test]
    fn factored_preparation_owns_immutable_factors_and_reports_only_selected_costs() {
        let (mut model, context, requests, mut adapters) = factor_fixture(1, 1);
        model.router = [[0; DIM]; CLASSES];
        // Extend unselected expert two from rank one to rank eight with zero
        // columns. Admission charges all eight; route zero executes rank one.
        adapters[2].down.resize(MAX_FACTOR_RANK, [0; DIM]);
        for up in &mut adapters[2].up {
            up.resize(MAX_FACTOR_RANK, 0);
        }
        let prepared = PreparedModel::new(model).unwrap();
        let factors = prepared.prepare_factors(adapters.clone()).unwrap();
        adapters[0].down[0][0] += 1;
        let (batch, _) = prepared.prepare_batch(&context, &requests, 20).unwrap();
        let (claim, _, counts) = prepared.observe_factored(&batch, &factors).unwrap();
        assert_eq!(factors.ranks(), [1, 1, MAX_FACTOR_RANK]);
        assert_eq!(
            factors.preparation_macs(),
            ((2 + MAX_FACTOR_RANK) * CLASSES * DIM) as u64
        );
        assert_eq!(counts.adapter_macs(), (DIM + CLASSES) as u64);
        assert!(prepared.verify(&context, &requests, 20, &claim).is_ok());
    }
}
