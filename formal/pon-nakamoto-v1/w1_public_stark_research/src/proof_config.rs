//! Fixed research-only PCS/FRI configuration and conditional RBR metadata.
//!
//! The native W1 relation still uses fully constrained SHA-256. Poseidon2 is
//! the separate commitment/transcript primitive of this research proof system.
//! No untrusted proof field selects or weakens these parameters.

use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, BaseAir};
use p3_challenger::{CanObserve, DuplexChallenger};
use p3_commit::{ExtensionMmcs, Pcs as PcsTrait};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_8};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_security::fri::FriRegime;
use p3_security::shape::{InstanceShape, StarkAirParams};
use p3_security::stark::proven_security_report;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{
    ConjecturedSecurity, GrindingSites, OpeningShape, Proof, StarkConfig, StarkGenericConfig,
    StarkSecurityParams,
};
use serde_json::{Value, json};

use crate::arith_air::Dot8Air;
use crate::arith_carry_air::{Dot8CarryAir, Dot8PackedCarryAir};
use crate::sha_air::W1ShaAir;

pub type Val = Goldilocks;
pub type Challenge = BinomialExtensionField<Val, 2>;
pub type Perm = Poseidon2Goldilocks<8>;
pub type Hasher = PaddingFreeSponge<Perm, 8, 4, 4>;
pub type Compressor = TruncatedPermutation<Perm, 2, 4, 8>;
pub type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hasher, Compressor, 2, 4>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Challenger = DuplexChallenger<Val, Perm, 8, 4>;
pub type Dft = Radix2DitParallel<Val>;
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
pub type W1Proof = Proof<Config>;

pub const SHA_COMPONENT: u32 = 1;
pub const ARITH_COMPONENT: u32 = 2;
/// New transcript component for the carry AIR; original proofs retain domain 2.
pub const CARRY_COMPONENT: u32 = 3;
/// Five-lane carry packing has its own fixed transcript component.
pub const PACKED_CARRY_COMPONENT: u32 = 4;
pub const RESEARCH_DOMAIN: &[u8] = b"TRNM-W1-FULL-PUBLIC-STARK-RESEARCH-P3-0.8.0-R1\0";
pub const LOG_BLOWUP: usize = 2;
pub const LOG_FINAL_POLY_LEN: usize = 0;
pub const MAX_LOG_ARITY: usize = 1;
pub const NUM_QUERIES: usize = 64;
pub const GOLDILOCKS_ORDER: u64 = 18_446_744_069_414_584_321;

// These are assumptions/rounding conventions for the estimator, not evidence
// of a concrete Poseidon2 reduction or a complete noninteractive theorem.
const CONSERVATIVE_MODULUS_BITS: usize = 127;
const ASSUMED_HASH_COLLISION_BITS: usize = 128;

fn fri_regime() -> FriRegime {
    FriRegime {
        log_blowup: LOG_BLOWUP,
        num_queries: NUM_QUERIES,
        log_final_poly_len: LOG_FINAL_POLY_LEN,
        max_log_arity: MAX_LOG_ARITY,
        commit_pow_bits: 0,
        query_pow_bits: 0,
    }
}

/// Construct the sole research parameter profile. Only the four fixed
/// components are admitted; component selection changes domain separation,
/// never the field, hash, query count, blowup, or grinding settings.
pub fn config(component: u32) -> Config {
    assert!(matches!(
        component,
        SHA_COMPONENT | ARITH_COMPONENT | CARRY_COMPONENT | PACKED_CARRY_COMPONENT
    ));
    let perm = default_goldilocks_poseidon2_8();
    let hash = Hasher::new(perm.clone());
    let compress = Compressor::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: LOG_FINAL_POLY_LEN,
        max_log_arity: MAX_LOG_ARITY,
        num_queries: NUM_QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    let mut challenger = Challenger::new(perm);
    // One canonical base-field element per byte; fixed length prefix and
    // fixed-width component prevent ambiguity at this application boundary.
    challenger.observe(Val::from_u32(RESEARCH_DOMAIN.len() as u32));
    for &byte in RESEARCH_DOMAIN {
        challenger.observe(Val::from_u8(byte));
    }
    challenger.observe(Val::from_u32(component));
    Config::new(pcs, challenger)
        .with_ood_proof_of_work_bits(0)
        .with_lookup_proof_of_work_bits(0)
}

fn component_security<A>(air: &A, height: usize, component: u32, max_combo: usize) -> Value
where
    A: BaseAir<Val> + Air<SymbolicAirBuilder<Val, Challenge>>,
{
    assert!(height.is_power_of_two());
    let cfg = config(component);
    assert_eq!(cfg.is_zk(), 0);
    assert_eq!(cfg.ood_proof_of_work_bits(), 0);
    assert_eq!(cfg.lookup_proof_of_work_bits(), 0);
    // Be explicit about preprocessing widths. These AIRs have no lookups or
    // permutation columns, and their public tables must not disappear from
    // symbolic constraint counting or PCS opening-batch accounting.
    let layout = AirLayout {
        main_width: air.width(),
        preprocessed_width: air.preprocessed_width(),
        num_public_values: air.num_public_values(),
        num_periodic_columns: air.num_periodic_columns(),
        ..Default::default()
    };
    let domain =
        <Pcs as PcsTrait<Challenge, Challenger>>::natural_domain_for_degree(cfg.pcs(), height);
    let params = StarkSecurityParams::from_air::<Val, Challenge, A>(
        fri_regime(),
        air,
        layout,
        domain,
        CONSERVATIVE_MODULUS_BITS,
        ASSUMED_HASH_COLLISION_BITS,
        max_combo,
        OpeningShape::new(),
        GrindingSites::NONE,
    );
    let degree_bits = height.ilog2() as usize;
    let air_shape = StarkAirParams {
        num_constraints: params.num_constraints,
        max_constraint_degree: params.air_max_constraint_degree,
        num_quotient_chunks: params.num_quotient_chunks,
        max_combo: params.max_combo,
    };
    let instance_shape = InstanceShape {
        log_trace_length: degree_bits,
        modulus_bits: params.num_modulus_bits,
        collision_resistance: params.collision_resistance,
        num_batched_functions: params.num_batched_functions,
    };
    let report = proven_security_report(
        &fri_regime(),
        &air_shape,
        &instance_shape,
        &[],
        &params.grinding,
    );
    let conjectured = ConjecturedSecurity::compute_from_params(&params, degree_bits);
    json!({
        "component": component,
        "trace_height": height,
        "degree_bits": degree_bits,
        "main_width": layout.main_width,
        "preprocessed_width": layout.preprocessed_width,
        "main_next_row_columns": air.main_next_row_columns(),
        "preprocessed_next_row_columns": air.preprocessed_next_row_columns(),
        "num_constraints": params.num_constraints,
        "air_max_constraint_degree": params.air_max_constraint_degree,
        "num_quotient_chunks": params.num_quotient_chunks,
        "max_combo": params.max_combo,
        "num_batched_functions": params.num_batched_functions,
        "modulus_bits_conservative_lower_bound": params.num_modulus_bits,
        "hash_collision_bits_assumption": params.collision_resistance,
        "conditional_rbr_estimate_bits": report.security_bits(),
        "conditional_rbr_report": report,
        "conjectured_estimate_bits_separate": conjectured.security_bits,
        "is_complete_noninteractive_bound": false,
        "is_quantum_security_bound": false
    })
}

/// Inspect the actual AIR constraints and PCS layout. This is a named-term
/// conditional round-by-round estimate, not an end-to-end ROM/QROM bound.
fn metadata<A>(sha: &W1ShaAir, arith: &A, arith_height: usize, arithmetic_component: u32) -> Value
where
    A: BaseAir<Val> + Air<SymbolicAirBuilder<Val, Challenge>>,
{
    let cardinality = u128::from(GOLDILOCKS_ORDER) * u128::from(GOLDILOCKS_ORDER);
    json!({
        "schema": "w1-p3-0.8.0-conditional-rbr-metadata-v1",
        "qualification": "HOLD_NO_GO",
        "p3_version": "0.8.0",
        "native_relation_hash": "SHA-256, fully constrained by the SHA AIR",
        "commitment_and_challenger": "default Goldilocks Poseidon2 width 8",
        "sponge": {"width": 8, "rate": 4, "output": 4, "padding": "PaddingFreeSponge, fixed-shape MMCS inputs only"},
        "compression": {"inputs": 2, "digest_elements": 4, "width": 8},
        "mmcs": {"arity": 2, "digest_elements": 4, "cap_height": 0},
        "field_modulus": GOLDILOCKS_ORDER.to_string(),
        "challenge_extension": "X^2 - 7",
        "challenge_field_cardinality": cardinality.to_string(),
        "estimator_modulus_bits": CONSERVATIVE_MODULUS_BITS,
        "estimator_modulus_bits_reason": "P^2 >= 2^127; using 128 as an exact denominator would round the field cardinality upward",
        "research_domain_hex": hex::encode(RESEARCH_DOMAIN),
        "component_domains": {"sha": SHA_COMPONENT, "arithmetic": arithmetic_component},
        "fri": {"log_blowup": LOG_BLOWUP, "log_final_poly_len": LOG_FINAL_POLY_LEN,
            "max_log_arity": MAX_LOG_ARITY, "num_queries": NUM_QUERIES,
            "batch_pow_bits": 0, "commit_pow_bits": 0, "query_pow_bits": 0,
            "ood_pow_bits": 0, "lookup_pow_bits": 0},
        "zero_knowledge": false,
        "public_statement_is_succinct": false,
        "complete_noninteractive_bound": "UNRESOLVED: requires concrete transcript/sampling, PCS binding and ROM compilation analysis",
        "hash_strength_status": "128-bit collision resistance is an explicit model assumption, not independently certified here",
        "sha": component_security(sha, sha.trace_height(), SHA_COMPONENT, 2),
        "arithmetic": component_security(arith, arith_height, arithmetic_component, 1)
    })
}

/// Original quotient/remainder AIR metadata, preserving its transcript domain.
pub fn security_metadata(sha: &W1ShaAir, arith: &Dot8Air) -> Value {
    metadata(sha, arith, arith.trace_height(), ARITH_COMPONENT)
}

/// Carry-AIR metadata from its actual symbolic constraints and fixed PCS shape.
/// The complete noninteractive and quantum security qualifications remain open.
pub fn carry_security_metadata(sha: &W1ShaAir, arith: &Dot8CarryAir) -> Value {
    let mut report = metadata(sha, arith, arith.trace_height(), CARRY_COMPONENT);
    report["schema"] = "w1-p3-0.8.0-conditional-rbr-carry-metadata-v2".into();
    report
}

/// Five-lane packing retains every relation row and changes the fixed PCS shape.
pub fn packed_carry_security_metadata(sha: &W1ShaAir, arith: &Dot8PackedCarryAir) -> Value {
    let mut report = metadata(sha, arith, arith.trace_height(), PACKED_CARRY_COMPONENT);
    report["schema"] = "w1-p3-0.8.0-conditional-rbr-packed-carry-metadata-v3".into();
    report["arithmetic"]["lanes_per_row"] = 5.into();
    report["arithmetic"]["real_dot8_rows"] = arith.real_rows().into();
    report
}
