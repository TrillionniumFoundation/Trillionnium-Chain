//! Source-pinned research instrumentation. No production configuration is changed.
//! Counters measure evaluations by this verifier, never an adversary query bound.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bincode::Options;
use p3_air::{Air, BaseAir};
use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, DuplexChallenger, FieldChallenger, GrindingChallenger,
};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{BasedVectorSpace, Field, PackedValue, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::default_goldilocks_poseidon2_8;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{
    CryptographicPermutation, MerkleCap, PaddingFreeSponge, Permutation, TruncatedPermutation,
};
use p3_uni_stark::{
    Proof, QuotientAir, StarkConfig, VerifierConstraintFolder, setup_preprocessed,
    verify_with_preprocessed,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use w1_full_public_stark_research::arith_carry_air::{Dot8CarryAir, Dot8PackedCarryAir};
use w1_full_public_stark_research::proof_config::{
    Challenge, LOG_BLOWUP, LOG_FINAL_POLY_LEN, MAX_LOG_ARITY, NUM_QUERIES, Perm, RESEARCH_DOMAIN,
    Config as NativeConfig, Val, W1Proof, config,
};
use w1_full_public_stark_research::proof_wire::{Component, limits, scan_proof};
use w1_full_public_stark_research::public::{Expected, PUBLIC_BYTES, PublicStatement};
use w1_full_public_stark_research::sha_air::W1ShaAir;
use w1_full_public_stark_research::sha_plan::HEADER_BYTES;

#[derive(Clone)]
struct CountPerm {
    inner: Perm,
    evaluations: Arc<AtomicU64>,
}

impl<T> Permutation<[T; 8]> for CountPerm
where
    T: PackedValue<Value = Val>,
    Perm: Permutation<[T; 8]>,
{
    fn permute_mut(&self, input: &mut [T; 8]) {
        // Include every SIMD lane, including padding. Repeated inputs are counted again.
        self.evaluations.fetch_add(T::WIDTH as u64, Ordering::Relaxed);
        self.inner.permute_mut(input);
    }
}

impl<T> CryptographicPermutation<[T; 8]> for CountPerm
where
    T: PackedValue<Value = Val>,
    Perm: CryptographicPermutation<[T; 8]>,
{
}

#[derive(Clone, Debug, Serialize)]
struct Op {
    kind: &'static str,
    fields: usize,
}

#[derive(Clone, Debug, Default)]
struct Tape {
    observed: usize,
    sampled: usize,
    ops: Vec<Op>,
    samples: Vec<Vec<u64>>,
    indices: Vec<(usize, usize)>,
    pow_checks: Vec<usize>,
    stream: Sha256,
}

impl Tape {
    fn op(&mut self, kind: &'static str, fields: usize) {
        if fields == 0 {
            return;
        }
        if let Some(last) = self.ops.last_mut().filter(|last| last.kind == kind) {
            last.fields += fields;
        } else {
            self.ops.push(Op { kind, fields });
        }
    }

    fn report(&self) -> Value {
        json!({
            "observed_base_fields":self.observed,
            "sampled_base_fields_including_index_samples":self.sampled,
            "operations":self.ops,"sampled_values":self.samples,
            "index_samples":self.indices,"pow_check_bits":self.pow_checks,
            "diagnostic_stream_sha256":hex::encode(self.stream.clone().finalize())
        })
    }
}

#[derive(Clone)]
struct CountChallenger {
    inner: DuplexChallenger<Val, CountPerm, 8, 4>,
    tape: Arc<Mutex<Tape>>,
}

impl CanObserve<Val> for CountChallenger {
    fn observe(&mut self, value: Val) {
        {
            let mut tape = self.tape.lock().expect("instrumentation lock");
            tape.observed += 1;
            tape.op("absorb", 1);
            tape.stream.update([0]);
            tape.stream.update(value.as_canonical_u64().to_le_bytes());
        }
        self.inner.observe(value);
    }
}

impl CanObserve<MerkleCap<Val, [Val; 4]>> for CountChallenger {
    fn observe(&mut self, cap: MerkleCap<Val, [Val; 4]>) {
        for root in cap.roots() {
            for value in root {
                self.observe(*value);
            }
        }
    }
}

impl<E: BasedVectorSpace<Val>> CanSample<E> for CountChallenger {
    fn sample(&mut self) -> E {
        let value: E = self.inner.sample();
        let fields: Vec<u64> = value
            .as_basis_coefficients_slice()
            .iter()
            .map(PrimeField64::as_canonical_u64)
            .collect();
        let mut tape = self.tape.lock().expect("instrumentation lock");
        tape.sampled += fields.len();
        tape.op("squeeze", fields.len());
        for field in &fields {
            tape.stream.update([1]);
            tape.stream.update(field.to_le_bytes());
        }
        tape.samples.push(fields);
        value
    }
}

impl CanSampleBits<usize> for CountChallenger {
    fn sample_bits(&mut self, bits: usize) -> usize {
        let value = self.inner.sample_bits(bits);
        let mut tape = self.tape.lock().expect("instrumentation lock");
        // The pinned implementation consumes exactly one base-field sample.
        tape.sampled += 1;
        tape.op("squeeze", 1);
        tape.indices.push((bits, value));
        tape.stream.update([2]);
        tape.stream.update((bits as u64).to_le_bytes());
        tape.stream.update((value as u64).to_le_bytes());
        value
    }
}

impl FieldChallenger<Val> for CountChallenger {}

impl GrindingChallenger for CountChallenger {
    type Witness = Val;

    fn grind(&mut self, bits: usize) -> Val {
        // Verification never invokes this. Forwarding keeps the implementation real.
        self.inner.grind(bits)
    }

    fn check_witness(&mut self, bits: usize, witness: Val) -> bool {
        self.tape.lock().expect("instrumentation lock").pow_checks.push(bits);
        self.inner.check_witness(bits, witness)
    }
}

type Hash = PaddingFreeSponge<CountPerm, 8, 4, 4>;
type Compress = TruncatedPermutation<CountPerm, 2, 4, 8>;
type Mmcs = MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hash, Compress, 2, 4>;
type ExtMmcs = ExtensionMmcs<Val, Challenge, Mmcs>;
type Pcs = TwoAdicFriPcs<Val, Radix2DitParallel<Val>, Mmcs, ExtMmcs>;
type Config = StarkConfig<Pcs, Challenge, CountChallenger>;
type CountProof = Proof<Config>;

#[derive(Clone)]
struct Audit {
    counts: [Arc<AtomicU64>; 3],
    tape: Arc<Mutex<Tape>>,
}

impl Audit {
    fn snapshot(&self) -> [u64; 3] {
        self.counts.each_ref().map(|x| x.load(Ordering::Relaxed))
    }
}

fn counted_config(component: u32) -> (Config, Audit) {
    assert!((1..=4).contains(&component));
    let inner = default_goldilocks_poseidon2_8();
    let counts: [Arc<AtomicU64>; 3] = std::array::from_fn(|_| Arc::new(AtomicU64::new(0)));
    let permutations: [CountPerm; 3] = std::array::from_fn(|i| CountPerm {
        inner: inner.clone(), evaluations: counts[i].clone(),
    });
    let mmcs = Mmcs::new(Hash::new(permutations[0].clone()), Compress::new(permutations[1].clone()), 0);
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP, log_final_poly_len: LOG_FINAL_POLY_LEN,
        max_log_arity: MAX_LOG_ARITY, num_queries: NUM_QUERIES,
        batch_proof_of_work_bits: 0, commit_proof_of_work_bits: 0, query_proof_of_work_bits: 0,
        mmcs: ExtMmcs::new(mmcs.clone()),
    };
    let pcs = Pcs::new(Radix2DitParallel::default(), mmcs, fri);
    let tape = Arc::new(Mutex::new(Tape::default()));
    let mut challenger = CountChallenger {
        inner: DuplexChallenger::new(permutations[2].clone()), tape: tape.clone(),
    };
    challenger.observe(Val::from_u32(RESEARCH_DOMAIN.len() as u32));
    for &byte in RESEARCH_DOMAIN { challenger.observe(Val::from_u8(byte)); }
    challenger.observe(Val::from_u32(component));
    (Config::new(pcs, challenger).with_ood_proof_of_work_bits(0).with_lookup_proof_of_work_bits(0), Audit { counts, tape })
}

fn difference(after: [u64; 3], before: [u64; 3]) -> Value {
    let d: [u64; 3] = std::array::from_fn(|i| after[i] - before[i]);
    json!({"leaf_sponge":d[0],"branch_compressor":d[1],"transcript":d[2],"shared_total":d.iter().sum::<u64>()})
}

fn sha256(data: &[u8]) -> String { hex::encode(Sha256::digest(data)) }

fn read_exact(path: &str, size: usize) -> Result<Vec<u8>, String> {
    if fs::metadata(path).map_err(|e| e.to_string())?.len() != size as u64 { return Err("file size mismatch".into()); }
    let bytes=fs::read(path).map_err(|e| e.to_string())?;
    if bytes.len()!=size { return Err("file changed while reading".into()); }
    Ok(bytes)
}

fn write_new(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut f=OpenOptions::new().write(true).create_new(true).open(path).map_err(|e|e.to_string())?;
    f.write_all(data).map_err(|e|e.to_string())?;
    f.sync_all().map_err(|e|e.to_string())
}

fn mutate(proof: &mut W1Proof, name: &str, value: Val) {
    match name {
        "ood" => proof.ood_pow_witness = value,
        "batch" => proof.opening_proof.batch_pow_witness = value,
        "commit-first" => proof.opening_proof.commit_pow_witnesses[0] = value,
        "commit-last" => *proof.opening_proof.commit_pow_witnesses.last_mut().expect("FRI rounds") = value,
        "query" => proof.opening_proof.query_pow_witness = value,
        _ => panic!("unknown research mutation"),
    }
}

fn audit<A>(air: &A, component: u32, wire: Component, degree_bits: usize, bytes: &[u8], out: &Path) -> Result<Value,String>
where
    A: BaseAir<Val> + QuotientAir<Config> + QuotientAir<NativeConfig>
        + for<'a> Air<VerifierConstraintFolder<'a, Config>>
        + for<'a> Air<VerifierConstraintFolder<'a, NativeConfig>>,
{
    scan_proof(bytes,wire).map_err(|e|e.to_string())?;
    let codec=bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
        .with_limit(limits(wire).maximum_bytes as u64);
    let mut native: W1Proof=codec.deserialize(&bytes[8..]).map_err(|e|e.to_string())?;
    let counted: CountProof=codec.deserialize(&bytes[8..]).map_err(|e|e.to_string())?;
    if native.degree_bits!=degree_bits || counted.degree_bits!=degree_bits { return Err("degree mismatch".into()); }
    if codec.serialize(&native).map_err(|e|e.to_string())? != bytes[8..]
        || codec.serialize(&counted).map_err(|e|e.to_string())? != bytes[8..] {
        return Err("instrumentation changed proof serialization".into());
    }
    let native_config=config(component);
    let (pp,native_vk)=setup_preprocessed(&native_config,air,degree_bits)
        .map_err(|e|format!("native preprocessing: {e:?}"))?.ok_or("preprocessing missing")?;
    drop(pp);
    verify_with_preprocessed(&native_config,air,&native,&[],Some(&native_vk))
        .map_err(|e|format!("native positive verification: {e:?}"))?;
    let (cfg,record)=counted_config(component);
    let seeded=record.snapshot();
    let (pp,vk)=setup_preprocessed(&cfg,air,degree_bits)
        .map_err(|e|format!("counted preprocessing: {e:?}"))?.ok_or("preprocessing missing")?;
    drop(pp);
    let preprocessed=record.snapshot();
    if codec.serialize(&vk.commitment).map_err(|e|e.to_string())?
        != codec.serialize(&native_vk.commitment).map_err(|e|e.to_string())? {
        return Err("counting changed preprocessed commitment".into());
    }
    verify_with_preprocessed(&cfg,air,&counted,&[],Some(&vk))
        .map_err(|e|format!("counted positive verification: {e:?}"))?;
    let verified=record.snapshot();
    let tape=record.tape.lock().expect("instrumentation lock").report();
    // A repeat verifies exact transcript determinism while keeping lifecycle calls separate.
    let first_tape=record.tape.lock().expect("instrumentation lock").clone();
    *record.tape.lock().expect("instrumentation lock")=Tape::default();
    verify_with_preprocessed(&cfg,air,&counted,&[],Some(&vk))
        .map_err(|e|format!("counted repeated verification: {e:?}"))?;
    let repeated=record.snapshot();
    let repeated_tape=record.tape.lock().expect("instrumentation lock").clone();
    if first_tape.samples!=repeated_tape.samples || first_tape.indices!=repeated_tape.indices {
        return Err("repeated verification changed challenge values".into());
    }
    if difference(verified,preprocessed)!=difference(repeated,verified) {
        return Err("repeated verification changed permutation counts".into());
    }
    let mut negative_controls=Vec::new();
    for name in ["ood","batch","commit-first","commit-last","query"] {
        mutate(&mut native,name,Val::ONE);
        let mut mutated=bytes[..8].to_vec();
        mutated.extend(codec.serialize(&native).map_err(|e|e.to_string())?);
        let structural=scan_proof(&mutated,wire).is_ok();
        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_with_preprocessed(&native_config,air,&native,&[],Some(&native_vk))
        }));
        let error=match result {
            Ok(Err(error))=>format!("{error:?}"),
            Ok(Ok(()))=>return Err(format!("zero-PoW nonzero witness unexpectedly accepted: {name}")),
            Err(_)=>return Err(format!("negative verification panicked: {name}")),
        };
        if !structural { return Err(format!("mutation no longer isolates cryptographic canonicality: {name}")); }
        let file=format!("{name}-one.proof.bin");
        write_new(&out.join(&file),&mutated)?;
        let changed_offsets: Vec<usize>=bytes.iter().zip(&mutated).enumerate()
            .filter_map(|(i,(a,b))|(a!=b).then_some(i)).collect();
        negative_controls.push(json!({"field":name,"value":1,"bytes":mutated.len(),
            "sha256":sha256(&mutated),"file":file,"changed_byte_offsets":changed_offsets,
            "structural_admission":true,"native_rejected":true,"panic":false,"error":error}));
        mutate(&mut native,name,Val::ZERO);
    }
    Ok(json!({
        "schema":"trnm-w1-native-lifecycle-probe-v1","qualification":"HOLD_NO_GO",
        "source_base":"cc836dfc13ef0006eb0878abd8cb5eca9a76bec0","component":component,
        "degree_bits":degree_bits,"fri_rounds":native.opening_proof.commit_pow_witnesses.len(),
        "proof_bytes":bytes.len(),"proof_sha256":sha256(bytes),
        "native_positive_verified":true,"instrumented_positive_verified":true,
        "instrumented_serialization_identical":true,"preprocessed_commitment_identical":true,
        "repeated_challenge_values_identical":true,"repeated_evaluation_counts_identical":true,
        "permutation_evaluations":{
            "config_initialization":difference(seeded,[0;3]),
            "independent_preprocessing":difference(preprocessed,seeded),
            "one_verification":difference(verified,preprocessed),
            "cold_verification_total":difference(verified,[0;3]),
            "same_proof_reverification":difference(repeated,verified)},
        "transcript_including_initialization":tape,"negative_controls":negative_controls,
        "counter_semantics":"total scalar-equivalent evaluations, including repeated inputs and SIMD padding; all three roles share one permutation",
        "adversary_query_upper_bound":null,"concrete_noninteractive_bits":null,
        "quantum_bits":null,"proves_new_false_statement_attack":false
    }))
}

fn run(args: &[String]) -> Result<Value,String> {
    if args.len()!=6 { return Err("lifecycle_probe COMPONENT STATEMENT EXPECTED_HEADER EXPECTED_ARTIFACTS PROOF OUTPUT_DIR".into()); }
    let statement_bytes=read_exact(&args[1],PUBLIC_BYTES)?;
    let statement=PublicStatement::decode(&statement_bytes).map_err(str::to_owned)?;
    let header=read_exact(&args[2],HEADER_BYTES)?;
    let artifacts=read_exact(&args[3],64)?;
    let expected=Expected::from_bytes(&header,&artifacts).map_err(str::to_owned)?;
    let (sha_plan,arith)=statement.plans(&expected)?;
    let (component,wire,degree)=match args[0].as_str() {
        "sha"=>(1,Component::Sha,13),
        "arithmetic"=>(2,Component::Arithmetic,17),
        "carry"=>(3,Component::Carry,17),
        "packed"=>(4,Component::PackedCarry,14),
        _=>return Err("unknown fixed profile".into()),
    };
    let proof_len=fs::metadata(&args[4]).map_err(|e|e.to_string())?.len();
    if proof_len>limits(wire).maximum_bytes as u64 { return Err("proof exceeds fixed shape limit".into()); }
    let bytes=read_exact(&args[4],proof_len as usize)?;
    let out=Path::new(&args[5]);
    fs::create_dir(out).map_err(|e|format!("new evidence directory: {e}"))?;
    let mut report=match component {
        1=>audit(&W1ShaAir::public_only(&sha_plan),component,wire,degree,&bytes,out)?,
        2=>audit(&arith,component,wire,degree,&bytes,out)?,
        3=>audit(&Dot8CarryAir::new(arith.rows().to_vec()).map_err(str::to_owned)?,component,wire,degree,&bytes,out)?,
        4=>audit(&Dot8PackedCarryAir::new(arith.rows().to_vec()).map_err(str::to_owned)?,component,wire,degree,&bytes,out)?,
        _=>unreachable!("profile checked above"),
    };
    report["statement_sha256"]=sha256(&statement_bytes).into();
    report["expected_header_sha256"]=sha256(&header).into();
    report["expected_artifacts_sha256"]=sha256(&artifacts).into();
    write_new(&out.join("receipt.json"),serde_json::to_string_pretty(&report).map_err(|e|e.to_string())?.as_bytes())?;
    Ok(report)
}

fn main() {
    match run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(report)=>println!("{report}"),
        Err(error)=>{
            println!("{}",json!({"schema":"trnm-w1-native-lifecycle-probe-v1","status":"FAILED","error":error,"qualification":"HOLD_NO_GO"}));
            std::process::exit(1);
        }
    }
}
