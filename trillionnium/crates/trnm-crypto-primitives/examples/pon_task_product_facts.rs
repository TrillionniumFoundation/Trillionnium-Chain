//! Fixed complete-relation verification service experiment; never a mining game.
//! Per-operation wall observations and outer whole-process CPU are different scopes.
use sha2::{Digest, Sha256};
use std::{hint::black_box, io::Write, time::Instant};
use trnm_crypto_primitives::pon_work::{
    self,
    task_product_facts::{ProductObservation, ProductPublication, TaskProductFactCache},
    Hash, VerificationProgress, VerifiedWork, CELLS, N, PROOF_BYTES, Q,
};

const SCHEMA: &str = "pon-w1-task-product-facts-research-v1";
const FAMILIES: [&str; 6] = ["zero", "identity", "rank1", "sparse", "near_q", "dense"];
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn seed() -> Result<u64> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 || args[0] != "--seed" {
        return Err("EXPECTED_SEED_OPTION".into());
    }
    match args[1].as_str() {
        "8101" => Ok(8101),
        "8102" => Ok(8102),
        _ => Err("UNREGISTERED_SEED".into()),
    }
}
fn emit(output: &mut impl Write, line: &str) -> Result<()> {
    writeln!(output, "{line}")?;
    output.flush()?;
    Ok(())
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn material(seed: u64, family: &str) -> Result<(Vec<u32>, Vec<u32>)> {
    let mut a = vec![0; CELLS];
    let mut b = vec![0; CELLS];
    for i in 0..N {
        for j in 0..N {
            let at = i * N + j;
            (a[at], b[at]) = match family {
                "zero" => (0, 0),
                "identity" => (u32::from(i == j), u32::from(i == j)),
                "rank1" => (((i + 1) * (j + 3)) as u32, ((i * 7 + j * 11) % 37) as u32),
                "sparse" => (
                    if at.is_multiple_of(19) {
                        Q as u32 - 1
                    } else {
                        0
                    },
                    if at.is_multiple_of(23) {
                        Q as u32 - 2
                    } else {
                        0
                    },
                ),
                "near_q" => (Q as u32 - 1, Q as u32 - 2),
                "dense" => {
                    let bytes = pon_work::hash(
                        b"task-product-facts-material-v1",
                        &[&seed.to_le_bytes(), &(at as u64).to_le_bytes()],
                    );
                    let x = u32::from_le_bytes(bytes[..4].try_into()?);
                    let y = u32::from_le_bytes(bytes[4..8].try_into()?);
                    ((u128::from(x) % Q) as u32, (u128::from(y) % Q) as u32)
                }
                _ => return Err("UNKNOWN_MATERIAL".into()),
            };
        }
    }
    Ok((a, b))
}
#[derive(Default)]
struct Progress {
    before_replay: u64,
    noise: u64,
    matrix_rows_before_product: u64,
    transcript_tiles: u64,
    before_product: u64,
    matrix_rows_after_product: u64,
    before_verified_work: u64,
}
impl Progress {
    fn add(&mut self, point: VerificationProgress) {
        match point {
            VerificationProgress::BeforeReplay => self.before_replay += 1,
            VerificationProgress::Noise { .. } => self.noise += 1,
            VerificationProgress::MatrixRow { .. } if self.before_product == 0 => {
                self.matrix_rows_before_product += 1
            }
            VerificationProgress::MatrixRow { .. } => self.matrix_rows_after_product += 1,
            VerificationProgress::TranscriptTile { .. } => self.transcript_tiles += 1,
            VerificationProgress::BeforeProduct => self.before_product += 1,
            VerificationProgress::BeforeVerifiedWork => self.before_verified_work += 1,
        }
    }
    fn json(&self) -> String {
        format!("{{\"before_replay\":{},\"noise\":{},\"matrix_rows_before_product\":{},\"transcript_tiles\":{},\"before_product\":{},\"matrix_rows_after_product\":{},\"before_verified_work\":{}}}",self.before_replay,self.noise,self.matrix_rows_before_product,self.transcript_tiles,self.before_product,self.matrix_rows_after_product,self.before_verified_work)
    }
}
fn observation_json(o: &ProductObservation) -> String {
    let publication = match o.publication {
        ProductPublication::None => "none",
        ProductPublication::Stored => "stored",
        ProductPublication::Existing => "existing",
        ProductPublication::Contended => "contended",
    };
    format!("{{\"lookup_probes\":{},\"lookup_contended\":{},\"exact_inputs_found\":{},\"product_reused\":{},\"transcript_entered\":{},\"transcript_completed\":{},\"product_reconstruction_entered\":{},\"product_reconstruction_completed\":{},\"publication_probes\":{},\"publication\":\"{}\"}}",o.lookup_probes,o.lookup_contended,o.exact_inputs_found,o.product_reused,o.transcript_entered,o.transcript_completed,o.product_reconstruction_entered,o.product_reconstruction_completed,o.publication_probes,publication)
}
fn same(actual: &VerifiedWork, reference: &VerifiedWork) -> Result<()> {
    if actual.challenge() != reference.challenge()
        || actual.task() != reference.task()
        || actual.ticket() != reference.ticket()
        || actual.product() != reference.product()
    {
        return Err("INDEPENDENT_REFERENCE_MISMATCH".into());
    }
    Ok(())
}
fn run(seed: u64) -> Result<()> {
    let origin = Instant::now();
    let stdout = std::io::stdout();
    let mut output = std::io::BufWriter::new(stdout.lock());
    emit(&mut output,&format!("{{\"type\":\"start\",\"schema\":\"{SCHEMA}\",\"seed\":{seed},\"profile\":\"{}\",\"target\":\"{}\",\"proof_bytes\":{PROOF_BYTES},\"timing_scope\":\"Instant-wall-per-operation-not-process-CPU\",\"reference_before_measurement\":true,\"whole_process_includes_material_proof_reference_output\":true,\"source_claim\":false,\"production_activation\":false,\"mining_opportunity_claim\":false}}",pon_work::PROFILE,hex::encode([255;32])))?;
    let mut cases = 0_u64;
    let mut verifications = 0_u64;
    for family in FAMILIES.into_iter().map(Some).chain(std::iter::once(None)) {
        let (group, families, capacity) = match family {
            Some(family) => (format!("main-{family}"), vec![family; 4], 2),
            None => (
                "eviction".to_owned(),
                vec!["zero", "identity", "zero", "zero"],
                1,
            ),
        };
        let started = Instant::now();
        let cache = TaskProductFactCache::new(capacity)?;
        let create_ns = started.elapsed().as_nanos();
        let family_json = families
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(",");
        emit(&mut output,&format!("{{\"type\":\"group\",\"group\":\"{group}\",\"families\":[{family_json}],\"cache_capacity\":{capacity},\"cache_software_bytes\":{},\"cache_create_wall_ns\":{create_ns}}}",cache.software_bytes()))?;
        for (ordinal, family) in families.into_iter().enumerate() {
            let id = format!("{group}-{ordinal}");
            let started = Instant::now();
            let (a, b) = material(seed, family)?;
            let task = pon_work::task_id(&a, &b).map_err(|e| format!("MATERIAL:{e:?}"))?;
            let material_ns = started.elapsed().as_nanos();
            let challenge: Hash = pon_work::hash(
                b"task-product-facts-challenge-v1",
                &[
                    &seed.to_le_bytes(),
                    group.as_bytes(),
                    &(ordinal as u64).to_le_bytes(),
                    &task,
                ],
            );
            let started = Instant::now();
            let proof =
                black_box(pon_work::prove(challenge, &a, &b).map_err(|e| format!("PROVE:{e:?}"))?);
            let prove_ns = started.elapsed().as_nanos();
            let started = Instant::now();
            let reference = black_box(
                pon_work::verify_reference(challenge, task, [255; 32], &proof)
                    .map_err(|e| format!("REFERENCE:{e:?}"))?,
            );
            let reference_ns = started.elapsed().as_nanos();
            emit(&mut output,&format!("{{\"type\":\"case\",\"id\":\"{id}\",\"group\":\"{group}\",\"family\":\"{family}\",\"ordinal\":{ordinal},\"challenge\":\"{}\",\"task\":\"{}\",\"target\":\"{}\",\"proof_hex\":\"{}\",\"proof_sha256\":\"{}\",\"material_wall_ns\":{material_ns},\"prove_wall_ns\":{prove_ns},\"reference_wall_ns\":{reference_ns}}}",hex::encode(challenge),hex::encode(task),hex::encode([255;32]),hex::encode(&proof),digest(&proof)))?;
            let arms = if seed == 8101 {
                ["raw", "facts"]
            } else {
                ["facts", "raw"]
            };
            for (order, arm) in arms.into_iter().enumerate() {
                let mut progress = Progress::default();
                let mut observation = ProductObservation::default();
                let started = Instant::now();
                let actual = if arm == "raw" {
                    pon_work::verify_with_progress(
                        black_box(challenge),
                        black_box(task),
                        black_box([255; 32]),
                        black_box(&proof),
                        &mut |point| {
                            progress.add(point);
                            Ok::<_, ()>(())
                        },
                    )
                    .map_err(|e| format!("RAW:{e:?}"))?
                } else {
                    cache
                        .verify_with_observation(
                            black_box(challenge),
                            black_box(task),
                            black_box([255; 32]),
                            black_box(&proof),
                            &mut |point| {
                                progress.add(point);
                                Ok::<_, ()>(())
                            },
                            &mut observation,
                        )
                        .map_err(|e| format!("FACTS:{e:?}"))?
                };
                let actual = black_box(actual);
                let elapsed = started.elapsed().as_nanos();
                same(&actual, &reference)?;
                let product_bytes: Vec<_> = actual
                    .product()
                    .iter()
                    .flat_map(|w| w.to_le_bytes())
                    .collect();
                let observation_json = if arm == "raw" {
                    "null".to_owned()
                } else {
                    observation_json(&observation)
                };
                emit(&mut output,&format!("{{\"type\":\"verify\",\"case_id\":\"{id}\",\"arm\":\"{arm}\",\"order\":{order},\"wall_ns\":{elapsed},\"ticket\":\"{}\",\"product_sha256\":\"{}\",\"progress\":{},\"observation\":{observation_json}}}",hex::encode(actual.ticket()),digest(&product_bytes),progress.json()))?;
                verifications += 1;
            }
            cases += 1;
        }
        let started = Instant::now();
        drop(cache);
        let elapsed = started.elapsed().as_nanos();
        emit(
            &mut output,
            &format!(
                "{{\"type\":\"group_end\",\"group\":\"{group}\",\"cache_drop_wall_ns\":{elapsed}}}"
            ),
        )?;
    }
    let whole_wall = origin.elapsed().as_nanos();
    emit(&mut output,&format!("{{\"type\":\"end\",\"schema\":\"{SCHEMA}\",\"status\":\"PASS\",\"cases\":{cases},\"verifications\":{verifications},\"observed_wall_before_final_output_ns\":{whole_wall},\"source_claim\":false,\"production_activation\":false,\"mining_opportunity_claim\":false}}"))?;
    Ok(())
}
fn main() {
    if let Err(error) = seed().and_then(run) {
        eprintln!("TASK_PRODUCT_FACT_RESEARCH_FAILURE:{error}");
        std::process::exit(1);
    }
}
