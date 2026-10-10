//! Paired W1 implementations on identical input/challenge/target streams.
//! Elapsed times include setup, all attempted searches and harness hashing. They
//! are observations, not CPU accounting, attacker lower bounds or admission tests.
use std::{env, error::Error, fs, hint::black_box, path::PathBuf, time::Instant};
use trnm_crypto_primitives::pon_work::{structured::StructuredPreparedTask, *};

struct Material {
    name: &'static str,
    source: &'static str,
    a: Vec<u32>,
    b: Vec<u32>,
}
struct Options {
    model: Option<PathBuf>,
    input: Option<PathBuf>,
    samples: u64,
    attempts: u64,
}
impl Options {
    fn parse() -> Result<Self, Box<dyn Error>> {
        let mut options = Self {
            model: None,
            input: None,
            samples: 8,
            attempts: 4096,
        };
        let mut arguments = env::args_os().skip(1);
        while let Some(flag) = arguments.next() {
            let value = arguments.next().ok_or("each flag requires a value")?;
            match flag.to_str() {
                Some("--model") if options.model.is_none() => options.model = Some(value.into()),
                Some("--input") if options.input.is_none() => options.input = Some(value.into()),
                Some("--samples") => {
                    options.samples = value.to_str().ok_or("samples encoding")?.parse()?
                }
                Some("--attempt-budget") => {
                    options.attempts = value.to_str().ok_or("budget encoding")?.parse()?
                }
                _ => {
                    return Err(
                        "expected --model PATH --input PATH, --samples N or --attempt-budget N"
                            .into(),
                    )
                }
            }
        }
        if options.model.is_some() != options.input.is_some()
            || !(1..=64).contains(&options.samples)
            || !(1..=4096).contains(&options.attempts)
        {
            return Err("paired materials, 1..64 samples and 1..4096 attempts are required".into());
        }
        Ok(options)
    }
}

fn multiply(a: u32, b: u32) -> u32 {
    ((u128::from(a) * u128::from(b)) % Q) as u32
}
fn inverse(mut power: u32) -> u32 {
    let mut result = 1;
    let mut exponent = (Q - 2) as u64;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = multiply(result, power);
        }
        power = multiply(power, power);
        exponent >>= 1;
    }
    result
}
fn rank(matrix: &[u32]) -> usize {
    let mut rows: Vec<_> = matrix.chunks_exact(N).map(<[u32]>::to_vec).collect();
    let mut rank = 0;
    for column in 0..N {
        let Some(pivot) = (rank..N).find(|row| rows[*row][column] != 0) else {
            continue;
        };
        rows.swap(rank, pivot);
        let reciprocal = inverse(rows[rank][column]);
        for value in &mut rows[rank][column..] {
            *value = multiply(*value, reciprocal);
        }
        let pivot_row = rows[rank].clone();
        for row in rows.iter_mut().skip(rank + 1) {
            let scale = row[column];
            for index in column..N {
                row[index] = ((u128::from(row[index]) + Q
                    - u128::from(multiply(scale, pivot_row[index])))
                    % Q) as u32;
            }
        }
        rank += 1;
    }
    rank
}
fn full_rank(label: u8) -> Vec<u32> {
    for generation in 0u32..32 {
        let mut values = Vec::with_capacity(CELLS);
        for counter in 0u32..1024 {
            for bytes in hash(
                b"comparison-material",
                &[&[label], &generation.to_le_bytes(), &counter.to_le_bytes()],
            )
            .chunks_exact(4)
            {
                let value = u32::from_le_bytes(bytes.try_into().unwrap());
                if u128::from(value) < Q {
                    values.push(value);
                }
                if values.len() == CELLS {
                    break;
                }
            }
            if values.len() == CELLS {
                break;
            }
        }
        if values.len() == CELLS && rank(&values) == N {
            return values;
        }
    }
    panic!("bounded full-rank material construction exhausted");
}
fn decode_material(path: &PathBuf) -> Result<Vec<u32>, Box<dyn Error>> {
    // Bound the actual read, including files that grow or are not regular files.
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take((CELLS * 4 + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() != CELLS * 4 {
        return Err("material must contain exactly 16384 bytes".into());
    }
    let values: Vec<_> = bytes
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect();
    task_id(&values, &values).map_err(|_| "noncanonical matrix material")?;
    Ok(values)
}
fn materials(options: &Options) -> Result<Vec<Material>, Box<dyn Error>> {
    let mut cases = vec![
        Material {
            name: "periodic-dense-fixture",
            source: "synthetic-fixture",
            a: (0..CELLS).map(|i| (i % 31) as u32).collect(),
            b: (0..CELLS).map(|i| ((i * 7) % 37) as u32).collect(),
        },
        Material {
            name: "full-rank-field",
            source: "hash-generated-rank-checked",
            a: full_rank(0),
            b: full_rank(1),
        },
        Material {
            name: "zero",
            source: "synthetic-fixture",
            a: vec![0; CELLS],
            b: vec![0; CELLS],
        },
        Material {
            name: "identity",
            source: "synthetic-fixture",
            a: (0..CELLS).map(|i| u32::from(i / N == i % N)).collect(),
            b: (0..CELLS).map(|i| u32::from(i / N == i % N)).collect(),
        },
        Material {
            name: "rank-one",
            source: "synthetic-fixture",
            a: (0..CELLS)
                .map(|i| ((i / N + 1) * (i % N + 1)) as u32)
                .collect(),
            b: (0..CELLS)
                .map(|i| ((i / N + 2) * (i % N + 1)) as u32)
                .collect(),
        },
        Material {
            name: "sparse-diagonal",
            source: "synthetic-fixture",
            a: (0..CELLS)
                .map(|i| {
                    if i / N == i % N {
                        (i / N + 1) as u32
                    } else {
                        0
                    }
                })
                .collect(),
            b: (0..CELLS)
                .map(|i| {
                    if i / N == i % N {
                        (i / N + 2) as u32
                    } else {
                        0
                    }
                })
                .collect(),
        },
    ];
    if let (Some(model), Some(input)) = (&options.model, &options.input) {
        cases.push(Material {
            name: "supplied-material",
            source: "caller-supplied-provenance-not-verified",
            a: decode_material(model)?,
            b: decode_material(input)?,
        });
    }
    Ok(cases)
}

struct Search {
    attempts: u64,
    elapsed: u128,
    stream: Hash,
    winning: Option<(Hash, Vec<u8>)>,
}
fn search(
    task: Hash,
    sample: u64,
    target: Hash,
    budget: u64,
    mut producer: impl FnMut(Hash) -> Vec<u8>,
) -> Search {
    use sha2::{Digest, Sha256};
    let start = Instant::now();
    let mut stream = Sha256::new();
    for nonce in 0..budget {
        let challenge = hash(
            b"producer-comparison",
            &[&task, &sample.to_le_bytes(), &target, &nonce.to_le_bytes()],
        );
        let proof = producer(challenge);
        let ticket = hash(b"ticket", &[&challenge, &proof[PROOF_BYTES - 32..]]);
        stream.update(ticket);
        if ticket <= target {
            return Search {
                attempts: nonce + 1,
                elapsed: start.elapsed().as_nanos(),
                stream: stream.finalize().into(),
                winning: Some((challenge, proof)),
            };
        }
    }
    Search {
        attempts: budget,
        elapsed: start.elapsed().as_nanos(),
        stream: stream.finalize().into(),
        winning: None,
    }
}

struct Observation {
    strategy: &'static str,
    method: &'static str,
    setup: u128,
    searched: Option<Search>,
}
fn observe(
    material: &Material,
    task: Hash,
    target: Hash,
    sample: u64,
    budget: u64,
    strategy: usize,
) -> Observation {
    match strategy {
        0 => Observation {
            strategy: "scalar-original",
            method: "scalar-full-generation",
            setup: 0,
            searched: Some(search(task, sample, target, budget, |c| {
                prove(c, &material.a, &material.b).unwrap()
            })),
        },
        1 => {
            let start = Instant::now();
            let prepared = PreparedTask::new(&material.a, &material.b).unwrap();
            let setup = start.elapsed().as_nanos();
            Observation {
                strategy: "prepared-generic",
                method: "generic-product-and-transcript",
                setup,
                searched: Some(search(task, sample, target, budget, |c| {
                    prepared.prove(c).unwrap()
                })),
            }
        }
        _ => {
            let start = Instant::now();
            let prepared = StructuredPreparedTask::new(&material.a, &material.b).unwrap();
            let setup = start.elapsed().as_nanos();
            match prepared {
                Some(prepared) => Observation {
                    strategy: "prepared-structured",
                    method: prepared.method(),
                    setup,
                    searched: Some(search(task, sample, target, budget, |c| {
                        prepared.prove(c).unwrap()
                    })),
                },
                None => Observation {
                    strategy: "prepared-structured",
                    method: "unsupported",
                    setup,
                    searched: None,
                },
            }
        }
    }
}
fn verifier_times(
    challenge: Hash,
    task: Hash,
    target: Hash,
    proof: &[u8],
    reference_first: bool,
) -> (u128, u128) {
    let fast = || {
        let start = Instant::now();
        black_box(verify(challenge, task, target, proof).unwrap());
        start.elapsed().as_nanos()
    };
    let scalar = || {
        let start = Instant::now();
        black_box(verify_reference(challenge, task, target, proof).unwrap());
        start.elapsed().as_nanos()
    };
    if reference_first {
        let r = scalar();
        (fast(), r)
    } else {
        let f = fast();
        (f, scalar())
    }
}
fn main() -> Result<(), Box<dyn Error>> {
    let options = Options::parse()?;
    let materials = materials(&options)?;
    print!("{{\"schema\":\"pon-w1-producer-comparison-v1\",\"timing\":\"monotonic-wall-elapsed-nanoseconds-not-cpu-accounting\",\"material_generation_and_rank_checks_timed\":false,\"samples_per_case_target\":{},\"attempt_budget\":{},\"observations\":[", options.samples, options.attempts);
    let mut first = true;
    for material in materials {
        let task = task_id(&material.a, &material.b).unwrap();
        let ranks = (rank(&material.a), rank(&material.b));
        for top in [127u8, 7u8] {
            let mut target = [255; 32];
            target[0] = top;
            for sample in 0..options.samples {
                let mut observations = Vec::new();
                for offset in 0..3 {
                    observations.push(observe(
                        &material,
                        task,
                        target,
                        sample,
                        options.attempts,
                        (sample as usize + offset) % 3,
                    ));
                }
                let baseline = observations
                    .iter()
                    .find(|r| r.strategy == "scalar-original")
                    .unwrap()
                    .searched
                    .as_ref()
                    .unwrap();
                for (order, row) in observations.iter().enumerate() {
                    if let Some(search) = &row.searched {
                        assert_eq!(search.attempts, baseline.attempts);
                        assert_eq!(search.stream, baseline.stream);
                        assert_eq!(search.winning, baseline.winning);
                    }
                    let reference_first = sample.is_multiple_of(2);
                    let (
                        status,
                        attempts,
                        search_ns,
                        production_ns,
                        reference_ns,
                        proof_id,
                        stream,
                    ) = match &row.searched {
                        Some(search) => match &search.winning {
                            Some((challenge, proof)) => {
                                let (production, reference) = verifier_times(
                                    *challenge,
                                    task,
                                    target,
                                    proof,
                                    reference_first,
                                );
                                (
                                    "winner",
                                    search.attempts,
                                    search.elapsed,
                                    production.to_string(),
                                    reference.to_string(),
                                    format!(
                                        "\"{}\"",
                                        hex::encode(hash(b"measured-proof", &[proof]))
                                    ),
                                    format!("\"{}\"", hex::encode(search.stream)),
                                )
                            }
                            None => (
                                "exhausted",
                                search.attempts,
                                search.elapsed,
                                "null".into(),
                                "null".into(),
                                "null".into(),
                                format!("\"{}\"", hex::encode(search.stream)),
                            ),
                        },
                        None => (
                            "unsupported",
                            0,
                            0,
                            "null".into(),
                            "null".into(),
                            "null".into(),
                            "null".into(),
                        ),
                    };
                    if !first {
                        print!(",");
                    }
                    first = false;
                    print!("{{\"class\":\"{}\",\"input_source\":\"{}\",\"task\":\"{}\",\"rank_a\":{},\"rank_b\":{},\"target\":\"{}\",\"sample\":{sample},\"invocation_order\":{order},\"strategy\":\"{}\",\"method\":\"{}\",\"status\":\"{status}\",\"setup_elapsed_ns\":{},\"search_elapsed_ns\":{search_ns},\"total_elapsed_ns\":{},\"attempts\":{attempts},\"ticket_stream_commitment\":{stream},\"production_verifier_elapsed_ns\":{production_ns},\"reference_verifier_elapsed_ns\":{reference_ns},\"reference_verifier_first\":{reference_first},\"proof_bytes\":{PROOF_BYTES},\"proof_commitment\":{proof_id}}}", material.name, material.source, hex::encode(task), ranks.0, ranks.1, hex::encode(target), row.strategy, row.method, row.setup, row.setup + search_ns);
                }
            }
        }
    }
    println!("],\"fastest_adversary_qualified\":false,\"work_hardness_accepted\":false,\"public_service_measured\":false,\"input_provenance_verified\":false,\"production_activation\":false}}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_dense_case_is_full_rank_and_periodic_case_is_labelled_exactly() {
        let options = Options {
            model: None,
            input: None,
            samples: 1,
            attempts: 1,
        };
        let cases = materials(&options).unwrap();
        assert_eq!((rank(&cases[0].a), rank(&cases[0].b)), (31, 37));
        assert_eq!((rank(&cases[1].a), rank(&cases[1].b)), (N, N));
        assert_eq!((rank(&cases[4].a), rank(&cases[4].b)), (1, 1));
    }
    #[test]
    fn exhausted_search_retains_attempts_and_the_same_ticket_stream() {
        let a = vec![0; CELLS];
        let task = task_id(&a, &a).unwrap();
        let prepared = StructuredPreparedTask::new(&a, &a).unwrap().unwrap();
        let mut target = [0; 32];
        target[31] = 1;
        let original = search(task, 0, target, 2, |c| prove(c, &a, &a).unwrap());
        let alternative = search(task, 0, target, 2, |c| prepared.prove(c).unwrap());
        assert!(original.winning.is_none());
        assert!(alternative.winning.is_none());
        assert_eq!(original.attempts, 2);
        assert_eq!(alternative.attempts, 2);
        assert_eq!(original.stream, alternative.stream);
    }
}
