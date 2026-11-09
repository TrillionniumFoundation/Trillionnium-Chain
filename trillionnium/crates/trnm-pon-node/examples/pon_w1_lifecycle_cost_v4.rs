//! V4 streams lifecycle observations before native work and after each attempt.
//! Missing finishes remain incomplete and have unknown cost. These records are
//! local diagnostics; they never grant chainwork or prove a work-cost bound.
#[path = "support/w1_cost_producers.rs"]
mod w1_cost_producers;
#[path = "../../trnm-crypto-primitives/examples/support/w1_material.rs"]
mod w1_material;

use serde_json::{json, Value};
use std::{hint::black_box, io::Write};
use trnm_crypto_primitives::pon_work::{self, Hash, VerifiedWork, WorkError, CELLS, PROOF_BYTES};
use w1_cost_producers::{
    raw, sha, Clock, Producer, Result, Search, SearchObserver, Timing, Trial, ARMS,
};

const SCHEMA: &str = "pon-w1-lifecycle-cost-v4";
const SELECTOR: &str = "--actual-lifecycle-v4";
const SAMPLES: u64 = 8;
const SEARCHES: usize = 4;
const LIMIT: u64 = 4096;
const SEED: u64 = 0;

fn target() -> Hash {
    let mut result = [255; 32];
    result[0] = 127;
    result
}
fn challenge(task: Hash, sample: u64, search: usize, nonce: u64) -> Hash {
    // Retain the V3 challenge stream, allowing exact full-proof comparisons.
    pon_work::hash(
        b"pon-w1-reused-challenge-v3",
        &[
            &task,
            &SEED.to_le_bytes(),
            &sample.to_le_bytes(),
            &(search as u64).to_le_bytes(),
            &nonce.to_le_bytes(),
        ],
    )
}

/// Write one entire JSON line and flush before acknowledging the event.
/// Flush exposes bytes to the host collector; it is not a power-loss guarantee.
struct Journal<W: Write> {
    output: W,
    next_sequence: u64,
}
impl<W: Write> Journal<W> {
    fn new(output: W) -> Self {
        Self {
            output,
            next_sequence: 0,
        }
    }
    fn emit(&mut self, mut row: Value) -> Result<()> {
        let following = self
            .next_sequence
            .checked_add(1)
            .ok_or("LIFECYCLE_SEQUENCE_EXHAUSTED")?;
        let object = row.as_object_mut().ok_or("LIFECYCLE_RECORD_OBJECT")?;
        if object.contains_key("schema") || object.contains_key("sequence") {
            return Err("LIFECYCLE_RESERVED_FIELDS".into());
        }
        object.insert("schema".into(), SCHEMA.into());
        object.insert("sequence".into(), self.next_sequence.into());
        let mut bytes = serde_json::to_vec(&row)?;
        bytes.push(b'\n');
        self.output.write_all(&bytes)?;
        self.output.flush()?;
        self.next_sequence = following;
        Ok(())
    }
}

fn event(key: &Value, kind: &str) -> Value {
    let mut row = key.clone();
    row["kind"] = kind.into();
    row
}
struct ObservedSearch<'a, W: Write> {
    journal: &'a mut Journal<W>,
    key: Value,
}
impl<W: Write> SearchObserver for ObservedSearch<'_, W> {
    fn attempt_started(&mut self, nonce: u64, context: Hash) -> Result<()> {
        let mut row = event(&self.key, "attempt-start");
        row["nonce"] = nonce.into();
        row["challenge"] = hex::encode(context).into();
        self.journal.emit(row)
    }
    fn attempt_finished(&mut self, trial: &Trial, timing: Timing) -> Result<()> {
        let mut row = event(&self.key, "attempt-finish");
        row["trial"] = serde_json::to_value(trial)?;
        row["timing"] = serde_json::to_value(timing)?;
        // A target hit has not yet passed the complete verifier.
        row["accepted_work"] = false.into();
        self.journal.emit(row)
    }
    fn attempt_failed(&mut self, nonce: u64, reason: &str, timing: Timing) -> Result<()> {
        let mut row = event(&self.key, "attempt-error");
        row["nonce"] = nonce.into();
        row["reason"] = reason.into();
        row["timing"] = serde_json::to_value(timing)?;
        row["accepted_work"] = false.into();
        self.journal.emit(row)
    }
}
fn verdict(result: std::result::Result<VerifiedWork, WorkError>, proof: &[u8]) -> String {
    match result {
        Ok(work) if raw(work.product()) == proof[4 + 8 * CELLS..PROOF_BYTES - 32] => {
            "Accepted".into()
        }
        Ok(_) => "AcceptedWrongProduct".into(),
        Err(error) => format!("{error:?}"),
    }
}
#[derive(Default)]
struct Counts {
    cohorts: usize,
    searches: usize,
    attempts: usize,
    candidates: usize,
    verifiers: usize,
    verified_searches: usize,
}

fn cohort<W: Write>(
    journal: &mut Journal<W>,
    material: &w1_material::Material,
    task: Hash,
    sample: u64,
    order: usize,
    canonical: &mut [Option<Search>; SEARCHES],
    counts: &mut Counts,
) -> Result<()> {
    let index = (sample as usize + order) % ARMS.len();
    let key = json!({"class":material.name,"sample":sample,"arm":ARMS[index],
        "invocation_order":order,"task":hex::encode(task),"target":hex::encode(target())});
    journal.emit(event(&key, "cohort-start"))?;
    let total = Clock::start();
    journal.emit(event(&key, "prepare-start"))?;
    let setup = Clock::start();
    let prepared = Producer::new(index, &material.a, &material.b);
    let mut prepared_event = event(&key, "prepare-finish");
    prepared_event["timing"] = serde_json::to_value(setup.finish())?;
    prepared_event["setup_calls"] = 1.into();
    let prepared = match prepared {
        Ok(value) => {
            prepared_event["status"] = if value.is_some() {
                "supported"
            } else {
                "unsupported"
            }
            .into();
            journal.emit(prepared_event)?;
            value
        }
        Err(error) => {
            prepared_event["status"] = "error".into();
            prepared_event["reason"] = format!("PREPARATION:{error:?}").into();
            journal.emit(prepared_event)?;
            return Err(format!("PREPARATION:{error:?}").into());
        }
    };
    counts.cohorts += 1;
    if let Some(producer) = &prepared {
        for (search, canonical_search) in canonical.iter_mut().enumerate() {
            let mut search_key = key.clone();
            search_key["search_index"] = search.into();
            journal.emit(event(&search_key, "search-start"))?;
            let started = Clock::start();
            let searched = w1_cost_producers::search_observed(
                producer,
                target(),
                LIMIT,
                |nonce| challenge(task, sample, search, nonce),
                &mut ObservedSearch {
                    journal,
                    key: search_key.clone(),
                },
            )?;
            let mut finished = event(&search_key, "search-finish");
            finished["timing"] = serde_json::to_value(started.finish())?;
            finished["attempt_count"] = searched.attempts.len().into();
            finished["status"] = if searched.winner.is_some() {
                "target-hit-unverified"
            } else {
                "exhausted"
            }
            .into();
            journal.emit(finished)?;
            counts.searches += 1;
            counts.attempts += searched.attempts.len();
            if let Some(original) = canonical_search.as_ref() {
                if original.attempts != searched.attempts || original.winner != searched.winner {
                    return Err("LIFECYCLE_SUPPORTED_STREAM_DISAGREEMENT".into());
                }
            }
            if let Some(winner) = &searched.winner {
                for verification_order in 0..2 {
                    let reference =
                        (sample as usize + order + search + verification_order) % 2 == 1;
                    let mut verify_key = search_key.clone();
                    verify_key["path"] = if reference { "reference" } else { "production" }.into();
                    verify_key["verification_order"] = verification_order.into();
                    verify_key["challenge"] = hex::encode(winner.challenge).into();
                    verify_key["proof_sha256"] = sha(&winner.proof).into();
                    journal.emit(event(&verify_key, "verify-start"))?;
                    let started = Clock::start();
                    let native = if reference {
                        black_box(pon_work::verify_reference(
                            winner.challenge,
                            task,
                            target(),
                            &winner.proof,
                        ))
                    } else {
                        black_box(pon_work::verify(
                            winner.challenge,
                            task,
                            target(),
                            &winner.proof,
                        ))
                    };
                    let timing = started.finish();
                    let outcome = verdict(native, &winner.proof);
                    let mut verified = event(&verify_key, "verify-finish");
                    verified["outcome"] = outcome.clone().into();
                    verified["timing"] = serde_json::to_value(timing)?;
                    verified["consensus_credit_added"] = 0.into();
                    journal.emit(verified)?;
                    counts.verifiers += 1;
                    if outcome != "Accepted" {
                        return Err("LIFECYCLE_NATIVE_VERIFIER_DISAGREEMENT".into());
                    }
                }
                counts.verified_searches += 1;
            }
            if canonical_search.is_none() {
                *canonical_search = Some(searched);
            }
        }
    }
    let mut finished = event(&key, "cohort-finish");
    finished["status"] = if prepared.is_some() {
        "supported"
    } else {
        "unsupported"
    }
    .into();
    // Includes V4 streaming and verification overhead, unlike V3 producer time.
    finished["total_with_observation_and_verification"] = serde_json::to_value(total.finish())?;
    journal.emit(finished)
}

fn campaign<W: Write>(journal: &mut Journal<W>, total: Clock) -> Result<()> {
    journal.emit(json!({"kind":"material-setup-start"}))?;
    let material_started = Clock::start();
    let mut materials = w1_material::materials(None, None)?;
    let nonzero: Vec<u32> = (0..CELLS)
        .map(|i| ((i / 64 + 1) * (i % 64 + 2)) as u32)
        .collect();
    materials.push(w1_material::Material {
        name: "one-zero-left-rank-one",
        source: "synthetic-fixture",
        a: vec![0; CELLS],
        b: nonzero.clone(),
    });
    materials.push(w1_material::Material {
        name: "one-zero-right-rank-one",
        source: "synthetic-fixture",
        a: nonzero,
        b: vec![0; CELLS],
    });
    journal.emit(json!({"kind":"material-setup-finish",
        "timing":material_started.finish(),
        "classes":materials.iter().map(|m|m.name).collect::<Vec<_>>()}))?;
    let mut counts = Counts::default();
    for material in &materials {
        let task =
            pon_work::task_id(&material.a, &material.b).map_err(|e| format!("MATERIAL:{e:?}"))?;
        journal.emit(
            json!({"kind":"material","class":material.name,"source":material.source,
            "task":hex::encode(task),"a_hex":hex::encode(raw(&material.a)),
            "b_hex":hex::encode(raw(&material.b))}),
        )?;
        for sample in 0..SAMPLES {
            let mut canonical: [Option<Search>; SEARCHES] = std::array::from_fn(|_| None);
            for order in 0..ARMS.len() {
                cohort(
                    journal,
                    material,
                    task,
                    sample,
                    order,
                    &mut canonical,
                    &mut counts,
                )?;
            }
            for (search, searched) in canonical.into_iter().enumerate() {
                let searched = searched.ok_or("LIFECYCLE_CANONICAL_SEARCH_MISSING")?;
                if let Some(winner) = searched.winner {
                    journal.emit(
                        json!({"kind":"candidate","class":material.name,"sample":sample,
                        "search_index":search,"task":hex::encode(task),"target":hex::encode(target()),
                        "challenge":hex::encode(winner.challenge),"proof_hex":hex::encode(&winner.proof),
                        "proof_sha256":sha(&winner.proof),"consensus_credit_added":0}),
                    )?;
                    counts.candidates += 1;
                }
            }
        }
    }
    journal.emit(
        json!({"kind":"end","material_count":materials.len(),"cohort_count":counts.cohorts,
        "search_count":counts.searches,"attempt_count":counts.attempts,
        "candidate_count":counts.candidates,"verifier_count":counts.verifiers,
        "fully_verified_search_count":counts.verified_searches,
        "total_before_terminal_record":total.finish(),"complete":true,
        "consensus_credit_added":0,"work_cost_lower_bound_proved":false,
        "production_qualified":false}),
    )
}

fn run<W: Write>(output: W) -> Result<()> {
    let total = Clock::start();
    let mut journal = Journal::new(output);
    journal.emit(json!({"kind":"start","selector":SELECTOR,"samples":SAMPLES,
        "searches_per_setup":SEARCHES,"attempt_budget":LIMIT,"seed":SEED,
        "target":hex::encode(target()),"arms":ARMS,
        "clock":"thread-cpu-and-monotonic-wall-ns",
        "setup_reuse":"one-actual-preparation-four-distinct-domain-searches",
        "attempt_timing_scope":"proof-generation-and-trial-digest-before-finish-observation",
        "search_timing_scope":"native-search-with-v4-streaming-observation",
        "verifier_timing_scope":"complete-native-verification-call",
        "missing_finish":"INCOMPLETE_COST_UNKNOWN_NEVER_ZERO",
        "sink_guarantee":"line-write-and-flush-not-power-loss-durability",
        "raw_process_and_source_receipts_required":true,
        "hardness_accepted":false,"work_profile_qualified":false,
        "public_service_measured":false,"production_activation":false,
        "consensus_credit_added":0}))?;
    if let Err(error) = campaign(&mut journal, total) {
        // A broken sink may refuse this final diagnostic. Its prior prefix
        // still lacks end/complete and cannot become successful by omission.
        let _ = journal.emit(json!({"kind":"failure","reason":error.to_string(),
            "complete":false,"unfinished_cost":null,"consensus_credit_added":0,
            "production_qualified":false}));
        return Err(error);
    }
    Ok(())
}

fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments != [SELECTOR] {
        return Err("V4_EXPLICIT_FIXED_SELECTOR_REQUIRED".into());
    }
    let stdout = std::io::stdout();
    run(stdout.lock())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[derive(Default)]
    struct Sink {
        bytes: Vec<u8>,
        flushes: usize,
        reject_flush: bool,
    }
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if self.reject_flush {
                Err(io::Error::other("control sink flush failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn every_begin_is_a_complete_flushed_line_with_monotone_sequence() {
        let mut journal = Journal::new(Sink::default());
        journal.emit(json!({"kind":"start"})).unwrap();
        journal
            .emit(json!({"kind":"attempt-start","nonce":0}))
            .unwrap();
        assert_eq!(journal.output.flushes, 2);
        assert!(journal.output.bytes.ends_with(b"\n"));
        let rows: Vec<Value> = journal
            .output
            .bytes
            .split(|b| *b == b'\n')
            .filter(|row| !row.is_empty())
            .map(|row| serde_json::from_slice(row).unwrap())
            .collect();
        assert_eq!(rows[0]["sequence"], 0);
        assert_eq!(rows[1]["sequence"], 1);
        assert_eq!(rows[1]["schema"], SCHEMA);
        assert!(rows
            .iter()
            .all(|row| row.get("complete") != Some(&Value::Bool(true))));
    }

    #[test]
    fn refused_flush_does_not_acknowledge_begin_or_start_native_search() {
        let mut journal = Journal::new(Sink {
            reject_flush: true,
            ..Sink::default()
        });
        let mut observer = ObservedSearch {
            journal: &mut journal,
            key: json!({"search_index":0}),
        };
        assert!(observer.attempt_started(0, [7; 32]).is_err());
        assert_eq!(journal.next_sequence, 0);
        assert_eq!(journal.output.flushes, 1);
        let row: Value = serde_json::from_slice(&journal.output.bytes).unwrap();
        assert_eq!(row["kind"], "attempt-start");
        assert!(row.get("complete").is_none());
    }

    #[test]
    fn observer_finished_target_hit_remains_unverified_and_uncredited() {
        let zero = vec![0; CELLS];
        let prepared = Producer::new(7, &zero, &zero).unwrap().unwrap();
        let mut journal = Journal::new(Sink::default());
        let result = w1_cost_producers::search_observed(
            &prepared,
            [255; 32],
            1,
            |_| [27; 32],
            &mut ObservedSearch {
                journal: &mut journal,
                key: json!({"search_index":0}),
            },
        )
        .unwrap();
        assert!(result.winner.is_some());
        let rows: Vec<Value> = journal
            .output
            .bytes
            .split(|b| *b == b'\n')
            .filter(|row| !row.is_empty())
            .map(|row| serde_json::from_slice(row).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["kind"], "attempt-start");
        assert_eq!(rows[1]["kind"], "attempt-finish");
        assert_eq!(rows[1]["trial"]["target_hit"], true);
        assert_eq!(rows[1]["accepted_work"], false);
        assert!(rows.iter().all(|row| row.get("complete").is_none()));
    }

    #[test]
    fn observer_error_retains_failure_without_complete_or_credit() {
        let mut journal = Journal::new(Sink::default());
        let mut observer = ObservedSearch {
            journal: &mut journal,
            key: json!({"search_index":0}),
        };
        observer.attempt_started(1, [7; 32]).unwrap();
        observer
            .attempt_failed(
                1,
                "GENERATION:NoiseBudget",
                Timing {
                    cpu_ns: None,
                    wall_ns: None,
                },
            )
            .unwrap();
        let rows: Vec<Value> = journal
            .output
            .bytes
            .split(|b| *b == b'\n')
            .filter(|row| !row.is_empty())
            .map(|row| serde_json::from_slice(row).unwrap())
            .collect();
        assert_eq!(rows[1]["kind"], "attempt-error");
        assert_eq!(rows[1]["accepted_work"], false);
        assert_eq!(rows[1]["timing"]["cpu_ns"], Value::Null);
        assert!(rows.iter().all(|row| row.get("complete").is_none()));
    }
}
