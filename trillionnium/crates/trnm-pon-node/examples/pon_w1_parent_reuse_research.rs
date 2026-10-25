//! Bounded native-parent research. This example does not alter W1 or Node policy.
//! The shared acquisition fixture is deliberately charged to every strategy.
#[path = "support/w1_parent_reuse.rs"]
mod research;
// The shared producer's retained tests use the complete original diagnostic
// material registry. Keep that test context without adding it to native runs.
#[cfg(test)]
#[path = "../../trnm-crypto-primitives/examples/support/w1_material.rs"]
mod w1_material;

use serde::Serialize;
use serde_json::{json, Value};
use std::{cell::Cell, collections::BTreeSet, io::Write, time::Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SCHEMA: &str = "pon-w1-parent-reuse-research-v1";

#[cfg(test)]
fn materials() -> Result<Vec<w1_material::Material>> {
    use trnm_crypto_primitives::pon_work::CELLS;
    use w1_material::Material;
    let mut cases = w1_material::materials(None, None)?;
    let rank_one = cases
        .iter()
        .find(|material| material.name == "rank-one")
        .expect("rank-one fixture");
    let a = rank_one.a.clone();
    let b = rank_one.b.clone();
    cases.push(Material {
        name: "zero-left-rank-one",
        source: "synthetic-fixture",
        a: vec![0; CELLS],
        b,
    });
    cases.push(Material {
        name: "zero-right-rank-one",
        source: "synthetic-fixture",
        a,
        b: vec![0; CELLS],
    });
    Ok(cases)
}

#[derive(Clone, Debug, Serialize)]
pub struct Options {
    rounds: u64,
    attempts_per_parent: u64,
    seed: u64,
    cache: String,
    strategy: String,
    screen_width: u64,
    arm: String,
    cpu_budget_ns: Option<u64>,
}

fn options() -> Result<Options> {
    let mut result = Options {
        rounds: 4,
        attempts_per_parent: 4,
        seed: 1,
        cache: "hot".into(),
        strategy: "paid-task-screen".into(),
        screen_width: 1,
        arm: "integer-paired-general".into(),
        cpu_budget_ns: None,
    };
    let mut seen = BTreeSet::new();
    let mut args = std::env::args().skip(1);
    while let Some(key) = args.next() {
        if key == "--help" {
            println!("pon_w1_parent_reuse_research --rounds 1..8 --attempts-per-parent 1..8 --seed U64 --cache hot|cold --strategy maintenance-only|zero-only|paid-task-screen --screen-width 1..8 --arm prepared-generic|paired-product|integer-paired-general --cpu-budget-ns U64");
            std::process::exit(0);
        }
        if !seen.insert(key.clone()) {
            return Err(format!("DUPLICATE_OPTION:{key}").into());
        }
        let value = args.next().ok_or_else(|| format!("MISSING_VALUE:{key}"))?;
        match key.as_str() {
            "--rounds" => result.rounds = value.parse()?,
            "--attempts-per-parent" => result.attempts_per_parent = value.parse()?,
            "--seed" => result.seed = value.parse()?,
            "--cache" => result.cache = value,
            "--strategy" => result.strategy = value,
            "--screen-width" => result.screen_width = value.parse()?,
            "--arm" => result.arm = value,
            "--cpu-budget-ns" => result.cpu_budget_ns = Some(value.parse()?),
            _ => return Err(format!("UNKNOWN_OPTION:{key}").into()),
        }
    }
    if !(1..=8).contains(&result.rounds)
        || !(1..=8).contains(&result.attempts_per_parent)
        || !(1..=8).contains(&result.screen_width)
        || !["hot", "cold"].contains(&result.cache.as_str())
        || !["maintenance-only", "zero-only", "paid-task-screen"]
            .contains(&result.strategy.as_str())
        || ![
            "prepared-generic",
            "paired-product",
            "integer-paired-general",
        ]
        .contains(&result.arm.as_str())
    {
        return Err("OPTION_BOUNDS".into());
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Stamp {
    process_cpu_ns: u64,
    wall_ns: u64,
}

pub struct Journal {
    origin_cpu: u64,
    origin_wall: Instant,
    sequence: u64,
    budget: Option<u64>,
    last_budget_poll: Cell<Option<Stamp>>,
}

#[cfg(target_os = "linux")]
fn process_cpu() -> Result<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let value = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ProcessCPUTime))?;
    let seconds = u64::try_from(value.tv_sec)?;
    let nanos = u64::try_from(value.tv_nsec)?;
    if nanos >= 1_000_000_000 {
        return Err("PROCESS_CPU_CLOCK".into());
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(nanos))
        .ok_or_else(|| "PROCESS_CPU_OVERFLOW".into())
}

#[cfg(not(target_os = "linux"))]
fn process_cpu() -> Result<u64> {
    Err("LINUX_PROCESS_CPU_CLOCK_REQUIRED".into())
}

impl Journal {
    fn new() -> Result<Self> {
        Ok(Self {
            origin_cpu: process_cpu()?,
            origin_wall: Instant::now(),
            sequence: 0,
            budget: None,
            last_budget_poll: Cell::new(None),
        })
    }

    pub fn stamp(&self) -> Result<Stamp> {
        Ok(Stamp {
            process_cpu_ns: process_cpu()?
                .checked_sub(self.origin_cpu)
                .ok_or("PROCESS_CPU_REVERSED")?,
            wall_ns: self.origin_wall.elapsed().as_nanos().try_into()?,
        })
    }

    pub fn permitted(&self) -> Result<bool> {
        let stamp = self.stamp()?;
        self.last_budget_poll.set(Some(stamp));
        Ok(self.budget.is_none_or(|limit| stamp.process_cpu_ns < limit))
    }

    pub fn within(&self, completed: Stamp) -> bool {
        self.budget
            .is_none_or(|limit| completed.process_cpu_ns <= limit)
    }

    pub fn emit(&mut self, mut record: Value) -> Result<()> {
        let object = record.as_object_mut().ok_or("RECORD_OBJECT")?;
        object.insert("schema".into(), json!(SCHEMA));
        object.insert("sequence".into(), json!(self.sequence));
        object.insert("observed".into(), json!(self.stamp()?));
        let mut stdout = std::io::stdout().lock();
        serde_json::to_writer(&mut stdout, &record)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
        self.sequence += 1;
        Ok(())
    }

    pub fn charge(&mut self, stage: &str, start: Stamp, detail: Value) -> Result<Stamp> {
        let end = self.stamp()?;
        let budget_poll = self.last_budget_poll.get().map(|stamp| {
            json!({
                "observed":stamp,
                "permitted":self.budget.is_none_or(|limit|stamp.process_cpu_ns<limit)
            })
        });
        self.emit(json!({"kind":"charge","stage":stage,"start":start,"end":end,
            "budget_poll":budget_poll,
            "process_cpu_ns":end.process_cpu_ns.checked_sub(start.process_cpu_ns).ok_or("CPU_REVERSED")?,
            "wall_ns":end.wall_ns.checked_sub(start.wall_ns).ok_or("WALL_REVERSED")?,
            "detail":detail}))?;
        Ok(end)
    }
}

fn run() -> Result<()> {
    let mut journal = Journal::new()?;
    let options = options()?;
    journal.budget = options.cpu_budget_ns;
    journal.emit(json!({"kind":"start","options":options,
        "cpu_scope":"whole-process-through-strategy-context-drop; posthoc-reconstruction-separate",
        "budget_policy":"poll-before-new-acquisition-selection-preparation-proof-and-activation; bounded-stage overshoot retained; admission-completed-by-budget for credited winners",
        "bounded_atomic_operations":["native context creation", "one native make search up to 64 complete proofs plus mandatory admission/readback", "one selected proof plus mandatory relation/admission observers", "one complete noise-screen grid", "one preparation", "one source transaction construction", "one activation/readback", "one negative control"],
        "shared_acquisition":"all strategies pay for both native task templates and zero registration",
        "not_claimed":["minimum-strategy-cost","physical-cost-lower-bound","public-network-task-authority",
            "Hepta-training","useful-learning","production-readiness","free-task-acquisition"],
        "proof_retention":"all research proofs and original native winners; original misses reconstructed only after strategy end",
        "noise_reuse":"screening expands real noise; Producer API expands it again; both costs paid",
        "sibling_winners_are_not_additive_chainweight":true}))?;
    research::run(&options, &mut journal)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("PARENT_REUSE_RESEARCH_ERROR:{error}");
        std::process::exit(2);
    }
}
