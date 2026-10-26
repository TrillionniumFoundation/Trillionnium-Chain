//! Research-only, physically sequential setup, miner, receiver and audit phases.
//! The miner receives no Node or verifier; this changes no production relation.
#[path = "support/w1_miner_budget.rs"]
mod research;
#[cfg(test)]
#[path = "../../trnm-crypto-primitives/examples/support/w1_material.rs"]
mod w1_material;

use serde::Serialize;
use serde_json::{json, Value};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    io::Write,
    time::Instant,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SCHEMA: &str = "pon-w1-miner-budget-research-v1";

#[cfg(test)]
fn materials() -> Result<Vec<w1_material::Material>> {
    use trnm_crypto_primitives::pon_work::CELLS;
    let mut values = w1_material::materials(None, None)?;
    let rank = values
        .iter()
        .find(|v| v.name == "rank-one")
        .expect("fixture");
    let (a, b) = (rank.a.clone(), rank.b.clone());
    values.push(w1_material::Material {
        name: "zero-left-rank-one",
        source: "synthetic-fixture",
        a: vec![0; CELLS],
        b,
    });
    values.push(w1_material::Material {
        name: "zero-right-rank-one",
        source: "synthetic-fixture",
        a,
        b: vec![0; CELLS],
    });
    Ok(values)
}

#[derive(Clone, Debug, Serialize)]
pub struct Options {
    setup_budget_ns: u64,
    miner_budget_ns: u64,
    parents: u64,
    max_attempts: u64,
    acquisition: String,
    policy: String,
    parent_policy: String,
    screen_width: u64,
    arm: String,
    cache: String,
    seed: u64,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            setup_budget_ns: 1_000_000_000,
            miner_budget_ns: 100_000_000,
            parents: 1,
            max_attempts: 4096,
            acquisition: "selective".into(),
            policy: "maintenance-only".into(),
            parent_policy: "round-robin".into(),
            screen_width: 1,
            arm: "integer-paired-general".into(),
            cache: "hot".into(),
            seed: 1,
        }
    }
}
impl Options {
    fn validate(&self) -> Result<()> {
        if !(1..=4).contains(&self.parents)
            || !(1..=4096).contains(&self.max_attempts)
            || !(1..=4).contains(&self.screen_width)
            || !["selective", "shared"].contains(&self.acquisition.as_str())
            || ![
                "maintenance-only",
                "zero-only",
                "round-robin",
                "paid-noise-screen",
            ]
            .contains(&self.policy.as_str())
            || !["newest", "round-robin"].contains(&self.parent_policy.as_str())
            || ![
                "prepared-generic",
                "integer-paired-general",
                "structure-specialized",
                "structure-paired",
            ]
            .contains(&self.arm.as_str())
            || !["hot", "cold"].contains(&self.cache.as_str())
        {
            return Err("OPTION_BOUNDS".into());
        }
        Ok(())
    }
    fn miner_tasks(&self) -> Vec<usize> {
        match self.policy.as_str() {
            "maintenance-only" => vec![0],
            "zero-only" => vec![1],
            _ => vec![0, 1],
        }
    }
    fn acquired_tasks(&self) -> Vec<usize> {
        if self.acquisition == "shared" {
            vec![0, 1]
        } else {
            self.miner_tasks()
        }
    }
    fn actual_arm(&self, index: usize) -> &str {
        match self.arm.as_str() {
            "structure-specialized" => ["maintenance-limb", "blocked-zero"][index],
            "structure-paired" => ["maintenance-limb", "blocked-zero-integer-paired"][index],
            _ => &self.arm,
        }
    }
}
fn options() -> Result<Options> {
    let mut value = Options::default();
    let mut seen = BTreeSet::new();
    let mut args = std::env::args().skip(1);
    while let Some(key) = args.next() {
        if key == "--help" {
            println!("pon_w1_miner_budget_research --setup-budget-ns U64 --miner-budget-ns U64 --parents 1..4 --max-attempts 1..4096 --acquisition selective|shared --policy maintenance-only|zero-only|round-robin|paid-noise-screen --parent-policy newest|round-robin --screen-width 1..4 --arm prepared-generic|integer-paired-general|structure-specialized|structure-paired --cache hot|cold --seed U64");
            std::process::exit(0);
        }
        if !seen.insert(key.clone()) {
            return Err("DUPLICATE_OPTION".into());
        }
        let arg = args.next().ok_or("MISSING_VALUE")?;
        match key.as_str() {
            "--setup-budget-ns" => value.setup_budget_ns = arg.parse()?,
            "--miner-budget-ns" => value.miner_budget_ns = arg.parse()?,
            "--parents" => value.parents = arg.parse()?,
            "--max-attempts" => value.max_attempts = arg.parse()?,
            "--acquisition" => value.acquisition = arg,
            "--policy" => value.policy = arg,
            "--parent-policy" => value.parent_policy = arg,
            "--screen-width" => value.screen_width = arg.parse()?,
            "--arm" => value.arm = arg,
            "--cache" => value.cache = arg,
            "--seed" => value.seed = arg.parse()?,
            _ => return Err("UNKNOWN_OPTION".into()),
        }
    }
    value.validate()?;
    Ok(value)
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Stamp {
    process_cpu_ns: u64,
    wall_ns: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Poll {
    phase: &'static str,
    observed: Stamp,
    elapsed_cpu_ns: u64,
    permitted: bool,
}
pub struct Journal {
    origin_cpu: u64,
    origin_wall: Instant,
    sequence: u64,
    phase: &'static str,
    phase_start: Stamp,
    limit: Option<u64>,
    last_poll: Cell<Option<Stamp>>,
    totals: BTreeMap<&'static str, u64>,
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
        .ok_or_else(|| "CPU_OVERFLOW".into())
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
            phase: "setup",
            phase_start: Stamp {
                process_cpu_ns: 0,
                wall_ns: 0,
            },
            limit: None,
            last_poll: Cell::new(None),
            totals: BTreeMap::new(),
        })
    }
    pub fn stamp(&self) -> Result<Stamp> {
        Ok(Stamp {
            process_cpu_ns: process_cpu()?
                .checked_sub(self.origin_cpu)
                .ok_or("CPU_REVERSED")?,
            wall_ns: self.origin_wall.elapsed().as_nanos().try_into()?,
        })
    }
    pub fn elapsed(&self, stamp: Stamp) -> Result<u64> {
        stamp
            .process_cpu_ns
            .checked_sub(self.phase_start.process_cpu_ns)
            .ok_or_else(|| "PHASE_CPU_REVERSED".into())
    }
    pub fn permitted(&self) -> Result<bool> {
        let stamp = self.stamp()?;
        self.last_poll.set(Some(stamp));
        Ok(self
            .limit
            .is_none_or(|b| self.elapsed(stamp).is_ok_and(|n| n < b)))
    }
    pub fn poll(&self) -> Result<Option<Poll>> {
        self.last_poll
            .get()
            .map(|observed| {
                let elapsed_cpu_ns = self.elapsed(observed)?;
                Ok(Poll {
                    phase: self.phase,
                    observed,
                    elapsed_cpu_ns,
                    permitted: self.limit.is_none_or(|b| elapsed_cpu_ns < b),
                })
            })
            .transpose()
    }
    pub fn emit(&mut self, mut row: Value) -> Result<()> {
        let fields = row.as_object_mut().ok_or("RECORD_OBJECT")?;
        fields.insert("schema".into(), json!(SCHEMA));
        fields.insert("sequence".into(), json!(self.sequence));
        fields.insert("phase".into(), json!(self.phase));
        fields.insert("observed".into(), json!(self.stamp()?));
        let mut stdout = std::io::stdout().lock();
        serde_json::to_writer(&mut stdout, &row)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
        self.sequence += 1;
        Ok(())
    }
    pub fn charge(&mut self, stage: &str, start: Stamp, detail: Value) -> Result<Stamp> {
        let end = self.stamp()?;
        self.emit(json!({"kind":"charge","stage":stage,"start":start,"end":end,"process_cpu_ns":end.process_cpu_ns-start.process_cpu_ns,"wall_ns":end.wall_ns-start.wall_ns,"budget_poll":self.poll()?,"detail":detail}))?;
        Ok(end)
    }
    pub fn transition(
        &mut self,
        next: &'static str,
        limit: Option<u64>,
        mut detail: Value,
    ) -> Result<Stamp> {
        let end = self.stamp()?;
        let begin = self.phase_start;
        let from = self.phase;
        let elapsed = self.elapsed(end)?;
        if from == "setup" && self.limit.is_some_and(|limit| elapsed > limit) {
            detail["complete"] = json!(false);
            detail["status"] = json!("setup-cpu-budget-stopped");
        }
        let poll = self.poll()?;
        self.totals.insert(from, elapsed);
        self.phase = next;
        self.phase_start = end;
        self.limit = limit;
        self.last_poll.set(None);
        self.emit(json!({"kind":"boundary","from":from,"to":next,"begin":begin,"end":end,"elapsed_cpu_ns":elapsed,"terminal_poll":poll,"detail":detail,"boundary_encoding_charged_to_next_phase":true}))?;
        Ok(end)
    }
}
fn run() -> Result<()> {
    let mut journal = Journal::new()?;
    let options = options()?;
    journal.limit = Some(options.setup_budget_ns);
    journal.emit(json!({"kind":"start","options":options,"phase_order":["setup","miner","receiver","audit","done"],"budget_units":"process-cpu-nanoseconds; setup P and miner B separately bounded","miner_has_node_or_verifier":false,"proof_completion":"full original bytes encoded/flushed before availability stamp","parent_bank":"finite historical ancestors of one paid native chain, not arbitrary fork forest","native_task_authority":"isolated disclosed development signers and continuity genesis","physical_cost_lower_bound":false,"production_activation":false}))?;
    research::run(&options, &mut journal)
}
fn main() {
    if let Err(error) = run() {
        eprintln!("MINER_BUDGET_RESEARCH_ERROR:{error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod option_tests {
    use super::*;
    #[test]
    fn acquisition_is_selective_and_arms_are_task_bound() {
        let mut o = Options::default();
        assert_eq!(o.acquired_tasks(), vec![0]);
        o.policy = "zero-only".into();
        assert_eq!(o.acquired_tasks(), vec![1]);
        o.acquisition = "shared".into();
        assert_eq!(o.acquired_tasks(), vec![0, 1]);
        o.arm = "structure-paired".into();
        assert_eq!(o.actual_arm(0), "maintenance-limb");
        assert_eq!(o.actual_arm(1), "blocked-zero-integer-paired");
    }
    #[test]
    fn caps_and_policy_names_reject_unregistered_values() {
        let mut o = Options {
            parents: 0,
            ..Options::default()
        };
        assert!(o.validate().is_err());
        o.parents = 4;
        o.max_attempts = 4097;
        assert!(o.validate().is_err());
        o.max_attempts = 1;
        o.policy = "free-unknown".into();
        assert!(o.validate().is_err());
    }
}
