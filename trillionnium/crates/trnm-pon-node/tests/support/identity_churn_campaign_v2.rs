//! v2 native campaign owner; full execution remains independently closed.
use super::{
    actor_v2::SCHEMA,
    controller_v2,
    evidence::{self, Budget},
    exec_identity, identity_work as work, limits,
    plan::{Mode, Plan},
    support,
};
use serde_json::{json, Value};
use std::{fs, io, path::Path, time::Instant};
use trnm_pon_node::{development_public, Node};
const TERMINAL_BYTES: u64 = 64 * 1024;
struct Owner<'a> {
    path: &'a Path,
    metadata: Budget,
    terminal: Budget,
    preparation: Budget,
    completed: bool,
}
impl<'a> Owner<'a> {
    fn new(path: &'a Path, root_limit: u64, preparation_limit: u64) -> Self {
        assert!(root_limit > TERMINAL_BYTES);
        Self {
            path,
            metadata: Budget::new(root_limit - TERMINAL_BYTES),
            terminal: Budget::new(TERMINAL_BYTES),
            preparation: Budget::new(preparation_limit),
            completed: false,
        }
    }
    fn fail(&mut self, reason: &str, extra: Value) -> io::Result<()> {
        if self.terminal.used == 0 {
            self.terminal.write(
                &self.path.join("cap-terminal.json"),
                &json!({"schema":SCHEMA,"kind":"campaign-terminal","reason":reason,"extra":extra,
                "observed_ns":support::monotonic(),"full_campaign_qualified":false}),
                TERMINAL_BYTES,
            )?;
        }
        Ok(())
    }
    fn save(&mut self, name: &str, row: &Value) -> io::Result<()> {
        if let Err(error) = self
            .metadata
            .write(&self.path.join(name), row, self.metadata.limit)
        {
            self.fail(
                "root-evidence-write",
                json!({"file":name,"error":error.to_string(),"budget":self.metadata.summary()}),
            )?;
            return Err(error);
        }
        Ok(())
    }
    fn prepare(&mut self, row: &Value) -> io::Result<()> {
        if let Err(error) = self.preparation.write(
            &self.path.join("preparation.json"),
            row,
            self.preparation.limit,
        ) {
            self.fail(
                "preparation-evidence-write",
                json!({"error":error.to_string(),"budget":self.preparation.summary()}),
            )?;
            return Err(error);
        }
        Ok(())
    }
}
impl Drop for Owner<'_> {
    fn drop(&mut self) {
        if !self.completed {
            let _=self.fail("campaign-left-before-final-report",json!({"thread_panicking":std::thread::panicking(),
            "generic_drop_diagnostic":true,"original_error_status":"UNKNOWN until logs and retained files reconciliation"}));
        }
    }
}
fn mechanism_complete(phases: &[Value], plan: &Plan) -> bool {
    phases.iter().all(|p| {
        p["paid_settled"] == true
            && p["cold_equal"] == true
            && p["children"].as_array().is_some_and(|children| {
                children.len() == plan.actors
                    && children
                        .iter()
                        .all(|c| c["exit_success"] == true && c["parent_forced_kill"] == false)
            })
            && p["hostile_candidates"].as_array().is_some_and(|rows| {
                !rows.is_empty()
                    && rows
                        .iter()
                        .all(|r| r["live_absent"] == true && r["cold_absent"] == true)
            })
            && if plan.qualification {
                p["post_prefix_work"]["retained_identities"] == 4096
                    && p["honest"]["all_signed_rounds_confirmed_in_window"] == true
                    && (p["mode"] != "fresh-identities"
                        || p["final_work"]["full_capacity_skips"]
                            .as_u64()
                            .zip(p["post_prefix_work"]["full_capacity_skips"].as_u64())
                            .is_some_and(|(a, b)| a > b))
            } else {
                p["post_prefix_work"]["retained_identities"]
                    == plan.actors * plan.prefix_calls_per_actor
                    && p["final_work"]["retained_identities"]
                        == plan.actors
                            * (plan.prefix_calls_per_actor + plan.pressure_calls_per_actor)
            }
    })
}
pub fn run(path: &Path, plan: Plan) -> io::Result<Value> {
    plan.validate();
    exec_identity::create_directory(path)?;
    let mut owner = Owner::new(path, limits::ROOT_NATIVE_BYTES, 8 * evidence::MIB);
    // This function is reached only from an explicitly selected owned binary.
    // The installation precedes every Node open and producer/actor allocation.
    let installed = limits::install(false).inspect_err(|error| {
        let _ = owner.fail("parent-process-limits", json!({"error":error.to_string()}));
    })?;
    owner.save("process-limits.json", &installed)?;
    let execution = exec_identity::Caller::new(plan.qualification).inspect_err(|error| {
        let _ = owner.fail(
            "execution-caller-inputs",
            json!({"error":error.to_string()}),
        );
    })?;
    owner.save("plan.json",&json!({"schema":SCHEMA,"plan":plan,"public_resource_policy":support::policy_observation(),
        "evidence_limits":limits::descriptor(),"capacity_required":4096,"fresh_post_capacity_required":1,
        "pressure_coverage_percent":90,"maximum_non_depleted_gap_ns":1_000_000_000_u64,
        "prefix_budget_status":"predeclared-collection-budget-not-a-completion-upper-bound",
        "cost_status":"FULL_ATTEMPTS_RETAINED_GLOBAL_COST_UNPROVEN","execution_caller":execution.receipt}))?;
    let settings = support::settings();
    let mut producer =
        Node::open_with_authenticated_state(&path.join("honest-miner"), settings.clone(), 1)
            .unwrap();
    let prepare_cpu = work::cpu();
    let prepare_start = Instant::now();
    let seed = work::seed(&mut producer, &settings);
    let mut business = Vec::new();
    for index in 0..21 {
        let txs = if index % 7 == 0 {
            vec![support::signed_transfer(
                &settings,
                1025 + (index / 7) as u64,
                development_public(1).unwrap(),
            )]
        } else {
            vec![]
        };
        let p = producer
            .make_consensus_maintenance(
                producer.active().unwrap().0,
                txs,
                development_public(0).unwrap(),
                settings.genesis_time() + (5 + index as u64) * 10,
                4096,
            )
            .unwrap();
        let id = producer.admit(&p, support::now()).unwrap();
        producer.activate(id).unwrap();
        business.push(p);
    }
    assert_eq!(business[0].header.parent, seed[3].id().unwrap());
    let preparation = json!({"schema":SCHEMA,"seed_packets":seed.iter().map(|p|hex::encode(p.encode().unwrap())).collect::<Vec<_>>(),
        "business_packets":business.iter().map(|p|hex::encode(p.encode().unwrap())).collect::<Vec<_>>(),
        "cpu_ns":work::elapsed(prepare_cpu),"wall_ns":prepare_start.elapsed().as_nanos(),"node_search_attempt_counts":null,
        "scope":"actual signed 1024-transfer seed and 21-block parent-linked business; Node unexposed search counts stay unknown"});
    owner.prepare(&preparation)?;
    let modes = if plan.qualification {
        vec![Mode::HonestOnly, Mode::ReplayOnly, Mode::FreshIdentities]
    } else {
        vec![Mode::FreshIdentities]
    };
    let mut phases = Vec::new();
    let mut stopped = false;
    for mode in modes {
        if stopped {
            phases.push(
                json!({"schema":SCHEMA,"kind":"phase-not-started","mode":mode,
            "error":"not-started-after-failed-v2-owner"}),
            );
            continue;
        }
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            controller_v2::phase(
                &path.join(mode.name()),
                &settings,
                &seed,
                &business,
                mode,
                &plan,
                &execution,
            )
        }));
        let result = match outcome {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => {
                json!({"schema":SCHEMA,"kind":"phase-error","mode":mode,"error":error.to_string()})
            }
            Err(_) => {
                json!({"schema":SCHEMA,"kind":"phase-error","mode":mode,"error":"native phase panicked; partial files retained"})
            }
        };
        stopped = result.get("error").is_some()
            || path.join(mode.name()).join("terminal.json").exists()
            || result["children"].as_array().is_none_or(|rows| {
                rows.iter().any(|c| {
                    c["stage_terminal"].is_object()
                        || c["exit_success"] != true
                        || c["log_capture"]["cap_reached"] != false
                        || !c["log_capture"]["io_error"].is_null()
                })
            });
        if stopped {
            owner.fail(
                "phase-owner-stopped",
                json!({"mode":mode,"phase_error":result.get("error")}),
            )?;
        }
        phases.push(result);
    }
    let node_files = limits::node_files(path).inspect_err(|error| {
        let _ = owner.fail("node-final-inventory", json!({"error":error.to_string()}));
    })?;
    owner.save("node-files.json", &node_files)?;
    let native_mechanism_complete = !stopped && mechanism_complete(&phases, &plan);
    let report = json!({"schema":SCHEMA,"kind":"campaign","plan":plan,"preparation_file":"preparation.json",
        "phases":phases.iter().map(|p|json!({"mode":p["mode"],"file":format!("{}/report.json",p["mode"].as_str().unwrap()),"error":p.get("error")})).collect::<Vec<_>>(),
        "native_mechanism_complete":native_mechanism_complete,"external_reader_required":true,"finite_service_qualified":false,
        "cost_status":"FULL_ATTEMPTS_RETAINED_GLOBAL_COST_UNPROVEN","work_hardness_accepted":false,"independent_operators":false,
        "wan_qualified":false,"production_activation":false,"merge_ready":false,"full_v2_io_boundary_implemented":false,
        "root_metadata_before_report":owner.metadata.summary(),"preparation_budget":owner.preparation.summary(),
        "root_terminal_budget":owner.terminal.summary(),"parent_process_after":limits::observation()?});
    owner.save("report.json", &report)?;
    owner.completed = true;
    Ok(report)
}
#[test]
fn preparation_cap_and_poison_keep_the_separately_reserved_root_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let mut owner = Owner::new(dir.path(), TERMINAL_BYTES + 4096, 1);
    owner.save("plan.json", &json!({"frozen":true})).unwrap();
    assert!(owner.prepare(&json!({"larger":true})).is_err());
    assert!(owner.preparation.cap_reached && owner.preparation.poisoned);
    let first = fs::read(dir.path().join("cap-terminal.json")).unwrap();
    assert!(owner.prepare(&json!({"later":true})).is_err());
    assert_eq!(
        fs::read(dir.path().join("cap-terminal.json")).unwrap(),
        first
    );
    assert!(!dir.path().join("preparation.json").exists());
    assert!(owner.metadata.used + owner.terminal.used <= TERMINAL_BYTES + 4096);
    assert!(dir.path().join("plan.json").exists());
}
