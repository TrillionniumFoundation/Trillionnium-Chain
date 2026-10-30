//! Opt-in actual 24-process identity-capacity supplement. Old campaigns unchanged.
#[path = "support/identity_churn_actor.rs"]
mod actor;
#[allow(dead_code)]
#[path = "support/identity_churn_actor_v2.rs"]
mod actor_v2;
#[allow(dead_code)]
#[path = "support/identity_churn_campaign_native_io_v1.rs"]
mod campaign_native_io_v1;
#[allow(dead_code)]
#[path = "support/identity_churn_campaign_v2.rs"]
mod campaign_v2;
#[path = "support/identity_churn_controller.rs"]
mod controller;
#[allow(dead_code)]
#[path = "support/identity_churn_controller_native_io_v1.rs"]
mod controller_native_io_v1;
#[allow(dead_code)]
#[path = "support/identity_churn_controller_v2.rs"]
mod controller_v2;
#[allow(dead_code)]
#[path = "support/identity_churn_evidence.rs"]
mod evidence;
#[allow(dead_code)]
#[path = "support/identity_churn_exec.rs"]
mod exec_identity;
#[path = "support/identity_churn_honest.rs"]
mod honest;
#[allow(dead_code)]
#[path = "support/identity_churn_work.rs"]
mod identity_work;
#[path = "support/identity_churn_limit_control.rs"]
mod limit_control;
#[allow(dead_code)]
#[path = "support/identity_churn_limits.rs"]
mod limits;
#[allow(dead_code)]
#[path = "support/identity_churn_logs.rs"]
mod logs;
#[allow(dead_code)]
#[path = "support/identity_churn_native_io_v1.rs"]
mod native_io_v1;
#[path = "support/identity_churn_plan.rs"]
mod plan;
#[allow(dead_code)]
#[path = "support/identity_churn_samples.rs"]
mod samples;
#[allow(dead_code)]
#[path = "support/multiprocess_support.rs"]
mod support;
use serde_json::{json, Value};
use std::{fs, path::Path, time::Instant};
use trnm_pon_node::{development_public, Node};

#[test]
fn preregistration_rejects_hidden_parallelism_or_changed_deadlines() {
    let original = plan::Plan::full();
    original.validate();
    let mut identities = std::collections::BTreeSet::new();
    for worker in 0..original.actors {
        for slot in 0..original.actor_total_call_cap {
            assert!(identities.insert(original.index(worker, slot)));
        }
    }
    assert_eq!(identities.len(), 24 * 480);
    for key in ["actors", "call_seconds", "rounds"] {
        let mut changed = serde_json::to_value(&original).unwrap();
        changed[key] = json!(if key == "actors" {
            25
        } else if key == "call_seconds" {
            3
        } else {
            2
        });
        let altered: plan::Plan = serde_json::from_value(changed).unwrap();
        assert!(
            std::panic::catch_unwind(|| altered.validate()).is_err(),
            "{key}"
        );
    }
    let mut unknown = serde_json::to_value(original).unwrap();
    unknown["extra_workers"] = json!(1);
    assert!(serde_json::from_value::<plan::Plan>(unknown).is_err());
}

fn campaign(path: &Path, plan: plan::Plan) -> Value {
    plan.validate();
    fs::create_dir(path).unwrap();
    let settings = support::settings();
    let mut producer =
        Node::open_with_authenticated_state(&path.join("honest-miner"), settings.clone(), 1)
            .unwrap();
    let prepare_cpu = identity_work::cpu();
    let prepare_start = Instant::now();
    let seed = identity_work::seed(&mut producer, &settings);
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
    let preparation = json!({"schema":plan::SCHEMA,"seed_packets":seed.iter().map(|p|hex::encode(p.encode().unwrap())).collect::<Vec<_>>(),
        "business_packets":business.iter().map(|p|hex::encode(p.encode().unwrap())).collect::<Vec<_>>(),
        "cpu_ns":identity_work::elapsed(prepare_cpu),"wall_ns":prepare_start.elapsed().as_nanos(),"node_search_attempt_counts":null,
        "scope":"actual signed 1024-transfer seed and 21-block parent-linked business; Node unexposed search counts stay unknown"});
    support::write_new(&path.join("preparation.json"), &preparation);
    support::write_new(
        &path.join("plan.json"),
        &json!({"schema":plan::SCHEMA,"plan":plan,"public_resource_policy":support::policy_observation(),
        "capacity_required":4096,"fresh_post_capacity_required":1,"pressure_coverage_percent":90,"maximum_non_depleted_gap_ns":1_000_000_000_u64,
        "prefix_budget_status":"predeclared-collection-budget-not-a-completion-upper-bound","cost_status":"UNKNOWN_FULL_ATTEMPT_BYTES_NOT_RETAINED"}),
    );
    let modes = if plan.qualification {
        vec![
            plan::Mode::HonestOnly,
            plan::Mode::ReplayOnly,
            plan::Mode::FreshIdentities,
        ]
    } else {
        vec![plan::Mode::FreshIdentities]
    };
    let mut phases = Vec::new();
    for mode in modes {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            controller::phase(
                &path.join(mode.name()),
                &settings,
                &seed,
                &business,
                mode,
                &plan,
            )
        }));
        phases.push(match result {Ok(v)=>v,Err(_)=>json!({"schema":plan::SCHEMA,"kind":"phase-error","mode":mode,"error":"native phase panicked; partial files retained"})});
    }
    let native_mechanism_complete = phases.iter().all(|p| {
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
    });
    let report = json!({"schema":plan::SCHEMA,"kind":"campaign","plan":plan,"preparation_file":"preparation.json",
        "phases":phases.iter().map(|p|json!({"mode":p["mode"],"file":format!("{}/report.json",p["mode"].as_str().unwrap()),"error":p.get("error")})).collect::<Vec<_>>(),
        "native_mechanism_complete":native_mechanism_complete,"external_reader_required":true,"finite_service_qualified":false,
        "cost_status":"UNKNOWN_FULL_ATTEMPT_BYTES_NOT_RETAINED","work_hardness_accepted":false,"independent_operators":false,
        "wan_qualified":false,"production_activation":false,"merge_ready":false});
    support::write_new(&path.join("report.json"), &report);
    report
}
#[test]
#[ignore = "child-process entry; explicit immutable parent job only"]
fn identity_actor_entry() {
    actor::run(Path::new(
        &std::env::var_os("TRNM_IDENTITY_ACTOR_JOB").expect("actor job"),
    ));
}
#[test]
#[ignore = "owned v2 actor entry; requires exact immutable parent job and inherited limits"]
fn identity_actor_entry_v2() {
    actor_v2::run(Path::new(
        &std::env::var_os("TRNM_IDENTITY_ACTOR_JOB").expect("actor job"),
    ))
    .expect("v2 actor; raw failure retained");
}
#[test]
#[ignore = "opt-in full same-host capacity and three 30s matched windows; root must review frozen budget before collection"]
fn separate_process_identity_capacity_and_signed_confirmation_supplement() {
    let out = std::env::var_os("TRNM_IDENTITY_CAMPAIGN_DIR")
        .expect("fresh source-bound collector output");
    let report = campaign(Path::new(&out), plan::Plan::full());
    assert_eq!(
        report["native_mechanism_complete"],
        true,
        "partial evidence retained at {}",
        Path::new(&out).display()
    );
}
#[test]
#[ignore = "explicit small actual subprocess/paid TCP control; not capacity, honest-service or release qualification"]
fn two_process_real_w1_prefix_and_pressure_control() {
    let out = std::env::var_os("TRNM_IDENTITY_CONTROL_DIR").expect("fresh small-control output");
    let report = campaign(Path::new(&out), plan::Plan::control());
    assert_eq!(report["native_mechanism_complete"], true, "{report}");
    assert_eq!(report["finite_service_qualified"], false);
}

#[test]
#[ignore = "v2 full owner chain remains closed until its complete byte/VM/log/sample ledger is implemented and reviewed"]
fn separate_process_identity_capacity_and_signed_confirmation_supplement_v2() {
    assert!(
        limits::full_route_ready(),
        "full v2 collection is unavailable: incomplete native owner/writer chain; no v1 fallback"
    );
    let out = std::env::var_os("TRNM_IDENTITY_CAMPAIGN_DIR")
        .expect("fresh source-bound collector output");
    let report = campaign_v2::run(Path::new(&out), plan::Plan::full())
        .expect("v2 campaign; failure files retained");
    assert_eq!(report["native_mechanism_complete"], true, "{report}");
}
#[test]
#[ignore = "v2 owned two-actor control; retains the original two-second pressure and all assertions; no capacity/service qualification"]
fn two_process_real_w1_prefix_and_pressure_v2_control() {
    let out =
        std::env::var_os("TRNM_IDENTITY_CONTROL_V2_DIR").expect("fresh v2 small-control output");
    let report = campaign_v2::run(Path::new(&out), plan::Plan::control())
        .expect("v2 control; failure files retained");
    assert_eq!(report["native_mechanism_complete"], true, "{report}");
    assert_eq!(report["finite_service_qualified"], false);
    assert_eq!(report["full_v2_io_boundary_implemented"], false);
}

#[test]
#[ignore = "new real-inode storage bridge remains closed until original caller, whole-writer and strict-reader qualification"]
fn separate_process_identity_capacity_and_signed_confirmation_supplement_native_io_v1() {
    assert!(
        native_io_v1::full_route_ready(),
        "native I/O full collection unavailable: original three-FD caller/whole-writer/strict-reader not qualified; no V1/V2 fallback"
    );
    let report = campaign_native_io_v1::run(plan::Plan::full())
        .expect("native I/O campaign; original failures and partial files retained");
    assert_eq!(report["native_mechanism_complete"], true, "{report}");
    assert_eq!(report["full_W1_4097_qualified"], false);
}

#[test]
#[ignore = "PN1 public component collector only; requires real source-bound preparation and three Python input FDs"]
fn two_process_real_w1_prefix_and_pressure_native_io_component_v1() {
    assert_eq!(
        std::env::var("TRNM_IDENTITY_COMPONENT_PROFILE").as_deref(),
        Ok("pn1-native-io-three-fd-component-v1")
    );
    let report = campaign_native_io_v1::run(plan::Plan::control())
        .expect("same-code native I/O finite component; retain every failure and partial");
    assert_eq!(report["native_mechanism_complete"], true, "{report}");
    assert_eq!(report["plan"]["qualification"], false);
    for flag in [
        "finite_service_qualified",
        "whole_writer_qualified",
        "original_three_FD_caller_qualified",
        "independent_reader_qualified",
        "full_W1_4097_qualified",
        "merge_ready",
    ] {
        assert_eq!(report[flag], false, "{flag}: {report}");
    }
}

#[test]
#[ignore = "explicit reservation-v2 finite component; requires original source-bound preparation and three Python input FDs"]
fn two_process_real_w1_prefix_and_pressure_native_io_reservation_component_v2() {
    assert_eq!(
        std::env::var("TRNM_IDENTITY_COMPONENT_PROFILE").as_deref(),
        Ok("pn1-native-io-three-fd-reservation-component-v2")
    );
    let report = campaign_native_io_v1::run_reservation_v2()
        .expect("reservation-v2 finite component; retain every original failure and partial");
    assert_eq!(
        report["schema"],
        "native-public-v3-identity-churn-native-io-reservation-v2"
    );
    assert_eq!(report["native_mechanism_complete"], true, "{report}");
    assert_eq!(
        report["plan"],
        serde_json::to_value(plan::Plan::control()).unwrap()
    );
    assert_eq!(
        report["native_io_storage"]["sqlite_domain"],
        trnm_sqlite_io_boundary::RESERVATION_DOMAIN_V2
    );
    for flag in [
        "finite_service_qualified",
        "whole_writer_qualified",
        "original_three_FD_caller_qualified",
        "independent_reader_qualified",
        "full_W1_4097_qualified",
        "merge_ready",
    ] {
        assert_eq!(report[flag], false, "{flag}: {report}");
    }
}
