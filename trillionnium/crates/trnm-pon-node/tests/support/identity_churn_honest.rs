//! Original t=1/5/9, seven-block rounds and independent ordinary history import.
use super::{identity_work as work, plan::Plan, support};
use serde_json::{json, Value};
use std::{net::SocketAddr, time::Instant};
use trnm_pon_node::{
    ingress::{
        self,
        public_v3::{PublicRequestObserver, Request, SubmitPhase},
    },
    Node, Packet, Settings,
};
use trnm_protocol::pon_wire::hash;

fn hostile(observer: &PublicRequestObserver, business_bodies: &[[u8; 32]]) -> Value {
    let snapshot = observer.snapshot();
    let rows: Vec<_> = snapshot
        .records
        .iter()
        .filter(|r| {
            r.operation == Some(1)
                && r.body_digest
                    .as_ref()
                    .is_some_and(|d| !business_bodies.contains(d))
                && r.full_work_accepted == Some(true)
                && r.dispatch_accepted == Some(false)
                && r.submit_phases.iter().any(|p| {
                    p.phase == SubmitPhase::Admission && p.completed && p.accepted == Some(false)
                })
        })
        .collect();
    json!({"accepted_work_admission_refusals":rows.len(),"admission_cpu_ns":rows.iter().try_fold(0_u64,|s,r|
        s.checked_add(r.submit_phases.iter().find(|p|p.phase==SubmitPhase::Admission)?.thread_cpu_ns?)),
        "scope":"live bounded observer; excludes exact prepared honest bodies; final reader must bind every hostile body to actual actor files"})
}
pub fn rounds(
    address: SocketAddr,
    settings: &Settings,
    business: &[Packet],
    verifier: &mut Node,
    observer: &PublicRequestObserver,
    plan: &Plan,
    window: (u64, u64),
) -> Value {
    let (epoch, end) = window;
    let mut after = verifier.read_active().unwrap().0;
    let mut next = 0;
    let mut submissions = Vec::new();
    let mut history = Vec::new();
    let mut rounds = Vec::new();
    let mut errors = Vec::new();
    let business_bodies: Vec<_> = business
        .iter()
        .map(|p| {
            hash(
                b"public-request-body-v3",
                &[&serde_json::to_vec(&Request::Submit {
                    packet: hex::encode(p.encode().unwrap()),
                })
                .unwrap()],
            )
        })
        .collect();
    for round in 0..plan.rounds {
        let scheduled = epoch + 1_000_000_000 + round as u64 * 4_000_000_000;
        while support::monotonic() < scheduled.min(end) {
            support::ready_sleep();
        }
        let started = support::monotonic();
        let hostile_before = hostile(observer, &business_bodies);
        let final_index = (round + 1) * 7;
        while next < final_index
            && support::monotonic() < end
            && submissions.len() < plan.honest_submission_cap
        {
            let mut row = support::call(
                address,
                settings,
                Request::Submit {
                    packet: hex::encode(business[next].encode().unwrap()),
                },
                73,
                epoch,
                end,
            );
            row["packet_index"] = json!(next);
            row["height"] = json!(business[next].header.height);
            if support::on_time(&row) {
                next += 1;
            }
            submissions.push(row);
        }
        let tip = business[final_index - 1].id().unwrap();
        let included = business[round * 7].id().unwrap();
        let transaction = hash(b"tx-id", &[&business[round * 7].transactions[0]]);
        let mut observation = None;
        while next == final_index
            && support::monotonic() < end
            && history.len() < plan.honest_history_cap
        {
            let mut row = support::call(
                address,
                settings,
                Request::History {
                    tip: hex::encode(tip),
                    after: hex::encode(after),
                },
                74,
                epoch,
                end,
            );
            if support::on_time(&row) {
                let import_cpu = work::cpu();
                let import_wall = Instant::now();
                let result =
                    serde_json::from_value::<ingress::Page>(row["response"]["value"].clone())
                        .map_err(|e| e.to_string())
                        .and_then(|page| {
                            ingress::receive_public_page_from(
                                verifier,
                                address,
                                page,
                                tip,
                                after,
                                support::now(),
                            )
                            .map_err(|e| e.to_string())
                        });
                row["client_import"] = json!({"thread_cpu_ns":work::elapsed(import_cpu),"wall_ns":import_wall.elapsed().as_nanos(),"succeeded":result.is_ok()});
                match result {
                    Ok(id) => after = id,
                    Err(e) => errors.push(e),
                }
                if after == tip {
                    let confirm_cpu = work::cpu();
                    let confirm_wall = Instant::now();
                    let result = verifier.confirmation(transaction, included, support::now());
                    row["client_confirmation"] = json!({"thread_cpu_ns":work::elapsed(confirm_cpu),"wall_ns":confirm_wall.elapsed().as_nanos(),"succeeded":result.is_ok()});
                    match result {
                        Ok(value) => observation = Some(value),
                        Err(e) => errors.push(e.to_string()),
                    }
                }
            }
            history.push(row);
            if observation.is_some() {
                break;
            }
        }
        let hostile_after = hostile(observer, &business_bodies);
        let ended = support::monotonic();
        let confirmed = observation.as_ref().is_some_and(|v| {
            v.confirmed && !v.finalized && !v.execution_authority && v.depth == Some(6)
        }) && ended < end;
        rounds.push(json!({"round":round,"scheduled_ns":scheduled-epoch,"started_ns":started-epoch,"ended_ns":ended-epoch,
            "confirmed_inside_pressure_window":confirmed,"transaction":hex::encode(transaction),"included_block":hex::encode(included),
            "tip":hex::encode(tip),"observation":observation,"receiver_hostile_before":hostile_before,"receiver_hostile_after":hostile_after}));
        if !confirmed {
            break;
        }
    }
    for round in rounds.len()..plan.rounds {
        rounds.push(json!({"round":round,"scheduled_ns":1_000_000_000+round as u64*4_000_000_000,
        "started_ns":null,"ended_ns":null,"confirmed_inside_pressure_window":false,"reason":"not-started-after-failed-round"}));
    }
    json!({"submissions":submissions,"history":history,"confirmations":rounds,"verifier_errors":errors,
        "all_signed_rounds_confirmed_in_window":plan.rounds==3 && rounds.len()==3 && rounds.iter().all(|r|r["confirmed_inside_pressure_window"]==true),
        "client_final_tip":hex::encode(verifier.read_active().unwrap().0),"client_native_history_arithmetic":verifier.native_history_arithmetic_observation()})
}
