use super::*;
use crate::public_submit::{
    pq::{
        submit_with_pq_parent_recovery, NativeRecoveryAttempt, PqRecoveryAttempt,
        PqRecoveryCampaign, PqSubmitRecoveryOutcome,
    },
    SubmitRecoveryPlan,
};
use std::path::Path;
#[path = "recovery_cases/fixture.rs"]
mod fixture;
#[path = "recovery_cases/proxy.rs"]
mod proxy;
use fixture::Harness;
use proxy::{Fault, Proxy};

fn plan() -> SubmitRecoveryPlan {
    SubmitRecoveryPlan::new(Duration::from_secs(10)).unwrap()
}
fn native_rows(outcome: &PqSubmitRecoveryOutcome) -> Vec<&NativeRecoveryAttempt> {
    outcome
        .attempts
        .iter()
        .filter_map(|attempt| match attempt {
            PqRecoveryAttempt::Native(row) => Some(row),
            PqRecoveryAttempt::History(_) => None,
        })
        .collect()
}
fn metadata(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path.join("journal")).unwrap()).unwrap()
}
fn positive(encrypted: bool) {
    let mut harness = Harness::new(encrypted, 2);
    let raw = harness.packets[1]
        .encode_for_settings(&harness.settings)
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let campaign = directory.path().join("campaign");
    let original = plan();
    harness.reopen();
    let target = crate::Packet::decode_for_settings(&raw, &harness.settings).unwrap();
    let parent = harness.packets[0].id().unwrap();
    let id = target.id().unwrap();
    let created = harness
        .recover(
            harness.native_address,
            &target,
            PqRecoveryCampaign::Create {
                directory: &campaign,
                initial_sequence: 1,
                plan: original,
            },
        )
        .unwrap();
    assert!(
        created.ok && created.membership_observed && created.may_advance_dependency,
        "{:?}",
        created.failure
    );
    assert!(!created.submission_outcome_uncertain && created.pending.is_none());
    assert!(!created.production_activation && !created.whole_directory_rollback_protection);
    assert_eq!(created.history_transport, "pq-signed-plaintext-loopback");
    assert_eq!(
        created.native_transport,
        if encrypted {
            "hybrid-tls13-loopback"
        } else {
            "authenticated-plaintext-loopback"
        }
    );
    assert_eq!(created.restored_parent_memberships, [hex::encode(parent)]);
    let native = native_rows(&created);
    assert_eq!(
        native.iter().map(|row| row.sequence).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(
        native
            .iter()
            .map(|row| row.packet.as_str())
            .collect::<Vec<_>>(),
        [hex::encode(id), hex::encode(parent), hex::encode(id)]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        native[0].authenticated_response.as_ref().unwrap()["value"]["error"],
        "UNKNOWN_PARENT"
    );
    assert!(native.iter().all(|row| row.receipt_persisted
        && row.client_error.is_none()
        && row.journal_error.is_none()));
    assert!(
        created.acknowledged_packets.contains(&hex::encode(parent))
            && created.acknowledged_packets.contains(&hex::encode(id))
    );
    for attempt in &created.attempts {
        if let PqRecoveryAttempt::History(row) = attempt {
            assert!(row.metrics.solution_found && row.authenticated_reply.is_some());
        }
    }
    assert_eq!(created.reserved_calls, Some(created.attempts.len() as u8));
    assert!(created.total_elapsed_ns <= created.original_budget_ns);
    assert_eq!(harness.records(), 3);
    assert_eq!(
        harness
            .owner
            .lock()
            .unwrap()
            .packet(id)
            .unwrap()
            .encode_for_settings(&harness.settings)
            .unwrap(),
        raw
    );
    let before = metadata(&campaign);
    harness.reopen();
    let resumed = harness
        .recover(
            harness.native_address,
            &target,
            PqRecoveryCampaign::Resume {
                directory: &campaign,
                initial_sequence: 1,
            },
        )
        .unwrap();
    assert!(
        resumed.ok && resumed.may_advance_dependency,
        "{:?}",
        resumed.failure
    );
    assert!(native_rows(&resumed).is_empty());
    assert!(resumed.reserved_calls.unwrap() > created.reserved_calls.unwrap());
    let after = metadata(&campaign);
    assert_eq!(before["epoch"], after["epoch"]);
    assert_eq!(before["binding"], after["binding"]);
    assert_eq!(before["operations"], after["operations"]);
    assert_eq!(harness.records(), 3);
}
#[test]
fn actual_npq6_plain_parent_recovery_and_cold_membership_keep_one_original_campaign() {
    positive(false);
}
#[test]
fn actual_npq6_hybrid_tls_parent_recovery_and_cold_membership_keep_one_original_campaign() {
    positive(true);
}

#[test]
fn actual_npq6_lost_ack_and_cold_resume_reuse_exact_wire_without_history_consuming_sequence() {
    let mut harness = Harness::new(false, 1);
    let target = harness.packets[0].clone();
    let proxy = Proxy::start(
        harness.native_address,
        harness.policy.clone(),
        Fault::LostAckThenMalformedFrame,
    );
    let directory = tempfile::tempdir().unwrap();
    let campaign = directory.path().join("campaign");
    let original = plan();
    harness.reopen();
    let first = harness
        .recover(
            proxy.address,
            &target,
            PqRecoveryCampaign::Create {
                directory: &campaign,
                initial_sequence: 1,
                plan: original,
            },
        )
        .unwrap();
    assert!(!first.ok && first.submission_outcome_uncertain && !first.may_advance_dependency);
    assert!(!first.membership_observed && first.acknowledged_packets.is_empty());
    let pending = first.pending.as_ref().unwrap();
    assert_eq!((pending.sequence, pending.reserved_attempts), (1, 2));
    let native = native_rows(&first);
    assert_eq!(native.len(), 2);
    assert!(native[0].retryable_transport_eof);
    assert!(!native[1].retryable_transport_eof);
    assert!(native
        .iter()
        .all(|row| !row.receipt_persisted && row.sequence == 1));
    assert_eq!(
        first.attempts.len(),
        3,
        "one paid Head precedes two actual native attempts"
    );
    let before = metadata(&campaign);
    assert_eq!(harness.records(), 1);
    assert_eq!(
        harness.owner.lock().unwrap().active().unwrap().0,
        target.id().unwrap()
    );
    harness.reopen();
    let resumed = harness
        .recover(
            proxy.address,
            &target,
            PqRecoveryCampaign::Resume {
                directory: &campaign,
                initial_sequence: 1,
            },
        )
        .unwrap();
    assert!(
        resumed.ok && resumed.membership_observed && resumed.may_advance_dependency,
        "{:?}",
        resumed.failure
    );
    assert!(!resumed.submission_outcome_uncertain && resumed.pending.is_none());
    let successful = native_rows(&resumed);
    assert_eq!(successful.len(), 1);
    assert_eq!(successful[0].sequence, 1);
    assert_eq!(
        successful[0].original_expires_at,
        pending.original_expires_at
    );
    assert_eq!(
        successful[0].request_wire_sha256,
        native[0].request_wire_sha256
    );
    assert!(successful[0].receipt_persisted);
    let seen = proxy.seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert!(
        seen.iter().all(|wire| wire == &seen[0]),
        "all three transmissions must be byte-identical"
    );
    assert_eq!(before["epoch"], metadata(&campaign)["epoch"]);
    assert_eq!(
        harness.records(),
        1,
        "cached native replay cannot execute another transaction"
    );
}

#[test]
fn actual_npq6_repeated_eof_and_cold_open_keep_the_original_three_attempt_limit() {
    let mut harness = Harness::new(false, 1);
    let target = harness.packets[0].clone();
    let proxy = Proxy::start(
        harness.native_address,
        harness.policy.clone(),
        Fault::EofBeforeEveryAdmission,
    );
    let directory = tempfile::tempdir().unwrap();
    let campaign = directory.path().join("campaign");
    let original = plan();
    harness.reopen();
    let first = harness
        .recover(
            proxy.address,
            &target,
            PqRecoveryCampaign::Create {
                directory: &campaign,
                initial_sequence: 1,
                plan: original,
            },
        )
        .unwrap();
    assert_eq!(
        first.failure.as_deref(),
        Some("SUBMIT_RECOVERY_ATTEMPT_LIMIT")
    );
    assert!(!first.ok && first.submission_outcome_uncertain && !first.may_advance_dependency);
    assert_eq!(first.pending.as_ref().unwrap().reserved_attempts, 3);
    assert_eq!(native_rows(&first).len(), 3);
    assert_eq!(first.reserved_calls, Some(4));
    let before = std::fs::read(campaign.join("journal")).unwrap();
    harness.reopen();
    let resumed = harness
        .recover(
            proxy.address,
            &target,
            PqRecoveryCampaign::Resume {
                directory: &campaign,
                initial_sequence: 1,
            },
        )
        .unwrap();
    assert_eq!(
        resumed.failure.as_deref(),
        Some("SUBMIT_RECOVERY_ATTEMPT_LIMIT")
    );
    assert!(resumed.attempts.is_empty());
    assert_eq!(resumed.reserved_calls, Some(4));
    assert_eq!(std::fs::read(campaign.join("journal")).unwrap(), before);
    let seen = proxy.seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert!(seen.iter().all(|wire| wire == &seen[0]));
    assert_eq!(harness.records(), 0);
}

#[test]
fn actual_npq6_call_cap_reservation_survives_cold_open_without_native_dispatch() {
    let mut harness = Harness::new(false, 1);
    let target = harness.packets[0].clone();
    let directory = tempfile::tempdir().unwrap();
    let campaign = directory.path().join("campaign");
    let mut original = plan();
    original.max_calls = 1;
    harness.reopen();
    let first = harness
        .recover(
            harness.native_address,
            &target,
            PqRecoveryCampaign::Create {
                directory: &campaign,
                initial_sequence: 1,
                plan: original,
            },
        )
        .unwrap();
    assert_eq!(first.failure.as_deref(), Some("SUBMIT_RECOVERY_CALL_LIMIT"));
    assert_eq!(first.reserved_calls, Some(1));
    assert!(first.pending.is_none());
    let retained = metadata(&campaign);
    assert_eq!(retained["reads"], 1);
    assert!(retained["operations"].as_array().unwrap().is_empty());
    assert_eq!(retained["binding"]["initial"], 1);
    assert!(native_rows(&first).is_empty() && !first.submission_outcome_uncertain);
    let before = std::fs::read(campaign.join("journal")).unwrap();
    harness.reopen();
    let resumed = harness
        .recover(
            harness.native_address,
            &target,
            PqRecoveryCampaign::Resume {
                directory: &campaign,
                initial_sequence: 1,
            },
        )
        .unwrap();
    assert_eq!(
        resumed.failure.as_deref(),
        Some("SUBMIT_RECOVERY_CALL_LIMIT")
    );
    assert!(resumed.attempts.is_empty());
    assert_eq!(resumed.reserved_calls, Some(1));
    assert_eq!(std::fs::read(campaign.join("journal")).unwrap(), before);
    assert_eq!(harness.records(), 0);
}

#[test]
fn actual_signed_expiry_label_cannot_fence_a_healthy_local_campaign_or_gain_a_retry() {
    let mut harness = Harness::new(false, 1);
    let target = harness.packets[0].clone();
    let proxy = Proxy::start(
        harness.native_address,
        harness.policy.clone(),
        Fault::SignedRemoteLabel {
            server: Box::new(harness.scripted_server()),
            label: "PQ_NETWORK_EXPIRED",
        },
    );
    let directory = tempfile::tempdir().unwrap();
    let campaign = directory.path().join("campaign");
    let mut original = plan();
    original.max_calls = 2;
    harness.reopen();
    let first = harness
        .recover(
            proxy.address,
            &target,
            PqRecoveryCampaign::Create {
                directory: &campaign,
                initial_sequence: 1,
                plan: original,
            },
        )
        .unwrap();
    assert_eq!(first.failure.as_deref(), Some("PQ_NETWORK_EXPIRED"));
    assert!(!first.ok && !first.submission_outcome_uncertain && !first.may_advance_dependency);
    assert!(first.pending.is_none() && first.journal_observation_error.is_none());
    assert_eq!(first.reserved_calls, Some(2));
    let native = native_rows(&first);
    assert_eq!(native.len(), 1);
    assert!(
        native[0].receipt_persisted
            && native[0].client_error.is_none()
            && native[0].journal_error.is_none()
            && !native[0].retryable_transport_eof
    );
    harness.reopen();
    let resumed = harness
        .recover(
            proxy.address,
            &target,
            PqRecoveryCampaign::Resume {
                directory: &campaign,
                initial_sequence: 1,
            },
        )
        .expect("authenticated remote label must not become a persisted local fence");
    assert_eq!(
        resumed.failure.as_deref(),
        Some("SUBMIT_RECOVERY_CALL_LIMIT")
    );
    assert!(resumed.attempts.is_empty() && resumed.pending.is_none());
    assert_eq!(resumed.reserved_calls, Some(2));
    assert_eq!(proxy.seen.lock().unwrap().len(), 1);
    assert_eq!(
        harness.records(),
        0,
        "scripted signed refusal is not a real Node execution"
    );
}
