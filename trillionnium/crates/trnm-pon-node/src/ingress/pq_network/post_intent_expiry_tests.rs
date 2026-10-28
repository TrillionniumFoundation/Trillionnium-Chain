#[test]
fn actual_signed_expiry_after_intent_cancels_without_renewing_live_authority() {
    // All five requests are signed once in start(), before the production
    // listener runs. Only this original first signature has a shorter lifetime.
    let mut running = Running::start_with_initial_lifetime(5);
    let initial_started_at = crate::ingress::now().unwrap();
    let initial = running.call("initial-target", &running.initial);
    let initial_ended_at = crate::ingress::now().unwrap();
    let after_initial = capture(running.directory.path());
    let same_peer = running.call("same-peer-next-sequence-head", &running.same_peer_head);
    let after_same_peer = capture(running.directory.path());
    let other_head = running.call("other-peer-head", &running.other_peer_head);
    let after_other_head = capture(running.directory.path());
    let other_submit = running.call("other-peer-honest-submit", &running.other_peer_submit);
    let after_other_submit = capture(running.directory.path());
    // The original expired signed bytes have no live authority. They cannot
    // request even a cached response through live request verification.
    let original_replay = running.call("original-exact-wire-replay", &running.initial);
    let after_replay = capture(running.directory.path());
    let retained = recorded_response(&after_same_peer, &running.initial);
    let original_expiry = running.initial.verified.expiry;
    let checked_at_current_time = crate::ingress::now().unwrap();
    let historical_response = retained.as_ref().map(|wire| {
        let outcome =
            running
                .policy
                .verify_response(wire, &running.initial.verified, original_expiry);
        match outcome {
            Ok(response) => json!({"verified":true,"response":response}),
            Err(error) => json!({"verified":false,"error":error.to_string()}),
        }
    });
    let current_response = retained.as_ref().map(|wire| {
        let outcome = running.policy.verify_response(
            wire,
            &running.initial.verified,
            checked_at_current_time,
        );
        match outcome {
            Ok(response) => json!({"verified":true,"response":response}),
            Err(error) => json!({"verified":false,"error":error.to_string()}),
        }
    });
    let current_request = match running
        .policy
        .verify_request(running.initial.wire(), checked_at_current_time)
    {
        Ok(_) => json!({"verified":true}),
        Err(error) => json!({"verified":false,"error":error.to_string()}),
    };
    let metrics = running.finish();
    let cold = match Node::open_with_pq_network(
        running.directory.path(),
        running.settings.clone(),
        1,
        &running.policy,
    ) {
        Ok(node) => {
            let checked = node.read_active().map(
                |(tip, generation, _)| json!({"tip":hex::encode(tip),"generation":generation}),
            );
            let snapshot = capture(running.directory.path());
            json!({"opened":true,"checked_active":checked.map_err(|error|error.to_string()),"snapshot":snapshot})
        }
        Err(error) => json!({"opened":false,"error":error.to_string()}),
    };
    let target_id = hex::encode(running.target.id().unwrap());
    let honest_id = hex::encode(running.honest.id().unwrap());
    let primary = running.initial.verified.peer;
    let other = running.other_peer_head.verified.peer;
    let historical = historical_response.clone().unwrap_or(Value::Null);
    let current = current_response.clone().unwrap_or(Value::Null);
    let calls = [
        &initial,
        &same_peer,
        &other_head,
        &other_submit,
        &original_replay,
    ];
    let snapshots = [
        &running.before,
        &after_initial,
        &after_same_peer,
        &after_other_head,
        &after_other_submit,
        &after_replay,
    ];
    let mut checks = vec![
        ("five_original_requests_observed", calls.len() == 5),
        (
            "every_live_snapshot_known",
            snapshots
                .iter()
                .all(|row| row.get("capture_error").is_none()),
        ),
        (
            "actual_wall_clock_crossed_original_signed_expiry",
            initial_started_at <= original_expiry && initial_ended_at > original_expiry,
        ),
        (
            "expiry_observed_inside_original_ten_second_deadline",
            initial["returned_before_original_deadline"] == true
                && initial["elapsed_ns"]
                    .as_u64()
                    .is_some_and(|n| n < ORIGINAL_PQ_REQUEST_SECONDS * 1_000_000_000),
        ),
        (
            "first_live_client_refuses_expired_signed_response",
            initial["response_wire_hex"].is_string()
                && initial["response_verification_error"].is_string()
                && initial["signed_response"].is_null(),
        ),
        (
            "real_original_intent_terminated",
            after_same_peer["reorg"][1] == target_id && after_same_peer["reorg"][4] == 2,
        ),
        (
            "lifecycle_records_actual_signed_expiry",
            after_same_peer["lifecycle"][0][1] == 2
                && after_same_peer["lifecycle"][0][3] == "PQ_NETWORK_EXPIRED",
        ),
        (
            "cancelled_activation_preserves_active_state",
            after_same_peer["active"] == running.before["active"],
        ),
        (
            "completed_original_receipt_valid_only_as_historical_observation",
            historical["verified"] == true
                && historical["response"]["ok"] == false
                && historical["response"]["value"]["error"] == "PQ_NETWORK_EXPIRED_UNCONFIRMED",
        ),
        (
            "current_time_signature_validation_refuses_old_response_and_request",
            checked_at_current_time > original_expiry
                && current["verified"] == false
                && current_request["verified"] == false,
        ),
        (
            "same_peer_original_next_sequence_head_succeeds",
            successful(&same_peer) && peer_sequence(&after_same_peer, primary) == Some(2),
        ),
        (
            "cleanup_does_not_advance_other_peer_sequence",
            peer_sequence(&after_same_peer, other) == Some(0),
        ),
        (
            "other_original_head_succeeds_at_sequence_one",
            successful(&other_head) && peer_sequence(&after_other_head, other) == Some(1),
        ),
        (
            "other_original_honest_submit_succeeds",
            successful(&other_submit)
                && other_submit["signed_response"]["value"]["block"] == honest_id
                && after_other_submit["active"]["tip"] == honest_id,
        ),
        (
            "both_peers_end_at_exact_sequence_two",
            peer_sequence(&after_replay, primary) == Some(2)
                && peer_sequence(&after_replay, other) == Some(2),
        ),
        (
            "original_expired_wire_replay_is_refused",
            original_replay["io_error"].is_string()
                && original_replay["response_wire_hex"].is_null()
                && original_replay["signed_response"].is_null(),
        ),
        (
            "expired_replay_changes_no_state_or_peer_ledger",
            after_replay["active"] == after_other_submit["active"]
                && after_replay["requests"] == after_other_submit["requests"]
                && after_replay["peers"] == after_other_submit["peers"],
        ),
        (
            "four_distinct_original_operations_retained",
            after_replay["requests"]
                .as_array()
                .is_some_and(|rows| rows.len() == 4),
        ),
        (
            "original_owner_lock_remains_held",
            running.before["owner_fence"]["exclusive_lock_probe"]["held_by_original_owner"] == true
                && after_same_peer["owner_fence"]["exclusive_lock_probe"]["held_by_original_owner"]
                    == true
                && after_replay["owner_fence"]["exclusive_lock_probe"]["held_by_original_owner"]
                    == true,
        ),
        (
            "no_metadata_credit_or_profile_change",
            after_replay["metadata"] == running.before["metadata"],
        ),
        (
            "cold_reopen_preserves_live_state_and_complete_peer_ledger",
            cold["opened"] == true
                && cold["snapshot"]["active"] == after_replay["active"]
                && cold["snapshot"]["requests"] == after_replay["requests"]
                && cold["snapshot"]["peers"] == after_replay["peers"],
        ),
        (
            "actual_server_joined_without_error",
            metrics["joined"] == true && metrics.get("metrics").is_some(),
        ),
    ];
    let mut checks_not_evaluated = Vec::new();
    if cfg!(unix) {
        checks.push((
            "original_namespace_and_owner_identity_preserved",
            after_replay["owner_fence"]["identity"]["supported"] == true
                && after_replay["owner_fence"]["identity"]
                    == running.before["owner_fence"]["identity"],
        ));
    } else {
        checks_not_evaluated.push("original_namespace_and_owner_identity_preserved");
    }
    let failures: Vec<_> = checks
        .iter()
        .filter(|(_, passed)| !passed)
        .map(|(name, _)| *name)
        .collect();
    let honest_followups_succeeded = [&same_peer, &other_head, &other_submit]
        .iter()
        .filter(|row| successful(row))
        .count();
    println!(
        "{}",
        json!({"schema":"pq-post-intent-real-expiry-observation-v1",
        "planned_calls":5,"observed_calls":calls.len(),"honest_followups_planned":3,
        "honest_followups_succeeded":honest_followups_succeeded,"calls":calls,
        "first_call_started_at":initial_started_at,"first_call_ended_at":initial_ended_at,
        "original_signed_expiry":original_expiry,"original_signed_wire_refreshed":false,
        "historical_verification_time":original_expiry,"historical_check_grants_live_authority":false,
        "current_verification_time":checked_at_current_time,
        "historical_response":historical_response,"current_response":current_response,"current_request":current_request,
        "before":running.before,"after_initial":after_initial,"after_same_peer":after_same_peer,
        "after_other_head":after_other_head,"after_other_submit":after_other_submit,"after_replay":after_replay,
        "cold":cold,"server":metrics,"checks":checks,"failures":failures,
        "checks_not_evaluated":checks_not_evaluated,"unix_inode_device_probe_supported":cfg!(unix),
        "scope":"real native ML-DSA and W1/M06; production PQ listener; existing post-intent scheduling cut; actual original signature expiry before unchanged ten-second deadline",
        "public_paid_host_qualified":false,"physical_kill_cut":false,"whole_chain_pq":false})
    );
    assert!(
        failures.is_empty(),
        "PQ original signed-expiry recovery checks failed: {failures:?}"
    );
}
