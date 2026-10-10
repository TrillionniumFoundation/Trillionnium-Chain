//! Definitions only: Root executes real Ed25519 and filesystem assertions.
//! Synthetic declared tasks here do not constitute a material/Native qualification.
use super::*;
use crate::operator_task_policy::tests as fixtures;
use std::os::unix::fs::PermissionsExt;
use trnm_crypto_primitives::{public_key_hex, sign_hex, signing_key_from_hex};

pub(crate) fn body(primary: &Grant, command: &str, raws: &[Vec<u8>], nonce: u8) -> PoolGrant {
    let mut g = PoolGrant {
        schema: POOL_SCHEMA.into(),
        context: primary.context.clone(),
        registry_sequence: primary.registry_sequence,
        registry_digest: primary.registry_digest.clone(),
        registry_previous_digest: primary.registry_previous_digest.clone(),
        declaration_digest: primary.declaration_digest.clone(),
        registered_task: primary.task.native_task.clone(),
        lease_sha256: primary.task.lease_sha256.clone(),
        instance_class: primary.instance_class.clone(),
        pool_context: "44".repeat(32),
        command: command.into(),
        exact_payload_sha256: pool_payload_sha256(command, raws).unwrap(),
        operation_nonce: format!("{nonce:02x}").repeat(32),
        operation_id: "00".repeat(32),
        expected_generation: 0,
        allocation: primary.allocation.clone(),
        limits: primary.limits.clone(),
        funding_commitment: primary.funding_commitment.clone(),
        funding_evidence: primary.funding_evidence.clone(),
        declared_funding_units: primary.declared_funding_units,
        not_before_ns: primary.not_before_ns,
        expires_ns: primary.expires_ns,
        revoked: false,
        allowed_task_commands: Vec::new(),
        authorized_retained_groups: Vec::new(),
    };
    g.operation_id = pool_operation_id(&g).unwrap();
    g
}
pub(crate) fn signed(body: PoolGrant) -> PoolExternalPermission {
    let registry = signing_key_from_hex(&"07".repeat(32)).unwrap();
    let task = signing_key_from_hex(&"09".repeat(32)).unwrap();
    let raw = serde_json::to_vec(&PoolEnvelope {
        registry_signature: sign_hex(&registry, &pool_message(&body, 1)),
        task_signature: sign_hex(&task, &pool_message(&body, 2)),
        body: body.clone(),
    })
    .unwrap();
    PoolExternalPermission {
        authority: PoolExternalAuthority {
            registry_key: public_key_hex(&registry),
            task_key: public_key_hex(&task),
            latest_sequence: body.registry_sequence,
            latest_digest: body.registry_digest.clone(),
            expected_envelope_sha256: sha(&raw),
            expected: body,
        },
        raw_policy: raw,
    }
}
fn verified(primary: &Grant, body: PoolGrant) -> VerifiedPoolPolicy {
    let (_, outside) = fixtures::signed(primary.clone());
    authenticate_pool(
        &signed(body),
        &outside,
        &fixtures::authenticated(primary.clone()),
        primary.not_before_ns + 1,
    )
    .unwrap()
}
fn facts(g: &PoolGrant) -> PoolFacts {
    PoolFacts {
        parent: g.context.actual_parent.clone(),
        generation: g.expected_generation,
        pool_context: g.pool_context.clone(),
        registered_task: g.registered_task.clone(),
        lease_sha256: g.lease_sha256.clone(),
        command: g.command.clone(),
        payload_sha256: g.exact_payload_sha256.clone(),
    }
}

#[test]
fn pool_both_roles_full_expected_payload_and_outside_latest_are_mandatory() {
    let primary = fixtures::body();
    let b = body(&primary, "submit-bundle", &[vec![1]], 1);
    let permission = signed(b.clone());
    let (_, mut outside) = fixtures::signed(primary.clone());
    let p = fixtures::authenticated(primary.clone());
    let now = primary.not_before_ns + 1;
    assert!(authenticate_pool(&permission, &outside, &p, now).is_ok());
    outside.task_key = outside.registry_key.clone();
    assert_eq!(
        authenticate_pool(&permission, &outside, &p, now)
            .err()
            .unwrap(),
        PolicyError::ExternalContext
    );
    let (_, outside) = fixtures::signed(primary.clone());
    let mut wrong = signed(b);
    wrong.authority.expected.exact_payload_sha256 = "99".repeat(32);
    wrong.authority.expected.operation_id = pool_operation_id(&wrong.authority.expected).unwrap();
    assert_eq!(
        authenticate_pool(&wrong, &outside, &p, now).err().unwrap(),
        PolicyError::ExternalContext
    );
    let mut stale = signed(body(&primary, "reconcile", &[], 2));
    stale.authority.latest_sequence += 1;
    assert_eq!(
        authenticate_pool(&stale, &outside, &p, now).err().unwrap(),
        PolicyError::ExternalContext
    );
}
#[test]
fn whole_ordered_bundle_and_operation_nonce_have_distinct_identities() {
    let p = fixtures::body();
    let a = body(&p, "submit-bundle", &[vec![1], vec![2]], 1);
    let b = body(&p, "submit-bundle", &[vec![2], vec![1]], 1);
    let c = body(&p, "submit-bundle", &[vec![1], vec![2]], 2);
    assert_ne!(a.exact_payload_sha256, b.exact_payload_sha256);
    assert_ne!(a.operation_id, b.operation_id);
    assert_eq!(a.exact_payload_sha256, c.exact_payload_sha256);
    assert_ne!(a.operation_id, c.operation_id);
    let mut wrong = a.clone();
    wrong.context.actual_parent = "66".repeat(32);
    assert!(validate_pool(&wrong).is_err());
    assert!(pool_payload_sha256("mining-batch", &[]).is_err());
}
#[test]
fn retained_group_needs_prior_durable_claim_and_new_signed_prefix_permission() {
    let p = fixtures::body();
    let raw = vec![vec![1]];
    let g = body(&p, "submit-bundle", &raw, 1);
    let v = verified(&p, g.clone());
    let dir = fixtures::directory();
    let primary = fixtures::authenticated(p.clone());
    let mut journal = Journal::open(dir.path(), fixtures::uid(), &primary).unwrap();
    let mut next = body(&p, "reconcile", &[], 2);
    next.authorized_retained_groups = vec![g.exact_payload_sha256.clone()];
    let permitted = verified(&p, next.clone());
    assert_eq!(
        journal
            .prefix_group_authorized(&permitted, &g.exact_payload_sha256)
            .err(),
        Some(PolicyError::ExternalContext)
    );
    journal
        .reserve_pool(&v, &facts(&g), p.not_before_ns + 1)
        .unwrap();
    assert!(journal
        .prefix_group_authorized(&permitted, &g.exact_payload_sha256)
        .is_ok());
    next.authorized_retained_groups.clear();
    assert!(journal
        .prefix_group_authorized(&verified(&p, next), &g.exact_payload_sha256)
        .is_err());
    assert!(journal
        .prefix_group_authorized(&permitted, &"88".repeat(32))
        .is_err());
}
#[test]
fn work_and_pool_share_class_reservation_ceiling_without_refund_on_restart() {
    let p = fixtures::body();
    let v = fixtures::authenticated(p.clone());
    let dir = fixtures::directory();
    let mut journal = Journal::open(dir.path(), fixtures::uid(), &v).unwrap();
    let nf = NativeFacts {
        network: p.context.network.clone(),
        parameters: p.context.parameters.clone(),
        parent: p.context.actual_parent.clone(),
        task: p.task.clone(),
        packet_sha256: p.exact_packet_sha256.clone(),
        header_nonce: 1,
    };
    journal.reserve(&v, &nf, p.not_before_ns + 1).unwrap();
    let pg = body(&p, "submit-bundle", &[vec![1]], 1);
    let pv = verified(&p, pg.clone());
    journal
        .reserve_pool(&pv, &facts(&pg), p.not_before_ns + 1)
        .unwrap();
    drop(journal);
    let mut reopened = Journal::open(dir.path(), fixtures::uid(), &v).unwrap();
    assert!(reopened.pool_operation_is_used(&pv));
    assert_eq!(
        reopened
            .reserve_pool(&pv, &facts(&pg), p.not_before_ns + 1)
            .err(),
        Some(PolicyError::Replay)
    );
    let next = body(&p, "reconcile", &[], 2);
    let next_v = verified(&p, next.clone());
    assert_eq!(
        reopened
            .reserve_pool(&next_v, &facts(&next), p.not_before_ns + 1)
            .err(),
        Some(PolicyError::Budget)
    );
}
#[test]
fn linked_view_retains_old_claims_and_revocation_cannot_refund_or_roll_back() {
    let p = fixtures::body();
    let pg = body(&p, "submit-bundle", &[vec![1]], 1);
    let pv = verified(&p, pg.clone());
    let dir = fixtures::directory();
    let mut j = Journal::open(
        dir.path(),
        fixtures::uid(),
        &fixtures::authenticated(p.clone()),
    )
    .unwrap();
    j.reserve_pool(&pv, &facts(&pg), p.not_before_ns + 1)
        .unwrap();
    let mut next = p.clone();
    next.registry_sequence = 2;
    next.registry_previous_digest = Some(p.registry_digest.clone());
    next.registry_digest = "77".repeat(32);
    next.revoked = true;
    let nv = fixtures::authenticated(next.clone());
    j.advance(&nv).unwrap();
    assert!(j.pool_operation_is_used(&pv));
    assert!(j.advance(&fixtures::authenticated(p.clone())).is_err());
    assert!(j
        .recheck_pool(
            &pv,
            &PoolReservation {
                operation: pg.operation_id,
                policy_sha256: pv.envelope_sha256.clone(),
                sequence: 1,
                registry_digest: p.registry_digest.clone()
            },
            &facts(&pv.body),
            p.not_before_ns + 1
        )
        .is_err());
    drop(j);
    let reopened = Journal::open(dir.path(), fixtures::uid(), &nv).unwrap();
    assert!(reopened.pool_operation_is_used(&pv));
}
#[test]
fn reservation_fault_partial_file_is_retained_and_future_owner_is_disabled() {
    let p = fixtures::body();
    let pg = body(&p, "submit-bundle", &[vec![1]], 1);
    let pv = verified(&p, pg.clone());
    let dir = fixtures::directory();
    let primary = fixtures::authenticated(p.clone());
    let mut j = Journal::open(dir.path(), fixtures::uid(), &primary).unwrap();
    let path = dir
        .path()
        .join(format!("pool-claim-{}.json", pg.operation_id));
    fs::write(&path, b"partial-not-a-reservation").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        j.reserve_pool(&pv, &facts(&pg), p.not_before_ns + 1).err(),
        Some(PolicyError::Journal)
    );
    assert_eq!(fs::read(&path).unwrap(), b"partial-not-a-reservation");
    drop(j);
    assert!(Journal::open(dir.path(), fixtures::uid(), &primary).is_err());
}
