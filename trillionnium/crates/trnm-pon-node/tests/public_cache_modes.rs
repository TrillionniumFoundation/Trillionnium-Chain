//! Public constructors must select one cache owner regardless of call order.
//! These controls exercise real setup; they grant no performance qualification.
use std::time::Duration;
use trnm_pon_node::ingress::{
    public_v3::{PublicPolicy, PublicServer},
    DevelopmentIdentity,
};

fn server() -> PublicServer {
    let identity = DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap();
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    PublicServer::new_process_cold(identity, policy).unwrap()
}

#[test]
fn rejection_cache_then_arithmetic_profile_is_refused() {
    let original = server()
        .with_w1_rejection_cache(8, Duration::from_secs(1))
        .unwrap();
    assert!(matches!(
        original.with_arithmetic_facts(),
        Err(error) if error.to_string() == "PUBLIC_ARITHMETIC_FACTS_ALREADY_ENABLED"
    ));
}

#[test]
fn arithmetic_profile_then_rejection_cache_is_refused() {
    let original = server().with_arithmetic_facts().unwrap();
    assert!(matches!(
        original.with_w1_rejection_cache(8, Duration::from_secs(1)),
        Err(error) if error.to_string() == "PUBLIC_W1_CACHE_MODE"
    ));
}

#[test]
fn rejection_cache_owner_cannot_be_replaced_by_repeated_setup() {
    let original = server()
        .with_w1_rejection_cache(8, Duration::from_secs(1))
        .unwrap();
    assert!(matches!(
        original.with_w1_rejection_cache(4, Duration::from_secs(2)),
        Err(error) if error.to_string() == "PUBLIC_W1_CACHE_MODE"
    ));
}

#[test]
fn either_cache_alone_preserves_original_cold_cpu_budget_and_profile() {
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    for arithmetic in [false, true] {
        let original = server();
        let domain = original.mutation_cpu_domain();
        let before = domain.observe().unwrap();
        assert_eq!(before.stored_credit_ns, 0);
        let configured = if arithmetic {
            original.with_arithmetic_facts().unwrap()
        } else {
            original
                .with_w1_rejection_cache(8, Duration::from_secs(1))
                .unwrap()
        };
        let after = configured.mutation_cpu_domain().observe().unwrap();
        assert_eq!(after.stored_credit_ns, before.stored_credit_ns);
        assert_eq!(after.in_flight, before.in_flight);
        assert_eq!(after.burst_ns, before.burst_ns);
        assert_eq!(after.refill_ns_per_second, before.refill_ns_per_second);
        assert_eq!(after.start_reserve_ns, before.start_reserve_ns);
        assert_eq!(after.worker_limit, before.worker_limit);
        assert_eq!(
            configured.resource_profile(),
            if arithmetic {
                policy.arithmetic_facts_id()
            } else {
                policy.id()
            }
        );
    }
}
