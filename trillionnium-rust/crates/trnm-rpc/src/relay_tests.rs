use super::*;
use trnm_types::RelaySessionStatus;

#[path = "relay_tests_ack.rs"]
mod ack;
#[path = "relay_tests_dispatch.rs"]
mod dispatch;
#[path = "relay_tests_open.rs"]
mod open;
#[path = "relay_tests_route.rs"]
mod route;
#[path = "relay_tests_state.rs"]
mod state;

fn tiny_quota_relay() -> RelayService {
    let mut router = RelayRouter::new();
    router.register("relay.echo", EchoHandler);
    let relay = RelayService::with_risk_quota_config(
        router,
        RiskQuotaConfig {
            window_ms: 50,
            per_session_limit: 2,
            per_source_limit: 2,
        },
    );
    relay
        .open(RelayOpenRequest {
            session_id: "rq-s1".into(),
        })
        .unwrap();
    relay
        .open(RelayOpenRequest {
            session_id: "rq-s2".into(),
        })
        .unwrap();
    relay
}
