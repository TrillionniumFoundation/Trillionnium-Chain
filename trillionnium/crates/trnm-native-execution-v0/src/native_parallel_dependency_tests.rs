use trnm_protocol::{
    account_key, AccountV1, CanonicalCommandV1, ACCOUNT_OBJECT_TYPE_V1, CANONICAL_TX_SCHEMA_V1,
};

use super::*;

#[derive(Clone, Default)]
struct View {
    values: BTreeMap<String, StateObject>,
    unavailable: Option<String>,
}

impl TryStateViewV0 for View {
    type Error = &'static str;

    fn try_get(&self, key: &str) -> std::result::Result<Option<StateObject>, Self::Error> {
        if self.unavailable.as_deref() == Some(key) {
            Err("authenticated read failure")
        } else {
            Ok(self.values.get(key).cloned())
        }
    }
}

fn account(id: &str, balance: u128, nonce: u64) -> StateObject {
    StateObject {
        object_type: ACCOUNT_OBJECT_TYPE_V1.to_string(),
        version: 1,
        value_bytes: serde_json::to_vec(&AccountV1 {
            account: id.to_string(),
            balance,
            nonce,
        })
        .unwrap(),
    }
}

fn transaction() -> CanonicalTxV1 {
    CanonicalTxV1 {
        schema: CANONICAL_TX_SCHEMA_V1.to_string(),
        sender: "did:payer".to_string(),
        nonce: 1,
        max_gas: 100_000,
        fee_limit: 100_000,
        command: CanonicalCommandV1::Transfer {
            to: "did:recipient".to_string(),
            amount: 10,
        },
    }
}

fn context() -> ExecutionContext<'static> {
    ExecutionContext {
        height: 2,
        signer_id: "did:payer",
        signer_role: "hepta",
        payload_len: 300,
    }
}

#[test]
fn native_dependencies_include_absence_and_full_value_and_type_at_unchanged_version() {
    let payer_key = account_key("did:payer");
    let recipient_key = account_key("did:recipient");
    let mut parent = View::default();
    parent
        .values
        .insert(payer_key.clone(), account("did:payer", 1_000_000, 0));
    let attempt = record_runtime_attempt_v0(&transaction(), context(), &parent);
    assert!(attempt.outcome.is_ok());
    assert_eq!(attempt.reads.get(&recipient_key), Some(&None));
    assert!(attempt.into_reusable_outcome_v0(&parent).is_some());
    let reusable = |current: &View| {
        record_runtime_attempt_v0(&transaction(), context(), &parent)
            .into_reusable_outcome_v0(current)
            .is_some()
    };

    let mut current = parent.clone();
    current
        .values
        .insert(recipient_key, account("did:recipient", 1, 0));
    assert!(!reusable(&current));
    current = parent.clone();
    current
        .values
        .insert(payer_key.clone(), account("did:payer", 999_999, 0));
    assert!(!reusable(&current));
    current = parent.clone();
    current.values.get_mut(&payer_key).unwrap().object_type = "changed-type".to_string();
    assert!(!reusable(&current));
    current = parent.clone();
    current.values.get_mut(&payer_key).unwrap().version += 1;
    assert!(!reusable(&current));
}

#[test]
fn native_unavailable_speculation_is_never_reused_as_absence_or_cached_failure() {
    let key = account_key("did:payer");
    let mut view = View {
        unavailable: Some(key.clone()),
        ..View::default()
    };
    let attempt = record_runtime_attempt_v0(&transaction(), context(), &view);
    assert!(matches!(
        attempt
            .outcome
            .as_ref()
            .unwrap_err()
            .downcast_ref::<CompleteNativeExecutionFailureV0>(),
        Some(CompleteNativeExecutionFailureV0::StateUnavailable)
    ));
    assert!(record_runtime_attempt_v0(&transaction(), context(), &view)
        .into_reusable_outcome_v0(&view)
        .is_none());
    view.unavailable = None;
    view.values.insert(key, account("did:payer", 1_000_000, 0));
    assert!(attempt.into_reusable_outcome_v0(&view).is_none());
    assert!(execute_runtime_v0(&transaction(), context(), &view).is_ok());
}

#[test]
fn native_fee_rebase_rejects_collector_type_nonce_identity_and_version_drift() {
    let collector_key = account_key(FEE_COLLECTOR_ACCOUNT_V1);
    let mut parent = View::default();
    parent
        .values
        .insert(account_key("did:payer"), account("did:payer", 1_000_000, 0));
    parent.values.insert(
        collector_key.clone(),
        account(FEE_COLLECTOR_ACCOUNT_V1, 100, 0),
    );
    for mutation in [
        "type",
        "nonce",
        "identity",
        "same-version",
        "regressed-balance",
        "unavailable",
    ] {
        let attempt = record_runtime_attempt_v0(&transaction(), context(), &parent);
        assert!(attempt.fee_delta.is_some());
        let mut current = parent.clone();
        let mut collector = account(FEE_COLLECTOR_ACCOUNT_V1, 200, 0);
        collector.version = 2;
        match mutation {
            "type" => collector.object_type = "wrong-type".to_string(),
            "nonce" => {
                collector.value_bytes = account(FEE_COLLECTOR_ACCOUNT_V1, 200, 1).value_bytes
            }
            "identity" => collector.value_bytes = account("did:wrong-account", 200, 0).value_bytes,
            "same-version" => collector.version = 1,
            "regressed-balance" => {
                collector.value_bytes = account(FEE_COLLECTOR_ACCOUNT_V1, 99, 0).value_bytes
            }
            "unavailable" => current.unavailable = Some(collector_key.clone()),
            _ => unreachable!(),
        }
        current.values.insert(collector_key.clone(), collector);
        assert!(
            attempt.into_reusable_outcome_v0(&current).is_none(),
            "{mutation}"
        );
    }
}

#[test]
fn native_speculation_read_limits_disable_reuse_without_fabricating_state_errors() {
    let view = View::default();
    let recording = RecordingViewV0 {
        view: &view,
        reads: RefCell::new(BTreeMap::new()),
        reads_available: std::cell::Cell::new(true),
        retained_bytes: std::cell::Cell::new(0),
    };
    for index in 0..=MAX_READS_V0 {
        assert_eq!(recording.try_get(&format!("key-{index}")), Ok(None));
    }
    assert!(!recording.reads_available.get());
    assert!(recording.reads.borrow().is_empty());

    let mut view = View::default();
    view.values.insert(
        "large".to_string(),
        StateObject {
            object_type: "oversized-test-value".to_string(),
            version: 1,
            value_bytes: vec![1; MAX_RETAINED_READ_BYTES_V0 + 1],
        },
    );
    let recording = RecordingViewV0 {
        view: &view,
        reads: RefCell::new(BTreeMap::new()),
        reads_available: std::cell::Cell::new(true),
        retained_bytes: std::cell::Cell::new(0),
    };
    assert!(recording.try_get("large").unwrap().is_some());
    assert!(!recording.reads_available.get());
    assert!(recording.reads.borrow().is_empty());
}
