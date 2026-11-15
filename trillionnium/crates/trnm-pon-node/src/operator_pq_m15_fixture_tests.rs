//! Reuses the existing full NPQ6 fixture/permission constructors. This ignored
//! helper only exports material to the isolated M15 native consumer suite.
//! It is not an independent deployment, model, work-cost or release verdict.
use super::*;
use std::io::{BufRead, Read, Write};

fn launch_value(f: &Fixture, input: &policy::Inputs) -> serde_json::Value {
    use serde_json::json;
    let identity = &input.view_authority.identity;
    let allocations: Vec<_> = input.allocations.iter().map(|row| json!({"raw":row.raw,"authority":{
        "identity":row.authority.identity,"expected":row.authority.expected,"expected_envelope_sha256":row.authority.expected_envelope_sha256,
        "latest_allocator_sequence":row.authority.latest_allocator_sequence,"latest_allocator_digest":row.authority.latest_allocator_digest}})).collect();
    let budget = input.budget_authority.as_ref().map(|authority| json!({"identity":authority.identity,"expected":authority.expected,
        "envelope_sha256":authority.envelope_sha256,"latest_sequence":authority.latest_sequence,"latest_digest":authority.latest_digest}));
    let materials: Vec<_> = input
        .materials
        .iter()
        .map(|row| json!({"role":row.role,"path":row.path,"bytes":row.bytes,"sha256":row.sha256}))
        .collect();
    json!({"schema":"restricted-owner-continuous-launch-pq-v3","source_commit":identity.source_commit,
        "node_policy_source":identity.node_policy_source,"registry2_package":identity.registry2_package,
        "store":f.root.path().join("consumer"),"maximum_steps":32,"wall_seconds":180,"receiver_service":null,
        "inputs":{"raw_view":input.raw_view,"view_authority":{"identity":identity,
            "expected":input.view_authority.expected,"envelope_sha256":input.view_authority.envelope_sha256,
            "latest_sequence":input.view_authority.latest_sequence,"latest_digest":input.view_authority.latest_digest},
            "raw_budget":input.raw_budget,"budget_authority":budget,"allocations":allocations,"journal_path":input.journal_path,
            "expected_uid":input.expected_uid,"expected_journal":input.expected_journal,"materials":materials,
            "lease_transition":null,"known_unclean_restart":null}})
}

fn emit(f: &Fixture, input: &policy::Inputs) {
    let launch = launch_value(f, input);
    let bytes = serde_json::to_vec(&launch).unwrap();
    let path = f.root.path().join(format!(
        "m15-launch-{}.json",
        input.view_authority.latest_sequence
    ));
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let output = serde_json::json!({"schema":"trnm-m15-existing-npq6-fixture-v1",
        "path":path,"sha256":digest_bytes(&bytes),"launch":launch,
        "identity":input.view_authority.identity,"parent":input.view_authority.expected.actual_parent,
        "generation":input.view_authority.expected.actual_generation,
        "qualification":false});
    println!("M15_FIXTURE:{}", serde_json::to_string(&output).unwrap());
    std::io::stdout().flush().unwrap();
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    action: String,
    head: Option<history::Anchor>,
    parent: Option<String>,
    generation: Option<u64>,
}

#[ignore = "helper requires explicit isolated M15 native-suite IPC; never a standalone qualification"]
#[test]
fn export_existing_npq6_inputs_for_isolated_m15_native_suite() {
    assert_eq!(
        std::env::var("TRNM_M15_FIXTURE_HELPER").unwrap(),
        "isolated-native-v1"
    );
    assert_ne!(rustix::process::geteuid().as_raw(), 0);
    let f = fixture();
    let (initial, mut prior) = inputs(&f, 1, None, history::Anchor::empty(), boot(&f), 2);
    emit(&f, &initial);
    let mut sequence = 1_u64;
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    loop {
        let mut raw = String::new();
        let read = (&mut reader).take(65537).read_line(&mut raw).unwrap();
        assert!(
            read > 0 && read <= 65536 && raw.ends_with('\n'),
            "bounded explicit helper command required"
        );
        let request: Request = serde_json::from_str(&raw).unwrap();
        assert_eq!(request.schema, "trnm-m15-existing-npq6-fixture-command-v1");
        if request.action == "stop" {
            assert!(
                request.head.is_none() && request.parent.is_none() && request.generation.is_none()
            );
            return;
        }
        assert_eq!(request.action, "refresh");
        sequence = sequence.checked_add(1).unwrap();
        assert!(sequence <= 32); // Same original controller step ceiling.
        let parent: [u8; 32] = hex::decode(request.parent.unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let (next, outside) = inputs(
            &f,
            sequence,
            Some(&prior),
            request.head.unwrap(),
            parent,
            request.generation.unwrap(),
        );
        emit(&f, &next);
        prior = outside;
    }
}
