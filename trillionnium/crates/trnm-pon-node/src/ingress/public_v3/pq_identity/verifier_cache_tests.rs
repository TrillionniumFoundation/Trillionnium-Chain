use super::super::{
    caller_message, digest, ensure, solution_magic, Cookie, Hello, PqNativeSigningKey,
    PqPublicIdentity, PublicPolicy, PublicServer, Settings, ThreadCpuStamp, MAX_AUTHENTICATIONS,
    ML_DSA_65_SPKI_BYTES, PQ_SOLUTION_BYTES,
};
use super::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    time::{Duration, Instant},
};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

fn identity(n: u8) -> PqPublicIdentity {
    let seed = Zeroizing::new([n; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    PqPublicIdentity::from_owned_seed(seed, ml_dsa_65_key_id_from_spki(&spki).unwrap()).unwrap()
}

fn server() -> PublicServer {
    PublicServer::new_pq_history(
        identity(71),
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
    )
    .unwrap()
}

fn cookie(owner: &PublicServer, settings: &Settings, caller: &PqPublicIdentity) -> Cookie {
    owner
        .cookie(
            settings,
            Hello {
                op: 2,
                len: 13,
                caller: digest(caller.public_key()).unwrap(),
                digest: [3; 32],
                client_nonce: [4; 32],
            },
            "127.0.0.1:1".parse().unwrap(),
        )
        .unwrap()
}

fn solution(cookie: &Cookie, nonce: u64, caller: &PqPublicIdentity) -> Vec<u8> {
    let mut bytes = solution_magic(true).to_vec();
    bytes.extend(cookie.id().unwrap());
    bytes.extend(nonce.to_le_bytes());
    bytes.extend(caller.public_spki());
    bytes.extend(
        caller
            .key
            .sign_exact_message(&caller_message(cookie, nonce, true).unwrap())
            .unwrap(),
    );
    assert_eq!(bytes.len(), PQ_SOLUTION_BYTES);
    bytes
}

// Retained complete pre-cache caller authentication, on the SAME actual intake
// and original finite CPU/attempt/byte budget as the candidate. No fake crypto,
// guessed cost, budget reset or unmetered reference verification.
fn original(
    owner: &PublicServer,
    cookie: &Cookie,
    nonce: u64,
    bytes: &[u8],
    expansions: &AtomicU64,
) -> Result<()> {
    let message = caller_message(cookie, nonce, true)?;
    owner
        .listener_intake()?
        .pq_authentication
        .perform(bytes.len() + message.len(), || {
            ensure(bytes.len() == PQ_SOLUTION_BYTES, "PUBLIC_SOLUTION")?;
            let spki = &bytes[44..44 + ML_DSA_65_SPKI_BYTES];
            let key = PqNativeVerifier::from_pinned_spki(spki, digest(&cookie.caller)?)
                .map_err(|_| "PUBLIC_CALLER_SIGNATURE")?;
            expansions.fetch_add(1, Ordering::Relaxed);
            key.verify_exact_message(&message, &bytes[44 + ML_DSA_65_SPKI_BYTES..])
                .map_err(|_| "PUBLIC_CALLER_SIGNATURE")?;
            Ok(())
        })
}

fn retained(cache: &VerifierCache) -> usize {
    cache.entries.lock().unwrap().keys.iter().flatten().count()
}

#[test]
fn warm_key_still_checks_fresh_signature_exact_spki_pin_and_original_budget() {
    let owner = server();
    let settings = Settings::development(Some(1)).unwrap();
    let caller = identity(72);
    let other = identity(73);
    let c = cookie(&owner, &settings, &caller);
    let bytes = solution(&c, 23, &caller);
    let intake = owner.listener_intake().unwrap();
    let budget = &intake.pq_authentication;
    let cache = &budget.verifiers;
    owner.verify_caller(&c, 23, &bytes).unwrap();
    let key = cache
        .cached(caller.public_spki(), digest(caller.public_key()).unwrap())
        .unwrap();
    assert_eq!(cache.expansions.load(Ordering::Relaxed), 1);
    owner
        .verify_caller(&c, 24, &solution(&c, 24, &caller))
        .unwrap();
    assert_eq!(cache.expansions.load(Ordering::Relaxed), 1);
    assert_eq!(cache.hits.load(Ordering::Relaxed), 1);
    assert!(Arc::ptr_eq(
        &key,
        &cache
            .cached(caller.public_spki(), digest(caller.public_key()).unwrap())
            .unwrap()
    ));

    let mut bad_signature = bytes.clone();
    // Alter c_tilde, retaining signature dimensions and decoder shape.
    bad_signature[44 + ML_DSA_65_SPKI_BYTES] ^= 1;
    let mut other_spki = bytes.clone();
    other_spki[44..44 + ML_DSA_65_SPKI_BYTES].copy_from_slice(other.public_spki());
    let mut wrong_pin = c.clone();
    wrong_pin.caller = other.public_key().into();
    let before = budget.usage().unwrap();
    let cases = [
        (c.clone(), 24, bytes.clone()),
        (c.clone(), 23, bad_signature),
        (c.clone(), 23, other_spki.clone()),
        (wrong_pin, 23, other_spki),
        (c.clone(), 23, bytes[..bytes.len() - 1].to_vec()),
    ];
    let mut charged_bytes = 0u64;
    let original_expansions = AtomicU64::new(0);
    for (request, nonce, wire) in &cases {
        charged_bytes +=
            2 * (wire.len() + caller_message(request, *nonce, true).unwrap().len()) as u64;
        let expected = original(&owner, request, *nonce, wire, &original_expansions)
            .unwrap_err()
            .to_string();
        assert_eq!(
            owner
                .verify_caller(request, *nonce, wire)
                .unwrap_err()
                .to_string(),
            expected
        );
    }
    let after = budget.usage().unwrap();
    assert_eq!(after.attempts - before.attempts, 2 * cases.len() as u64);
    assert_eq!(after.bytes - before.bytes, charged_bytes);
    assert!(after.actual_thread_cpu_ns > before.actual_thread_cpu_ns);
    assert!(!after.unavailable);
    assert_eq!(retained(cache), 1);
    assert!(cache
        .cached(other.public_spki(), digest(other.public_key()).unwrap())
        .is_none());

    // A mathematically valid caller signature cannot repair a stale/different
    // server cookie. The existing owner's current profile/epoch checks still win.
    for field in ["profile", "epoch"] {
        let mut changed = c.clone();
        if field == "profile" {
            changed.profile = "00".repeat(32);
        } else {
            changed.epoch = "00".repeat(32);
        }
        let signed = solution(&changed, 25, &caller);
        owner.verify_caller(&changed, 25, &signed).unwrap();
        assert!(owner.validate(&changed, &settings, true).is_err());
    }

    let hits = cache.hits.load(Ordering::Relaxed);
    let expansions = cache.expansions.load(Ordering::Relaxed);
    budget.usage.lock().unwrap().attempts = MAX_AUTHENTICATIONS;
    assert!(owner
        .verify_caller(&c, 23, &bytes)
        .unwrap_err()
        .to_string()
        .contains("PUBLIC_MUTATION_CPU_BUDGET"));
    assert_eq!(cache.hits.load(Ordering::Relaxed), hits);
    assert_eq!(cache.expansions.load(Ordering::Relaxed), expansions);
    assert_eq!(budget.usage().unwrap().attempts, MAX_AUTHENTICATIONS);
}

#[test]
fn verifier_slots_are_bounded_shared_by_the_original_epoch_and_cold_after_restart() {
    let owner = server();
    let settings = Settings::development(Some(1)).unwrap();
    let intake = owner.listener_intake().unwrap();
    let cache = &intake.pq_authentication.verifiers;
    let callers: Vec<_> = (80..80 + MAX_VERIFIERS as u8 + 2).map(identity).collect();
    for (index, caller) in callers.iter().enumerate() {
        let c = cookie(&owner, &settings, caller);
        owner
            .verify_caller(&c, 23, &solution(&c, 23, caller))
            .unwrap();
        assert_eq!(retained(cache), (index + 1).min(MAX_VERIFIERS));
    }
    let first = &callers[0];
    assert!(cache
        .cached(first.public_spki(), digest(first.public_key()).unwrap())
        .is_none());
    let last = callers.last().unwrap();
    let pinned = cache
        .cached(last.public_spki(), digest(last.public_key()).unwrap())
        .unwrap();
    let domain = owner.mutation_cpu_domain();
    let reconstructed =
        PublicServer::with_continuous_pq_history(identity(74), owner.policy, &domain).unwrap();
    let shared = reconstructed.listener_intake().unwrap();
    assert!(Arc::ptr_eq(&intake, &shared));
    assert!(Arc::ptr_eq(
        &pinned,
        &shared
            .pq_authentication
            .verifiers
            .cached(last.public_spki(), digest(last.public_key()).unwrap())
            .unwrap()
    ));
    let fresh = server().listener_intake().unwrap();
    assert!(!Arc::ptr_eq(&intake, &fresh));
    assert_eq!(retained(&fresh.pq_authentication.verifiers), 0);
    assert_eq!(fresh.pq_authentication.usage().unwrap().attempts, 0);
}

#[test]
fn held_or_poisoned_material_lock_never_waits_or_skips_full_charged_verification() {
    let owner = server();
    let settings = Settings::development(Some(1)).unwrap();
    let caller = identity(72);
    let c = cookie(&owner, &settings, &caller);
    let bytes = solution(&c, 23, &caller);
    let mut bad = bytes.clone();
    bad[44 + ML_DSA_65_SPKI_BYTES] ^= 1;
    owner.verify_caller(&c, 23, &bytes).unwrap();
    let intake = owner.listener_intake().unwrap();
    let cache = &intake.pq_authentication.verifiers;
    let before = intake.pq_authentication.usage().unwrap();
    let expanded = cache.expansions.load(Ordering::Relaxed);
    let hits = cache.hits.load(Ordering::Relaxed);
    std::thread::scope(|scope| {
        let held = cache.entries.lock().unwrap();
        let (done, completion) = std::sync::mpsc::channel();
        let owner = &owner;
        let c = &c;
        let bytes = &bytes;
        let bad = &bad;
        let worker = scope.spawn(move || {
            let valid = owner.verify_caller(c, 23, bytes);
            let invalid = owner.verify_caller(c, 23, bad);
            done.send(()).unwrap();
            (valid, invalid)
        });
        let completed_while_held = completion.recv_timeout(Duration::from_secs(10));
        drop(held);
        let (valid, invalid) = worker.join().unwrap();
        assert!(
            completed_while_held.is_ok(),
            "material cache waited for a lock"
        );
        valid.unwrap();
        assert!(invalid.is_err());
    });
    assert_eq!(cache.expansions.load(Ordering::Relaxed), expanded + 2);
    assert_eq!(cache.hits.load(Ordering::Relaxed), hits);
    let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = cache.entries.lock().unwrap();
        panic!("only the optional mathematical material is poisoned");
    }));
    assert!(poison.is_err());
    owner.verify_caller(&c, 23, &bytes).unwrap();
    assert!(owner.verify_caller(&c, 23, &bad).is_err());
    let after = intake.pq_authentication.usage().unwrap();
    assert_eq!(after.attempts - before.attempts, 4);
    assert!(after.actual_thread_cpu_ns > before.actual_thread_cpu_ns);
    assert!(!after.unavailable);
    assert_eq!(cache.expansions.load(Ordering::Relaxed), expanded + 4);
    assert_eq!(cache.hits.load(Ordering::Relaxed), hits);
}

/// ABBA compares the entire original/candidate caller-auth function, including
/// canonical message construction, original budget reservation/CPU settlement and
/// real ML-DSA. It excludes cookie/ticket generation, networking and Node work.
/// Each arm receives the same exact independently signed bytes; successive requests
/// have different nonces. Key churn and expected bad signatures remain in the log.
#[test]
#[ignore = "paired PQ authentication cost; requires a fresh output directory"]
fn pq_caller_authentication_complete_cost() {
    let directory = std::env::var_os("TRNM_PQ_AUTH_COST_DIRECTORY")
        .expect("TRNM_PQ_AUTH_COST_DIRECTORY must name a new directory");
    let directory = std::path::Path::new(&directory);
    std::fs::create_dir(directory).unwrap();
    let mut log = std::fs::File::create(directory.join("pq-authentication-cost.jsonl")).unwrap();
    let mut emit = |row: serde_json::Value| {
        let text = serde_json::to_string(&row).unwrap();
        writeln!(log, "{text}").unwrap();
        log.flush().unwrap();
        println!("{text}");
    };
    let sources: [(&str, &[u8]); 5] = [
        ("pq_identity.rs", include_bytes!("../pq_identity.rs")),
        ("verifier_cache.rs", include_bytes!("verifier_cache.rs")),
        (
            "verifier_cache_tests.rs",
            include_bytes!("verifier_cache_tests.rs"),
        ),
        (
            "pq_auth.rs",
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../trnm-crypto-primitives/src/pq_auth.rs"
            )),
        ),
        (
            "Cargo.lock",
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock")),
        ),
    ];
    let source_files: Vec<_> = sources
        .iter()
        .map(|(path, bytes)| json!({"path":path,"sha256":hex::encode(Sha256::digest(bytes))}))
        .collect();
    emit(json!({
        "schema":"pon-pq-caller-auth-cost-source-v1","source_files":source_files,
        "binary_sha256":hex::encode(Sha256::digest(
            std::fs::read(std::env::current_exe().unwrap()).unwrap()
        )),
        "architecture":std::env::consts::ARCH,"order":"ABBA",
        "compiled_debug_assertions":cfg!(debug_assertions),
        "build_profile_scope":"the existing CI compiled test binary; no release-capacity claim",
        "reference":"retained pre-cache PQ caller authentication in this same test binary",
        "samples_per_arm_per_case":64,"retained_slots":MAX_VERIFIERS,
        "timed_scope":"complete charged caller authentication; no ticket, network or Node",
        "same_original_intake_budget_for_both_arms":true,
        "process_rss_measured":false,"public_network_ready":false,"production_activation":false
    }));
    let mut samples = 0usize;
    let mut mismatches = 0usize;
    let mut unknown_cpu = 0usize;
    for (case, keys, invalid) in [
        ("one-warm-key", 1usize, false),
        ("eight-warm-keys", MAX_VERIFIERS, false),
        ("sixteen-key-churn", 2 * MAX_VERIFIERS, false),
        ("warm-invalid-signature", 1, true),
    ] {
        let owner = server();
        let settings = Settings::development(Some(1)).unwrap();
        let original_expansions = AtomicU64::new(0);
        let callers: Vec<_> = (0..keys).map(|n| identity(100 + n as u8)).collect();
        let cookies: Vec<_> = callers
            .iter()
            .map(|caller| cookie(&owner, &settings, caller))
            .collect();
        for (caller, c) in callers.iter().zip(&cookies) {
            let wire = solution(c, 23, caller);
            original(&owner, c, 23, &wire, &original_expansions).unwrap();
            owner.verify_caller(c, 23, &wire).unwrap();
        }
        let inputs: Vec<_> = (0..64)
            .map(|index| {
                let nonce = 1000 + index as u64;
                let mut wire = solution(&cookies[index % keys], nonce, &callers[index % keys]);
                if invalid {
                    wire[44 + ML_DSA_65_SPKI_BYTES] ^= 1;
                }
                (nonce, wire)
            })
            .collect();
        let intake = owner.listener_intake().unwrap();
        let cache = &intake.pq_authentication.verifiers;
        for pair in 0..32 {
            for (arm, index) in [
                ("original", 2 * pair),
                ("cached", 2 * pair),
                ("cached", 2 * pair + 1),
                ("original", 2 * pair + 1),
            ] {
                let before = intake.pq_authentication.usage().unwrap();
                let expansion_counter = if arm == "original" {
                    &original_expansions
                } else {
                    &cache.expansions
                };
                let expansions = expansion_counter.load(Ordering::Relaxed);
                let hits = cache.hits.load(Ordering::Relaxed);
                let (nonce, wire) = &inputs[index];
                let c = &cookies[index % keys];
                let stamp = ThreadCpuStamp::start();
                let started = Instant::now();
                let result = if arm == "original" {
                    original(&owner, c, *nonce, wire, &original_expansions)
                } else {
                    owner.verify_caller(c, *nonce, wire)
                };
                let elapsed_ns = started.elapsed().as_nanos();
                let cpu_ns = stamp.and_then(ThreadCpuStamp::finish);
                let error = result.err().map(|e| e.to_string());
                let expected = if invalid {
                    Some("PUBLIC_CALLER_SIGNATURE")
                } else {
                    None
                };
                let matches_expected = error.as_deref() == expected;
                let after = intake.pq_authentication.usage().unwrap();
                let accounting = after.attempts == before.attempts + 1
                    && after.bytes
                        == before.bytes
                            + (wire.len() + caller_message(c, *nonce, true).unwrap().len()) as u64
                    && !after.unavailable;
                mismatches += usize::from(!matches_expected || !accounting);
                unknown_cpu += usize::from(cpu_ns.is_none());
                emit(json!({
                    "schema":"pon-pq-caller-auth-cost-sample-v1",
                    "case":case,"pair":pair,"input":index,"arm":arm,"nonce":nonce,
                    "wire_sha256":hex::encode(Sha256::digest(wire)),
                    "elapsed_ns":elapsed_ns,"thread_cpu_ns":cpu_ns,
                    "error":error,"matches_expected":matches_expected,
                    "original_accounting_preserved":accounting,
                    "charged_cpu_ns":after.actual_thread_cpu_ns-before.actual_thread_cpu_ns,
                    "actual_completed_expansions":expansion_counter.load(Ordering::Relaxed)-expansions,
                    "actual_cache_hits":cache.hits.load(Ordering::Relaxed)-hits,
                    "retained_slots":retained(cache)
                }));
                samples += 1;
            }
        }
    }
    emit(json!({
        "schema":"pon-pq-caller-auth-cost-result-v1","complete":true,
        "samples":samples,"cases":4,"unexpected_outcomes_or_accounting":mismatches,
        "unknown_thread_cpu":unknown_cpu,"public_network_ready":false,
        "production_activation":false
    }));
    assert_eq!(samples, 512);
    assert_eq!(mismatches, 0);
    assert_eq!(unknown_cpu, 0);
}
