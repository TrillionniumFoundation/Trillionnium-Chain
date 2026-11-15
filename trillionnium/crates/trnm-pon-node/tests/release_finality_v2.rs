//! Differential controls, not new network/finality/model measurements.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};
use trnm_crypto_primitives::{public_key_hex, sign_hex, signing_key_from_hex};
use trnm_pon_node::release_finality::{verify_certificate, INPUT_LIMIT};

const PREFIX: &[u8] = b"TRNM-RELEASE-FINALITY-V2\0";
const B: &[u8] = include_bytes!("fixtures/release-finality-v2/bundle.json");
const M: &[u8] = include_bytes!("fixtures/release-finality-v2/committee.json");
const C: &[u8] = include_bytes!("fixtures/release-finality-v2/context.json");
fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}
fn value(b: &[u8]) -> Value {
    serde_json::from_slice(b).unwrap()
}
fn id(v: &Value) -> String {
    hex::encode(Sha256::digest([PREFIX, &bytes(v)].concat()))
}
fn key_seed(i: usize) -> String {
    hex::encode(Sha256::digest(format!("PUBLIC TEST FIXTURE ONLY {i}")))
}
fn public(i: usize) -> String {
    public_key_hex(&signing_key_from_hex(&key_seed(i)).unwrap())
}
fn sign(body: &Value, signer: &str, domain: &[u8]) -> Value {
    let i = (0..33).find(|i| public(*i) == signer).unwrap();
    let key = signing_key_from_hex(&key_seed(i)).unwrap();
    json!({"body":body,"signer":signer,"signature":sign_hex(&key, &[domain, &bytes(body)].concat())})
}
fn seal(b: &mut Value, m: &Value, c: &mut Value, voters: &[String]) {
    c["committee"] = json!(id(m));
    b["context"] = c.clone();
    b["statement"]["context"] = json!(id(c));
    for (phase, view) in [("availability", 0), ("commit", 1)] {
        let body = json!({"context":id(c),"view":view,"phase":phase,"value":id(&b["statement"])});
        let votes: Vec<_> = voters
            .iter()
            .map(|signer| sign(&body, signer, PREFIX))
            .collect();
        b[phase] = json!({"body":body,"votes":votes});
    }
}
fn variant(n: usize, f: u64, q: u64) -> (Value, Value, Value) {
    let (mut b, mut m, mut c) = (value(B), value(M), value(C));
    let mut members: Vec<_> = (0..n).map(public).collect();
    members.sort();
    m["members"] = json!(members);
    m["fault_bound"] = json!(f);
    m["quorum"] = json!(q);
    seal(&mut b, &m, &mut c, &members);
    (b, m, c)
}
struct Case {
    name: String,
    b: Vec<u8>,
    m: Vec<u8>,
    c: Vec<u8>,
    accepted: bool,
}
fn add(
    cases: &mut Vec<Case>,
    name: impl Into<String>,
    b: &Value,
    m: &Value,
    c: &Value,
    accepted: bool,
) {
    cases.push(Case {
        name: name.into(),
        b: bytes(b),
        m: bytes(m),
        c: bytes(c),
        accepted,
    });
}
fn changed(cases: &mut Vec<Case>, name: impl Into<String>, mutate: impl FnOnce(&mut Value)) {
    let mut b = value(B);
    mutate(&mut b);
    add(cases, name, &b, &value(M), &value(C), false);
}

#[test]
fn original_reference_signed_fixture_preserves_facts_and_scope() {
    assert_eq!(bytes(&value(B)), B);
    let before = B.to_vec();
    let verified = verify_certificate(B, M, C).unwrap();
    let expected = value(include_bytes!("fixtures/release-finality-v2/expected.json"));
    assert_eq!(hex::encode(verified.value()), expected["value"]);
    assert_eq!(
        hex::encode(verified.statement().model),
        value(B)["statement"]["model"]
    );
    assert_eq!(verified.context().epoch, 0);
    assert_eq!(verified.context().height, 1);
    assert_eq!(verified.statement().retention_height, 101);
    assert_eq!(verified.statement().next_committee, None);
    assert_eq!(verified.signer_counts(), (4, 4));
    assert_eq!(verified.commit_view(), 1);
    assert!(verified.finality_certificate_valid());
    assert!(!verified.model_quality_accepted());
    assert!(!verified.long_term_availability_accepted());
    assert!(!verified.hepta_final_use());
    assert!(!verified.production_activation());
    assert_eq!(B, before);
}

#[test]
#[ignore = "requires explicit TRNM_FINALITY_REFERENCE_PYTHON with the reference dependencies"]
fn unchanged_python_reference_regenerates_exact_fixture_bytes() {
    let generator = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/release-finality-v2/generate.py");
    let output = Command::new(reference_python())
        .arg(generator)
        .arg("--check")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn corpus() -> Vec<Case> {
    let mut cases = Vec::new();
    add(
        &mut cases,
        "original-reference",
        &value(B),
        &value(M),
        &value(C),
        true,
    );
    for (n, f, q, accepted) in [
        (1, 0, 1, true),
        (5, 1, 4, true),
        (32, 10, 22, true),
        (5, 1, 3, false),
        (4, 1, 4, false),
        (33, 0, 33, false),
    ] {
        let (b, m, c) = variant(n, f, q);
        add(
            &mut cases,
            format!("committee-{n}-{f}-{q}"),
            &b,
            &m,
            &c,
            accepted,
        );
    }
    let (mut b, mut m, mut c) = variant(1, 0, 1);
    m["genesis"] = json!("0".repeat(64));
    c["genesis"] = m["genesis"].clone();
    c["parent"] = json!("0".repeat(64));
    c["parent_model"] = json!("0".repeat(64));
    for field in [
        "model",
        "evaluation",
        "availability",
        "state_root",
        "next_committee",
    ] {
        b["statement"][field] = json!("0".repeat(64));
    }
    seal(&mut b, &m, &mut c, &[public(0)]);
    add(
        &mut cases,
        "zero-digests-and-next-committee",
        &b,
        &m,
        &c,
        true,
    );
    let (mut b, mut m, mut c) = variant(1, 0, 1);
    m["epoch"] = json!((1_u64 << 63) - 1);
    c["epoch"] = m["epoch"].clone();
    c["height"] = m["epoch"].clone();
    b["statement"]["retention_height"] = m["epoch"].clone();
    seal(&mut b, &m, &mut c, &[public(0)]);
    b["commit"]["body"]["view"] = m["epoch"].clone();
    b["commit"]["votes"][0] = sign(&b["commit"]["body"], &public(0), PREFIX);
    add(&mut cases, "maximum-u63-values", &b, &m, &c, true);
    for (phase, aliases) in [
        ("availability", vec![json!(false), json!(0.0)]),
        ("commit", vec![json!(true), json!(1.0)]),
    ] {
        for alias in aliases {
            for resigned in [false, true] {
                changed(
                    &mut cases,
                    format!("nested-{phase}-{alias}-{resigned}"),
                    |b| {
                        let vote = &mut b[phase]["votes"][0];
                        vote["body"]["view"] = alias.clone();
                        if resigned {
                            *vote = sign(&vote["body"], vote["signer"].as_str().unwrap(), PREFIX);
                        }
                    },
                );
            }
        }
        for alias in [
            json!(true),
            json!(1.0),
            json!("1"),
            Value::Null,
            json!(-1),
            json!(1_u64 << 63),
        ] {
            changed(&mut cases, format!("outer-{phase}-{alias}"), |b| {
                b[phase]["body"]["view"] = alias
            });
        }
        for (field, replacement) in [
            ("context", json!("f".repeat(64))),
            ("value", json!("f".repeat(64))),
            ("phase", json!("prepare")),
            ("extra", json!(1)),
        ] {
            changed(&mut cases, format!("resigned-{phase}-{field}"), |b| {
                let vote = &mut b[phase]["votes"][0];
                vote["body"][field] = replacement;
                *vote = sign(&vote["body"], vote["signer"].as_str().unwrap(), PREFIX);
            });
        }
        for mode in [
            "duplicate",
            "reverse",
            "insufficient",
            "outsider",
            "domain",
            "S>=L",
            "R-noncanonical",
        ] {
            changed(&mut cases, format!("{phase}-{mode}"), |b| {
                let votes = b[phase]["votes"].as_array_mut().unwrap();
                match mode {
                    "duplicate" => votes[1] = votes[0].clone(),
                    "reverse" => votes.reverse(),
                    "insufficient" => votes.truncate(2),
                    "outsider" => votes[0] = sign(&votes[0]["body"], &public(10), PREFIX),
                    "domain" => {
                        votes[0] = sign(
                            &votes[0]["body"],
                            votes[0]["signer"].as_str().unwrap(),
                            b"WRONG-DOMAIN\0",
                        )
                    }
                    _ => {
                        let mut sig = hex::decode(votes[0]["signature"].as_str().unwrap()).unwrap();
                        if mode == "S>=L" {
                            sig[32..].fill(255);
                        } else {
                            sig[..32].fill(255);
                        }
                        votes[0]["signature"] = json!(hex::encode(sig));
                    }
                }
            });
        }
    }
    for field in ["epoch", "height"] {
        for alias in [json!(true), json!(1.0)] {
            changed(
                &mut cases,
                format!("bundled-context-{field}-{alias}"),
                |b| b["context"][field] = alias,
            );
        }
    }
    for field in [
        "model",
        "evaluation",
        "availability",
        "state_root",
        "context",
        "next_committee",
    ] {
        changed(&mut cases, format!("statement-{field}"), |b| {
            b["statement"][field] = json!("f".repeat(64))
        });
    }
    for alias in [
        json!(true),
        json!(101.0),
        json!("101"),
        json!(0),
        json!(1_u64 << 63),
    ] {
        changed(&mut cases, format!("retention-{alias}"), |b| {
            b["statement"]["retention_height"] = alias
        });
    }
    for path in [
        "",
        "/statement",
        "/context",
        "/commit",
        "/commit/body",
        "/commit/votes/0",
    ] {
        changed(&mut cases, format!("unknown-field-{path}"), |b| {
            b.pointer_mut(path).unwrap()["extra"] = json!(1)
        });
    }
    for (target, field) in [
        ("committee", "extra"),
        ("context", "extra"),
        ("context", "epoch"),
        ("context", "height"),
    ] {
        let (b, mut m, mut c) = (value(B), value(M), value(C));
        if target == "committee" {
            m[field] = json!(1);
        } else {
            c[field] = json!(true);
        }
        add(
            &mut cases,
            format!("trusted-{target}-{field}"),
            &b,
            &m,
            &c,
            false,
        );
    }
    for mode in ["duplicate", "reverse", "uppercase", "invalid-point"] {
        let mut m = value(M);
        let members = m["members"].as_array_mut().unwrap();
        match mode {
            "duplicate" => members[1] = members[0].clone(),
            "reverse" => members.reverse(),
            "uppercase" => members[0] = json!(members[0].as_str().unwrap().to_uppercase()),
            _ => members[0] = json!("ff".repeat(32)),
        }
        add(
            &mut cases,
            format!("members-{mode}"),
            &value(B),
            &m,
            &value(C),
            false,
        );
    }
    for field in ["epoch", "fault_bound", "quorum"] {
        for alias in [
            json!(true),
            json!(1.0),
            json!((1_u64 << 63) - 1),
            json!(1_u64 << 63),
        ] {
            let mut m = value(M);
            m[field] = alias.clone();
            add(
                &mut cases,
                format!("manifest-{field}-{alias}"),
                &value(B),
                &m,
                &value(C),
                false,
            );
        }
    }
    // Remove the replaced key's vote: weak points must fail even when unvoted.
    let (mut b, mut m, mut c) = variant(4, 1, 3);
    let mut voters: Vec<_> = m["members"]
        .as_array()
        .unwrap()
        .iter()
        .take(3)
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    m["members"][3] = json!(format!("01{}", "00".repeat(31)));
    m["members"]
        .as_array_mut()
        .unwrap()
        .sort_by_key(|v| v.as_str().unwrap().to_string());
    voters.sort();
    seal(&mut b, &m, &mut c, &voters);
    add(&mut cases, "unvoted-weak-member", &b, &m, &c, false);
    for target in ["bundle", "committee", "context"] {
        let mut row = Case {
            name: format!("oversize-{target}"),
            b: B.to_vec(),
            m: M.to_vec(),
            c: C.to_vec(),
            accepted: false,
        };
        *match target {
            "bundle" => &mut row.b,
            "committee" => &mut row.m,
            _ => &mut row.c,
        } = vec![b' '; INPUT_LIMIT + 1];
        cases.push(row);
    }
    for (name, raw) in [
        ("whitespace", [b" ".as_slice(), B].concat()),
        (
            "duplicate-root",
            [b"{\"context\":null,".as_slice(), &B[1..]].concat(),
        ),
        (
            "duplicate-nested",
            String::from_utf8(B.to_vec())
                .unwrap()
                .replace("\"view\":1", "\"view\":1,\"view\":1")
                .into_bytes(),
        ),
        (
            "escaped-key",
            String::from_utf8(B.to_vec())
                .unwrap()
                .replace("\"view\"", "\"\\u0076iew\"")
                .into_bytes(),
        ),
        (
            "NaN",
            String::from_utf8(B.to_vec())
                .unwrap()
                .replace("\"view\":1", "\"view\":NaN")
                .into_bytes(),
        ),
    ] {
        cases.push(Case {
            name: name.into(),
            b: raw,
            m: M.to_vec(),
            c: C.to_vec(),
            accepted: false,
        });
    }
    cases
}

fn assert_native(cases: &[Case]) {
    for case in cases {
        let result = verify_certificate(&case.b, &case.m, &case.c);
        assert_eq!(
            result.is_ok(),
            case.accepted,
            "native {}: {result:?}",
            case.name
        );
        if let Ok(verified) = result {
            assert!(
                !verified.model_quality_accepted()
                    && !verified.long_term_availability_accepted()
                    && !verified.hepta_final_use()
                    && !verified.production_activation()
            );
        }
    }
    println!(
        "{} native cases, {} accepted, remaining refused",
        cases.len(),
        cases.iter().filter(|case| case.accepted).count()
    );
}

#[test]
fn native_reader_enforces_adversarial_corpus_without_python() {
    assert_native(&corpus());
}

fn reference_python() -> std::ffi::OsString {
    std::env::var_os("TRNM_FINALITY_REFERENCE_PYTHON")
        .filter(|value| !value.is_empty())
        .expect(
            "explicit TRNM_FINALITY_REFERENCE_PYTHON is required; no ambient interpreter fallback",
        )
}

#[test]
#[ignore = "requires explicit TRNM_FINALITY_REFERENCE_PYTHON with the reference dependencies"]
fn original_python_reader_and_native_reader_agree_on_adversarial_corpus() {
    let cases = corpus();
    assert_native(&cases);
    let rows: Vec<_> = cases.iter().map(|case| json!({"b":hex::encode(&case.b),"m":hex::encode(&case.m),"c":hex::encode(&case.c)})).collect();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap();
    let script = "import sys,json\nsys.path.insert(0,sys.argv[1])\nfrom verify_certificate import verify\nresults=[]\nfor row in json.load(sys.stdin):\n try:\n  verify(*(bytes.fromhex(row[k]) for k in ('b','m','c')))\n  results.append(True)\n except ValueError:\n  results.append(False)\nprint(json.dumps(results))\n";
    let mut child = Command::new(reference_python())
        .args(["-c", script])
        .arg(root.join("formal/release-finality-v2"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&rows).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Vec<bool> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(expected.len(), cases.len());
    for (case, python) in cases.iter().zip(expected) {
        assert_eq!(python, case.accepted, "Python {}", case.name);
    }
    println!(
        "{} paired cases, {} accepted, remaining refused",
        cases.len(),
        cases.iter().filter(|case| case.accepted).count()
    );
}
