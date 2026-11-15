#![cfg(unix)]
//! Exercise the original process boundary: auth rejection must precede cache IO.
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_data_availability::cell::{
    digest_hex, CellCacheConfigV4, CellContextV1, CellReleaseManifestV1, CellStoreV1,
};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

fn run(binary: &str, args: &[String]) -> Output {
    Command::new(binary).args(args).output().unwrap()
}
fn success(output: Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn value(args: &mut [String], name: &str, new: impl ToString) {
    let i = args.iter().position(|v| v == name).unwrap();
    args[i + 1] = new.to_string();
}
fn path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
fn flags(pairs: &[(&str, String)]) -> Vec<String> {
    pairs
        .iter()
        .flat_map(|(k, v)| [k.to_string(), v.clone()])
        .collect()
}

#[test]
fn original_release_cli_pq_fetch_checks_auth_before_cache_or_marker() {
    let bin = env!("CARGO_BIN_EXE_trnm-cell");
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let seed_path = dir.join("seed");
    fs::write(&seed_path, [42; 32]).unwrap();
    fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).unwrap();
    let spki_path = dir.join("public.der");
    success(run(
        bin,
        &[
            "pq-key-public".into(),
            "--pq-seed-file".into(),
            path(&seed_path),
            "--output".into(),
            path(&spki_path),
        ],
    ));
    let spki = PqNativeSigningKey::public_spki_from_seed(&Zeroizing::new([42; 32]));
    assert_eq!(fs::read(&spki_path).unwrap(), spki);
    let key = digest_hex(ml_dsa_65_key_id_from_spki(&spki).unwrap());
    let cache = CellCacheConfigV4 {
        max_database_bytes: 4_194_304,
        max_logical_bytes: 2_097_152,
        max_chunk_rows: 256,
        max_manifest_rows: 64,
    };
    let store_path = dir.join("cache");
    let store = CellStoreV1::open(&store_path, cache).unwrap();
    let input = dir.join("input");
    fs::write(&input, vec![17; 20_000]).unwrap();
    let context = CellContextV1 {
        family: "cli-pq".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    };
    let manifest = store.pack_file(&input, context.clone(), 16_384).unwrap();
    drop(store);
    let release = CellReleaseManifestV1::new(context, vec![manifest.id()]).unwrap();
    let root = dir.join("release.tcr1");
    fs::write(&root, release.encode()).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let auth = dir.join("release.cpr2");
    let mut sign = vec!["sign-release".into()];
    sign.extend(flags(&[
        ("--authentication-profile", "cell-pq-v2".into()),
        ("--release-file", path(&root)),
        ("--release", digest_hex(release.id())),
        ("--output", path(&auth)),
        ("--pq-seed-file", path(&seed_path)),
        ("--pq-signer-key-id", key.clone()),
        ("--pq-network", digest_hex([6; 32])),
        ("--pq-parameters", digest_hex([7; 32])),
        ("--pq-generation", "1".into()),
        ("--pq-sequence", "4".into()),
        ("--pq-issued", (now - 1).to_string()),
        ("--pq-expires", (now + 300).to_string()),
    ]));
    success(run(bin, &sign));
    assert_eq!(fs::read(&auth).unwrap().len(), 3509);
    let marker = dir.join("complete");
    let mut fetch = vec!["fetch-release".into()];
    fetch.extend(flags(&[
        ("--store", path(&store_path)),
        ("--cache-max-db-bytes", cache.max_database_bytes.to_string()),
        ("--cache-max-bytes", cache.max_logical_bytes.to_string()),
        ("--cache-max-chunks", cache.max_chunk_rows.to_string()),
        ("--cache-max-manifests", cache.max_manifest_rows.to_string()),
        ("--release-file", path(&root)),
        ("--release", digest_hex(release.id())),
        ("--peers", String::new()),
        ("--output", path(&marker)),
        ("--max-bytes", "1048576".into()),
        ("--max-chunks", "64".into()),
        ("--seconds", "10".into()),
        ("--max-response-bytes", "0".into()),
        ("--authentication-profile", "cell-pq-v2".into()),
        ("--pq-authorization", path(&auth)),
        ("--pq-signer-spki", path(&spki_path)),
        ("--pq-signer-key-id", key),
        ("--pq-generation", "1".into()),
        ("--pq-sequence", "4".into()),
        ("--pq-network", digest_hex([6; 32])),
        ("--pq-parameters", digest_hex([7; 32])),
        ("--pq-key-not-before", (now - 10).to_string()),
        ("--pq-key-expires", (now + 600).to_string()),
    ]));
    success(run(bin, &fetch));
    assert_eq!(fs::read(marker).unwrap(), release.encode());
    let absent = dir.join("must-not-open-cache");
    let output = dir.join("must-not-publish");
    value(&mut fetch, "--store", path(&absent));
    value(&mut fetch, "--output", path(&output));
    for (flag, bad) in [
        ("--pq-sequence", "3".into()),
        ("--pq-generation", "2".into()),
        ("--pq-key-expires", now.to_string()),
        ("--authentication-profile", "classical-or-pq".into()),
    ] {
        let mut negative = fetch.clone();
        value(&mut negative, flag, bad);
        assert!(!run(bin, &negative).status.success());
        assert!(!absent.exists());
        assert!(!output.exists());
    }
    let mut forged = fs::read(&auth).unwrap();
    forged[500] ^= 1;
    fs::write(&auth, forged).unwrap();
    assert!(!run(bin, &fetch).status.success());
    assert!(!absent.exists());
    assert!(!output.exists());
    fs::write(&auth, [0; 335]).unwrap();
    assert!(!run(bin, &fetch).status.success());
    assert!(!absent.exists());
}

#[test]
fn discovery_cli_pq_key_and_fresh_directory_reject_classic_wire_and_seed_aliases() {
    let bin = env!("CARGO_BIN_EXE_trnm-cell-discovery");
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let seed = dir.join("seed");
    fs::write(&seed, [42; 32]).unwrap();
    fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).unwrap();
    let spki = dir.join("key.der");
    let profile = vec!["--profile".into(), "cell-provider-discovery-pq-v2".into()];
    let mut public = vec!["key-public".into()];
    public.extend(profile.clone());
    public.extend(flags(&[
        ("--secret-key-file", path(&seed)),
        ("--spki-output", path(&spki)),
    ]));
    success(run(bin, &public));
    let id = digest_hex(ml_dsa_65_key_id_from_spki(&fs::read(&spki).unwrap()).unwrap());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let keys = dir.join("keys.cpk2");
    let mut pin = vec!["pin-key".into()];
    pin.extend(profile.clone());
    pin.extend(flags(&[
        ("--spki", path(&spki)),
        ("--owner", id),
        ("--owner-generation", "1".into()),
        ("--key-not-before", (now - 10).to_string()),
        ("--key-expires", (now + 3600).to_string()),
        ("--keys-output", path(&keys)),
    ]));
    success(run(bin, &pin));
    let db = dir.join("directory");
    let mut init = vec!["init".into()];
    init.extend(profile);
    init.extend(flags(&[
        ("--directory", path(&db)),
        ("--namespace", digest_hex([1; 32])),
        ("--network", digest_hex([2; 32])),
        ("--parameters", digest_hex([3; 32])),
        ("--genesis", digest_hex([4; 32])),
        ("--pq-keys-file", path(&keys)),
    ]));
    success(run(bin, &init));
    success(run(bin, &init));
    value(&mut init, "--profile", "cell-provider-discovery-dev-v1");
    let i = init.iter().position(|v| v == "--pq-keys-file").unwrap();
    init.drain(i..i + 2);
    assert!(!run(bin, &init).status.success());
    let alias = dir.join("seed-alias");
    std::os::unix::fs::symlink(&seed, &alias).unwrap();
    value(&mut public, "--secret-key-file", path(&alias));
    value(&mut public, "--spki-output", path(&dir.join("blocked.der")));
    assert!(!run(bin, &public).status.success());
    assert!(!dir.join("blocked.der").exists());
}
