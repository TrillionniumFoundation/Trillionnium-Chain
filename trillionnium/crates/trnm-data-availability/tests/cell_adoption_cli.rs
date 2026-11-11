#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::{json, Value};
use trnm_data_availability::cell::{
    CellCacheConfigV4, CellClosureFileV1, CellContextV1, CellFileRoleV1, CellManifestV1,
    CellModelReleaseRootV1, CellReleaseClosureV1, CellStoreV1, CellVersionManifestV1,
};

struct Fixture {
    dir: tempfile::TempDir,
    owner: PathBuf,
    policy: PathBuf,
    execution: PathBuf,
    cache: PathBuf,
    anchor_file: PathBuf,
    candidate_file: PathBuf,
    anchor: CellVersionManifestV1,
    candidate: CellVersionManifestV1,
}

impl Fixture {
    fn new(node: u8) -> Self {
        // Operator-input privacy is an explicit fixture precondition; neither
        // tempfile's defaults nor the test runner's umask establishes it.
        let temporary_parent = std::env::temp_dir().canonicalize().unwrap();
        let dir = tempfile::tempdir_in(temporary_parent).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let owner_dir = dir.path().join("private-owner");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&owner_dir)
            .unwrap();
        let owner = owner_dir.join("adoption.sqlite");
        let cache = dir.path().join("cache.sqlite");
        let store = CellStoreV1::open(
            &cache,
            CellCacheConfigV4 {
                max_database_bytes: 64 << 20,
                max_logical_bytes: 32 << 20,
                max_chunk_rows: 128,
                max_manifest_rows: 64,
            },
        )
        .unwrap();
        let anchor = make_version(&store, None, 21);
        let candidate = make_version(&store, Some(&anchor), 81);
        let anchor_file = dir.path().join("anchor.tcv1");
        let candidate_file = dir.path().join("candidate.tcv1");
        fs::write(&anchor_file, anchor.encode()).unwrap();
        fs::set_permissions(&anchor_file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&candidate_file, candidate.encode()).unwrap();
        drop(store);
        let execution = dir.path().join("execution.json");
        let execution_value = json!({
            "network": hex(&[31; 32]),
            "consensus": hex(&[32; 32]),
            "fees": hex(&[33; 32]),
            "root_authority": hex(&[34; 32]),
            "node_software": hex(&[35; 32]),
            "protocol_configuration": hex(&[36; 32])
        });
        write_json(&execution, &execution_value);
        let policy = dir.path().join("operator-policy.json");
        write_json(
            &policy,
            &json!({
                "schema": "trnm.cell.adoption.policy.v1",
                "node_id": hex(&[node; 32]),
                "policy_id": hex(&[52; 32]),
                "scope": hex(&[53; 32]),
                "execution": execution_value,
                "mutable_roles": ["Base"],
                "max_model_payload_bytes": 1_000_000,
                "max_model_chunks": 64
            }),
        );
        Self {
            dir,
            owner,
            policy,
            execution,
            cache,
            anchor_file,
            candidate_file,
            anchor,
            candidate,
        }
    }

    fn command(&self, name: &str, floor: Option<&Path>) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-cell-adoption"));
        command
            .arg(name)
            .arg("--owner-db")
            .arg(&self.owner)
            .arg("--policy-file")
            .arg(&self.policy)
            .arg("--anchor")
            .arg(&self.anchor_file);
        if let Some(floor) = floor {
            command.arg("--recovery-floor").arg(floor);
        }
        command
    }

    fn save_floor(&self, name: &str, output: &Value) -> PathBuf {
        let path = self.dir.path().join(format!("{name}.floor.json"));
        write_json(&path, &output["recovery_floor"]);
        path
    }

    fn init(&self) -> (Value, PathBuf) {
        let output = good(&mut self.command("init", None));
        let floor = self.save_floor("initial", &output);
        (output, floor)
    }

    fn observe_anchor(&self, floor: &Path) -> Value {
        good(
            self.command("observe", Some(floor))
                .arg("--candidate")
                .arg(&self.anchor_file),
        )
    }

    fn observe_candidate(&self, floor: &Path) -> Value {
        good(
            self.command("observe", Some(floor))
                .arg("--candidate")
                .arg(&self.candidate_file)
                .arg("--parent-commitment")
                .arg(hex(&self.anchor.commitment())),
        )
    }

    fn decision(
        &self,
        floor: &Path,
        expected: &Path,
        request: u8,
        action: &str,
        version: &CellVersionManifestV1,
    ) -> Command {
        let mut command = self.command("decide", Some(floor));
        command
            .arg("--expected-snapshot")
            .arg(expected)
            .arg("--request-id")
            .arg(hex(&[request; 32]))
            .arg("--action")
            .arg(action)
            .arg("--version-commitment")
            .arg(hex(&version.commitment()))
            .arg("--local-review")
            .arg(hex(&[101; 64]));
        command
    }

    fn verification(&self, floor: &Path, expected: &Path, candidate: &Path) -> Command {
        let mut command = self.command("verify-selected", Some(floor));
        command
            .arg("--candidate")
            .arg(candidate)
            .arg("--expected-snapshot")
            .arg(expected)
            .arg("--execution-file")
            .arg(&self.execution)
            .arg("--cache")
            .arg(&self.cache)
            .arg("--read-ms")
            .arg("30000");
        command
    }

    fn adopt_anchor(&self) -> PathBuf {
        let (_, initial) = self.init();
        self.observe_anchor(&initial);
        let adopted = good(&mut self.decision(&initial, &initial, 1, "adopt", &self.anchor));
        self.save_floor("adopted", &adopted)
    }
}

fn context(runtime: [u8; 32], parent: [u8; 32]) -> CellContextV1 {
    CellContextV1 {
        family: "local-adoption-cli-test".into(),
        base: [1; 32],
        parent,
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime,
    }
}

fn payload(
    store: &CellStoreV1,
    context: CellContextV1,
    seed: u8,
    name: &str,
    role: CellFileRoleV1,
    dependencies: Vec<u16>,
) -> (CellClosureFileV1, CellManifestV1) {
    let bytes = vec![seed; 257];
    let input = tempfile::NamedTempFile::new().unwrap();
    fs::write(input.path(), &bytes).unwrap();
    let manifest = store.pack_file(input.path(), context, 16_384).unwrap();
    (
        CellClosureFileV1 {
            path: name.into(),
            role,
            manifest: manifest.id(),
            payload_sha256: manifest.payload_sha256(),
            payload_bytes: bytes.len() as u64,
            dependencies,
        },
        manifest,
    )
}

fn make_version(
    store: &CellStoreV1,
    parent: Option<&CellVersionManifestV1>,
    seed: u8,
) -> CellVersionManifestV1 {
    let env_context = context([5; 32], [2; 32]);
    let (environment_file, environment_manifest) = payload(
        store,
        env_context.clone(),
        11,
        "runtime.bin",
        CellFileRoleV1::Configuration,
        vec![],
    );
    let environment =
        CellReleaseClosureV1::new(env_context, 1, [6; 32], vec![0], vec![environment_file])
            .unwrap();
    let model_context = context(environment.id(), parent.map_or([2; 32], |p| p.model().id()));
    let (base_file, base_manifest) = payload(
        store,
        model_context.clone(),
        seed,
        "base.bin",
        CellFileRoleV1::Base,
        vec![1],
    );
    let (tokenizer_file, tokenizer_manifest) = payload(
        store,
        model_context.clone(),
        22,
        "tokenizer.json",
        CellFileRoleV1::Tokenizer,
        vec![],
    );
    let closure = CellReleaseClosureV1::new(
        model_context,
        parent.map_or(2, |p| p.model().closure().selected_generation() + 1),
        [7; 32],
        vec![0],
        vec![base_file, tokenizer_file],
    )
    .unwrap();
    let model = CellModelReleaseRootV1::new(
        closure,
        parent.map(|p| vec![p.model().id()]).unwrap_or_default(),
    )
    .unwrap();
    let mut manifests = vec![environment_manifest, base_manifest, tokenizer_manifest];
    manifests.sort_by_key(CellManifestV1::id);
    CellVersionManifestV1::new(model, environment, manifests).unwrap()
}

fn good(command: &mut Command) -> Value {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "command {command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    for field in [
        "use_authority",
        "final_use_granted",
        "independent_evaluation_verified",
        "chain_confirmation_verified",
    ] {
        assert_eq!(value[field], false, "{field}");
    }
    assert_eq!(value["independent_recovery_floor_required"], true);
    value
}

fn bad(command: &mut Command, message: &str) {
    let output = command.output().unwrap();
    assert!(!output.status.success(), "unexpected success: {command:?}");
    assert!(
        output.stdout.is_empty(),
        "failed command emitted success JSON"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(message),
        "expected {message:?}, got {stderr:?}"
    );
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[test]
fn cli_init_and_observe_select_nothing_and_all_four_decisions_are_explicit() {
    let f = Fixture::new(51);
    let (initial, floor0) = f.init();
    assert_eq!(initial["snapshot"]["revision"], 0);
    assert!(initial["snapshot"]["selected"].is_null());
    assert_eq!(
        fs::metadata(&f.owner).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let observation = f.observe_anchor(&floor0);
    assert_eq!(observation["snapshot"], initial["snapshot"]);
    bad(
        &mut f.verification(&floor0, &floor0, &f.anchor_file),
        "selected use snapshot",
    );
    let adopted = good(&mut f.decision(&floor0, &floor0, 1, "adopt", &f.anchor));
    let floor1 = f.save_floor("one", &adopted);
    let verified = good(&mut f.verification(&floor1, &floor1, &f.anchor_file));
    assert_eq!(verified["result"]["payload_bytes_verified"], true);
    assert_eq!(verified["result"]["payload_bytes"], 771);
    assert_eq!(verified["result"]["chunks"], 3);
    assert_eq!(verified["result"]["safe_tensor_parser_executed"], false);
    let observed = f.observe_candidate(&floor1);
    assert_eq!(observed["snapshot"], adopted["snapshot"]);

    let mut floor = floor1;
    for (request, action, version, selected) in [
        (2, "defer", &f.candidate, &f.anchor),
        (3, "retain", &f.anchor, &f.anchor),
        (4, "adopt", &f.candidate, &f.candidate),
        (5, "rollback", &f.anchor, &f.anchor),
    ] {
        let result = good(&mut f.decision(&floor, &floor, request, action, version));
        assert_eq!(result["snapshot"]["revision"], request);
        assert_eq!(result["snapshot"]["selected"], hex(&selected.commitment()));
        floor = f.save_floor(&format!("revision-{request}"), &result);
    }
    bad(
        &mut f.verification(&floor, &floor, &f.candidate_file),
        "selected use snapshot",
    );
    good(&mut f.verification(&floor, &floor, &f.anchor_file));
    let reopened = good(&mut f.command("status", Some(&floor)));
    assert_eq!(reopened["snapshot"]["revision"], 5);
    assert_eq!(
        reopened["snapshot"]["selected"],
        hex(&f.anchor.commitment())
    );
}

#[test]
fn cli_nodes_can_adopt_or_defer_the_same_candidate_independently() {
    let a = Fixture::new(51);
    let b = Fixture::new(61);
    assert_eq!(a.candidate, b.candidate);
    let a_floor = a.adopt_anchor();
    let b_floor = b.adopt_anchor();
    a.observe_candidate(&a_floor);
    b.observe_candidate(&b_floor);
    let adopted = good(&mut a.decision(&a_floor, &a_floor, 2, "adopt", &a.candidate));
    let deferred = good(&mut b.decision(&b_floor, &b_floor, 2, "defer", &b.candidate));
    let a_next = a.save_floor("candidate", &adopted);
    let b_next = b.save_floor("deferred", &deferred);
    assert_eq!(
        adopted["snapshot"]["selected"],
        hex(&a.candidate.commitment())
    );
    assert_eq!(
        deferred["snapshot"]["selected"],
        hex(&b.anchor.commitment())
    );
    good(&mut a.verification(&a_next, &a_next, &a.candidate_file));
    bad(
        &mut b.verification(&b_next, &b_next, &b.candidate_file),
        "selected use snapshot",
    );
    bad(
        &mut a.verification(&a_next, &a_floor, &a.candidate_file),
        "selected use snapshot",
    );
    bad(&mut b.command("status", Some(&a_next)), "recovery policy");
}

#[test]
fn cli_strict_policy_rejects_unknown_authority_fields_roles_and_noncanonical_hex() {
    let f = Fixture::new(0xab);
    let original = read_json(&f.policy);
    for field in [
        "root_authority",
        "consensus_update",
        "fee_update",
        "execute",
        "auto_adopt",
    ] {
        let mut changed = original.clone();
        changed[field] = json!(true);
        write_json(&f.policy, &changed);
        bad(&mut f.command("init", None), "unknown field");
        assert!(!f.owner.exists());
    }
    let mut changed = original.clone();
    changed["execution"]["allow_root_update"] = json!(true);
    write_json(&f.policy, &changed);
    bad(&mut f.command("init", None), "unknown field");
    let mut changed = original.clone();
    changed["mutable_roles"] = json!(["Configuration"]);
    write_json(&f.policy, &changed);
    bad(&mut f.command("init", None), "unknown variant");
    let mut changed = original.clone();
    changed["node_id"] = json!(hex(&[0xab; 32]).to_uppercase());
    write_json(&f.policy, &changed);
    bad(&mut f.command("init", None), "lowercase hexadecimal");
    let mut changed = original.clone();
    changed["node_id"] = json!("ab");
    write_json(&f.policy, &changed);
    bad(&mut f.command("init", None), "byte width");
    write_json(&f.policy, &original);
    let text = fs::read_to_string(&f.policy).unwrap();
    let duplicate = format!("{{\"node_id\":\"{}\",{}", hex(&[0xab; 32]), &text[1..]);
    fs::write(&f.policy, duplicate).unwrap();
    bad(&mut f.command("init", None), "duplicate field");
    write_json(&f.policy, &original);
    let (_, floor) = f.init();
    let mut changed = original;
    changed["execution"]["root_authority"] = json!(hex(&[90; 32]));
    write_json(&f.policy, &changed);
    bad(&mut f.command("status", Some(&floor)), "recovery policy");
}

#[test]
fn cli_requires_floor_review_expected_snapshot_and_rejects_extra_arguments() {
    let f = Fixture::new(51);
    let (_, floor) = f.init();
    f.observe_anchor(&floor);
    bad(
        &mut f.command("status", None),
        "required argument --recovery-floor",
    );
    bad(
        f.command("init", None).arg("--grant-final-use").arg("true"),
        "unknown local adoption argument",
    );
    bad(
        f.command("observe", Some(&floor))
            .arg("--candidate")
            .arg(&f.anchor_file)
            .arg("--candidate")
            .arg(&f.candidate_file),
        "unique",
    );
    bad(
        f.command("decide", Some(&floor))
            .arg("--request-id")
            .arg(hex(&[1; 32])),
        "required argument --expected-snapshot",
    );
    let mut missing_review = f.command("decide", Some(&floor));
    missing_review
        .arg("--request-id")
        .arg(hex(&[1; 32]))
        .arg("--expected-snapshot")
        .arg(&floor)
        .arg("--action")
        .arg("adopt")
        .arg("--version-commitment")
        .arg(hex(&f.anchor.commitment()));
    bad(&mut missing_review, "required argument --local-review");
    let forbidden_floor = f.owner.parent().unwrap().join("co-restored.floor.json");
    fs::copy(&floor, &forbidden_floor).unwrap();
    bad(
        &mut f.command("status", Some(&forbidden_floor)),
        "outside the owner database directory",
    );
    let mut changed = read_json(&floor);
    changed["trusted"] = json!(true);
    let forged_floor = f.dir.path().join("forged.floor.json");
    write_json(&forged_floor, &changed);
    bad(
        &mut f.command("status", Some(&forged_floor)),
        "unknown field",
    );
    let status = good(&mut f.command("status", Some(&floor)));
    assert_eq!(status["snapshot"]["revision"], 0);
    assert!(status["snapshot"]["selected"].is_null());
}

#[test]
fn cli_evidence_references_do_not_authenticate_claims_or_select_a_candidate() {
    let f = Fixture::new(51);
    let (_, floor) = f.init();
    let evidence = f.dir.path().join("evidence.json");
    write_json(
        &evidence,
        &json!({
            "schema": "trnm.cell.adoption.evidence.v1",
            "evaluation": hex(&[71; 64]),
            "reproduction": hex(&[72; 64]),
            "chain_observation": hex(&[73; 64]),
            "settlement": hex(&[74; 64]),
            "independent_accepted": true
        }),
    );
    bad(
        f.command("observe", Some(&floor))
            .arg("--candidate")
            .arg(&f.anchor_file)
            .arg("--evidence-file")
            .arg(&evidence),
        "unknown field",
    );
    let mut valid = read_json(&evidence);
    valid
        .as_object_mut()
        .unwrap()
        .remove("independent_accepted");
    write_json(&evidence, &valid);
    let output = good(
        f.command("observe", Some(&floor))
            .arg("--candidate")
            .arg(&f.anchor_file)
            .arg("--evidence-file")
            .arg(&evidence),
    );
    assert!(output["snapshot"]["selected"].is_null());
    assert_eq!(output["snapshot"]["revision"], 0);
    assert_eq!(output["result"]["payload_bytes_verified"], false);
}

#[test]
fn cli_historical_request_replay_exports_current_floor_and_conflicts_refuse() {
    let f = Fixture::new(51);
    let (_, floor0) = f.init();
    f.observe_anchor(&floor0);
    let first = good(&mut f.decision(&floor0, &floor0, 1, "adopt", &f.anchor));
    let floor1 = f.save_floor("first", &first);
    let second = good(&mut f.decision(&floor1, &floor1, 2, "retain", &f.anchor));
    let floor2 = f.save_floor("second", &second);
    let replay = good(&mut f.decision(&floor2, &floor0, 1, "adopt", &f.anchor));
    assert_eq!(replay["result"], first["result"]);
    assert_eq!(replay["result"]["after"]["revision"], 1);
    assert_eq!(replay["snapshot"]["revision"], 2);
    assert_eq!(replay["recovery_floor"], second["recovery_floor"]);
    bad(
        &mut f.decision(&floor2, &floor0, 1, "defer", &f.anchor),
        "request identity conflict",
    );
    bad(
        &mut f.decision(&floor2, &floor0, 3, "retain", &f.anchor),
        "stale local snapshot",
    );
    assert_eq!(
        good(&mut f.command("status", Some(&floor2)))["snapshot"]["revision"],
        2
    );
}

#[test]
fn cli_latest_independent_floor_rejects_a_rolled_back_database() {
    let f = Fixture::new(51);
    let (_, floor0) = f.init();
    f.observe_anchor(&floor0);
    let old_database = fs::read(&f.owner).unwrap();
    let chosen = good(&mut f.decision(&floor0, &floor0, 1, "adopt", &f.anchor));
    let floor1 = f.save_floor("separately-retained-latest", &chosen);
    fs::write(&f.owner, old_database).unwrap();
    bad(&mut f.command("status", Some(&floor1)), "recovery");
    bad(
        &mut f.verification(&floor1, &floor1, &f.anchor_file),
        "recovery",
    );
}

#[test]
fn cli_selected_readback_rejects_changed_execution_pins_and_corrupted_cache_bytes() {
    let f = Fixture::new(51);
    let floor = f.adopt_anchor();
    good(&mut f.verification(&floor, &floor, &f.anchor_file));
    let original = read_json(&f.execution);
    for field in [
        "network",
        "consensus",
        "fees",
        "root_authority",
        "node_software",
        "protocol_configuration",
    ] {
        let mut changed = original.clone();
        changed[field] = json!(hex(&[91; 32]));
        write_json(&f.execution, &changed);
        bad(
            &mut f.verification(&floor, &floor, &f.anchor_file),
            "execution boundary changed",
        );
    }
    write_json(&f.execution, &original);
    let connection = rusqlite::Connection::open(&f.cache).unwrap();
    connection
        .execute(
            "UPDATE cell_chunks_v1 SET bytes=zeroblob(length(bytes)) WHERE hash=?1",
            [f.anchor.manifests()[0].chunks()[0].sha256.as_slice()],
        )
        .unwrap();
    drop(connection);
    bad(&mut f.verification(&floor, &floor, &f.anchor_file), "");
    assert_eq!(
        good(&mut f.command("status", Some(&floor)))["snapshot"]["revision"],
        1
    );
}

#[test]
fn cli_refuses_symlink_inputs_and_create_never_resets_an_existing_owner() {
    let f = Fixture::new(51);
    let real_policy = f.dir.path().join("real-policy.json");
    fs::rename(&f.policy, &real_policy).unwrap();
    std::os::unix::fs::symlink(&real_policy, &f.policy).unwrap();
    bad(&mut f.command("init", None), "");
    assert!(!f.owner.exists());
    fs::remove_file(&f.policy).unwrap();
    fs::rename(real_policy, &f.policy).unwrap();
    let (_, floor) = f.init();
    let original = fs::read(&f.owner).unwrap();
    bad(&mut f.command("init", None), "");
    assert_eq!(fs::read(&f.owner).unwrap(), original);
    assert_eq!(
        good(&mut f.command("status", Some(&floor)))["snapshot"]["revision"],
        0
    );
}

#[test]
fn cli_operator_inputs_require_private_files_parents_and_single_link_identity() {
    let f = Fixture::new(51);
    for input in [&f.policy, &f.anchor_file] {
        fs::set_permissions(input, fs::Permissions::from_mode(0o644)).unwrap();
        bad(
            &mut f.command("init", None),
            "operator input owner/mode/links",
        );
        assert!(!f.owner.exists());
        fs::set_permissions(input, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let alias = f.dir.path().join("policy-hardlink.json");
    fs::hard_link(&f.policy, &alias).unwrap();
    bad(
        &mut f.command("init", None),
        "operator input owner/mode/links",
    );
    fs::remove_file(alias).unwrap();
    fs::set_permissions(f.dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
    bad(
        &mut f.command("init", None),
        "private operator input parent",
    );
    fs::set_permissions(f.dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&f.policy, fs::Permissions::from_mode(0o400)).unwrap();
    fs::set_permissions(&f.anchor_file, fs::Permissions::from_mode(0o400)).unwrap();
    let floor = f.adopt_anchor();
    fs::set_permissions(&floor, fs::Permissions::from_mode(0o644)).unwrap();
    bad(
        &mut f.command("status", Some(&floor)),
        "operator input owner/mode/links",
    );
    fs::set_permissions(&floor, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&f.execution, fs::Permissions::from_mode(0o644)).unwrap();
    bad(
        &mut f.verification(&floor, &floor, &f.anchor_file),
        "operator input owner/mode/links",
    );
    fs::set_permissions(&f.execution, fs::Permissions::from_mode(0o600)).unwrap();
    let expected = f.dir.path().join("unprotected-expected.json");
    fs::copy(&floor, &expected).unwrap();
    fs::set_permissions(&expected, fs::Permissions::from_mode(0o644)).unwrap();
    bad(
        &mut f.verification(&floor, &expected, &f.anchor_file),
        "operator input owner/mode/links",
    );
    good(&mut f.verification(&floor, &floor, &f.anchor_file));
}

#[test]
fn cli_operator_paths_must_be_absolute_with_canonical_parent_directories() {
    let f = Fixture::new(51);
    let mut relative = Command::new(env!("CARGO_BIN_EXE_trnm-cell-adoption"));
    relative
        .current_dir(f.dir.path())
        .arg("init")
        .arg("--owner-db")
        .arg(&f.owner)
        .arg("--policy-file")
        .arg(f.policy.file_name().unwrap())
        .arg("--anchor")
        .arg(&f.anchor_file);
    bad(&mut relative, "absolute operator input path");
    assert!(!f.owner.exists());
    let alias = f.dir.path().join("operator-alias");
    std::os::unix::fs::symlink(f.dir.path(), &alias).unwrap();
    let mut aliased = Command::new(env!("CARGO_BIN_EXE_trnm-cell-adoption"));
    aliased
        .arg("init")
        .arg("--owner-db")
        .arg(&f.owner)
        .arg("--policy-file")
        .arg(&f.policy)
        .arg("--anchor")
        .arg(alias.join(f.anchor_file.file_name().unwrap()));
    bad(&mut aliased, "canonical operator input parent");
    assert!(!f.owner.exists());
    // Public candidate data stays outside the private operator-input contract.
    // It still acquires no authority and must pass the pinned metadata boundary.
    fs::set_permissions(&f.candidate_file, fs::Permissions::from_mode(0o644)).unwrap();
    let floor = f.adopt_anchor();
    let observed = f.observe_candidate(&floor);
    assert_eq!(
        observed["snapshot"]["selected"],
        hex(&f.anchor.commitment())
    );
    assert_eq!(observed["snapshot"]["revision"], 1);
}
