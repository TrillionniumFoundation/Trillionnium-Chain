//! Actual public owner openers, real Ed25519 policy signatures and complete
//! observed catalogs. These synthetic materials do not qualify model or Work.
use super::*;
use crate::{
    ingress::public_v3::ServiceMutationCpuDomain,
    operator_mining_policy as mining,
    operator_task_policy::{self as task, MaterialInput},
};
use std::collections::BTreeSet;
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_mvcc_fee::pon_executor::pq_accounts_v2::{application_v6, GenesisAccount};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

struct CatalogFixture {
    root: tempfile::TempDir,
    native: PathBuf,
    journal: PathBuf,
    rows: Vec<(String, PathBuf, u64, String)>,
    catalog: String,
}
impl CatalogFixture {
    fn new(existing_empty_store: bool) -> Self {
        let root = task::tests::directory();
        let native = root.path().join("native");
        let journal = root.path().join("journal");
        let materials = root.path().join("materials");
        for path in [&journal, &materials] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        if existing_empty_store {
            fs::create_dir(&native).unwrap();
            fs::set_permissions(&native, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut catalog = b"TRNM-RESTRICTED-NODE-CATALOG1".to_vec();
        let mut rows = Vec::new();
        for role in [
            "activation",
            "bootstrap",
            "checkpoint",
            "input",
            "model",
            "spec",
        ] {
            let raw = format!("unqualified-policy-file:{role}").into_bytes();
            let path = materials.join(role);
            fs::write(&path, &raw).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let digest = task::digest_bytes(&raw);
            catalog.extend_from_slice(&(role.len() as u32).to_le_bytes());
            catalog.extend_from_slice(role.as_bytes());
            catalog.extend_from_slice(&(raw.len() as u64).to_le_bytes());
            catalog.extend_from_slice(&(digest.len() as u32).to_le_bytes());
            catalog.extend_from_slice(digest.as_bytes());
            rows.push((role.to_owned(), path, raw.len() as u64, digest));
        }
        Self {
            root,
            native,
            journal,
            rows,
            catalog: task::digest_bytes(&catalog),
        }
    }
    fn materials(&self) -> Vec<MaterialInput> {
        self.rows
            .iter()
            .map(|(role, path, bytes, sha256)| MaterialInput {
                role: role.clone(),
                path: path.clone(),
                bytes: *bytes,
                sha256: sha256.clone(),
            })
            .collect()
    }
    fn bind_materials(&self, declared: &mut task::Task) {
        declared.full_material_catalog = self.catalog.clone();
        declared.model_material = self.rows[4].3.clone();
        declared.input_material = self.rows[3].3.clone();
    }
    fn task_inputs(&self, settings: &Settings) -> task::RestrictedNodeInputs {
        let mut grant = task::tests::body();
        grant.context.network = hex::encode(settings.network());
        grant.context.parameters = hex::encode(settings.parameters());
        grant.context.actual_parent = hex::encode(settings.genesis());
        self.bind_materials(&mut grant.task);
        grant.operation_id =
            task::operator_operation_id(&grant.context, &grant.exact_packet_sha256).unwrap();
        let (raw_policy, authority) = task::tests::signed(grant);
        task::authenticate(&raw_policy, &authority, task::now_ns().unwrap()).unwrap();
        task::RestrictedNodeInputs {
            pool_permissions: Vec::new(),
            raw_policy,
            authority,
            journal_path: self.journal.clone(),
            expected_uid: task::tests::uid(),
            materials: self.materials(),
        }
    }
    fn mining_inputs(&self, settings: &Settings) -> mining::Inputs {
        let mut view = mining::tests::view();
        view.context.network = hex::encode(settings.network());
        view.context.parameters = hex::encode(settings.parameters());
        view.context.actual_parent = hex::encode(settings.genesis());
        self.bind_materials(&mut view.task);
        let allocation = view.permissions[0].allocation.clone();
        view.permissions.clear();
        for (purpose, nonce, payload) in [
            (
                mining::Purpose::StartupCatalog,
                "a1".repeat(32),
                self.catalog.clone(),
            ),
            (
                mining::Purpose::ParentReconcile,
                "a2".repeat(32),
                view.context.actual_parent.clone(),
            ),
        ] {
            view.permissions.push(mining::OperationGrant {
                operation_id: mining::operation_id(&view.context, &purpose, &nonce, &payload)
                    .unwrap(),
                purpose,
                operation_nonce: nonce,
                expected_generation: 0,
                payload_sha256: payload,
                search: None,
                related_search_operation: None,
                allocation: allocation.clone(),
            });
        }
        let (raw_view, authority) = mining::tests::sign(view);
        mining::authenticate(&raw_view, &authority, task::now_ns().unwrap()).unwrap();
        mining::Inputs {
            raw_view,
            authority,
            journal_path: self.journal.clone(),
            expected_uid: task::tests::uid(),
            materials: self.materials(),
        }
    }
}

fn pq_settings() -> Settings {
    let spkis: Vec<_> = [71, 72]
        .into_iter()
        .map(|seed| PqNativeSigningKey::public_spki_from_seed(&Zeroizing::new([seed; 32])))
        .collect();
    let accounts: Vec<_> = spkis
        .iter()
        .map(|spki| GenesisAccount {
            spki: spki.to_vec(),
            balance: 1_000_000_000,
        })
        .collect();
    let settings = Settings::native_pq_application_v6(
        &accounts,
        1,
        &application_v6::ApplicationPolicy {
            evaluators: spkis
                .iter()
                .map(|spki| ml_dsa_65_key_id_from_spki(spki).unwrap())
                .collect::<BTreeSet<_>>(),
            evaluation_profile: trnm_mvcc_fee::public_evaluation::PROFILE.into(),
            model_profile: "linear-expert-dev-v1".into(),
        },
    )
    .unwrap();
    assert!(settings.is_native_pq_application_v6());
    settings
}

type DirectorySnapshot = BTreeMap<PathBuf, (u32, Option<Vec<u8>>)>;
fn snapshot(root: &Path) -> DirectorySnapshot {
    fn walk(root: &Path, path: &Path, result: &mut DirectorySnapshot) {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(!metadata.file_type().is_symlink());
        let bytes = if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), result);
            }
            None
        } else {
            assert!(metadata.is_file());
            Some(fs::read(path).unwrap())
        };
        result.insert(
            path.strip_prefix(root).unwrap().to_path_buf(),
            (metadata.mode(), bytes),
        );
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result);
    result
}

#[test]
fn pq_account_rejects_classical_task_owner_before_any_durable_effect() {
    let settings = pq_settings();
    for existing_empty_store in [false, true] {
        let fixture = CatalogFixture::new(existing_empty_store);
        let inputs = fixture.task_inputs(&settings);
        let before = snapshot(fixture.root.path());
        let error =
            Node::open_with_operator_task_policy(&fixture.native, settings.clone(), 1, inputs)
                .err()
                .expect("a classical policy cannot own a PQ account Node");
        assert_eq!(error.to_string(), "PQ_ACCOUNT_REQUIRES_PQ_NETWORK_OWNER");
        assert_eq!(snapshot(fixture.root.path()), before);
    }
}

#[test]
fn pq_account_rejects_classical_mining_owner_before_any_durable_effect() {
    let settings = pq_settings();
    for existing_empty_store in [false, true] {
        let fixture = CatalogFixture::new(existing_empty_store);
        let inputs = fixture.mining_inputs(&settings);
        let before = snapshot(fixture.root.path());
        let error = Node::open_with_operator_mining_task_view(
            &fixture.native,
            settings.clone(),
            1,
            inputs,
            &ServiceMutationCpuDomain::standalone(),
        )
        .err()
        .expect("a classical mining view cannot own a PQ account Node");
        assert_eq!(error.to_string(), "PQ_ACCOUNT_REQUIRES_PQ_NETWORK_OWNER");
        assert_eq!(snapshot(fixture.root.path()), before);
    }
}

#[test]
fn classical_task_owner_with_signed_catalog_still_opens() {
    let settings = Settings::development(Some(1)).unwrap();
    let fixture = CatalogFixture::new(false);
    let inputs = fixture.task_inputs(&settings);
    let node =
        Node::open_with_operator_task_policy(&fixture.native, settings.clone(), 1, inputs).unwrap();
    assert_eq!(node.active().unwrap(), (settings.genesis(), 0));
    assert!(fixture.native.join("owner-task-policy.required").is_file());
    assert!(fixture
        .journal
        .join("view-00000000000000000001.json")
        .is_file());
}

#[test]
fn classical_mining_owner_with_signed_catalog_still_opens() {
    let settings = Settings::development(Some(1)).unwrap();
    let fixture = CatalogFixture::new(false);
    let inputs = fixture.mining_inputs(&settings);
    let mut node = Node::open_with_operator_mining_task_view(
        &fixture.native,
        settings.clone(),
        1,
        inputs,
        &ServiceMutationCpuDomain::standalone(),
    )
    .unwrap();
    assert_eq!(node.active().unwrap(), (settings.genesis(), 0));
    assert!(
        !node
            .take_mining_startup_cpu()
            .unwrap()
            .accounting_unavailable
    );
    assert_eq!(
        fs::read_dir(&fixture.journal)
            .unwrap()
            .filter(|entry| entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("claim-"))
            .count(),
        2,
    );
    assert!(fixture.native.join("owner-task-policy.required").is_file());
}
