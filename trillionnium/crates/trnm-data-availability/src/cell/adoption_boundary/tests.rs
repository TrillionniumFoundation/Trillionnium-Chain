use super::*;
use crate::cell::{
    version::tests::fixture, CellChunkV1, CellContextV1, CellModelReleaseRootV1,
    CellReleaseClosureV1, CellStoreV1,
};
use sha2::Sha256;

pub(crate) fn execution() -> CellExecutionBoundaryV1 {
    CellExecutionBoundaryV1 {
        network: [31; 32],
        consensus: [32; 32],
        fees: [33; 32],
        root_authority: [34; 32],
        node_software: [35; 32],
        protocol_configuration: [36; 32],
    }
}

pub(crate) fn boundary(anchor: &CellVersionManifestV1) -> CellModelUpdateBoundaryV1 {
    CellModelUpdateBoundaryV1::new(
        anchor,
        vec![CellFileRoleV1::Base],
        execution(),
        1_000_000,
        64,
    )
    .unwrap()
}

/// Produce real cache bytes and complete TCV1 ancestry. Frozen tokenizer
/// payloads keep their bytes even though parent-bound manifest locators change.
pub(crate) fn successor(
    store: &CellStoreV1,
    parent: &CellVersionManifestV1,
    seed: u8,
) -> CellVersionManifestV1 {
    rewrite(store, parent, CellFileRoleV1::Base, seed, |_| {})
}

fn rewrite(
    store: &CellStoreV1,
    parent: &CellVersionManifestV1,
    changed: CellFileRoleV1,
    seed: u8,
    change_context: impl FnOnce(&mut CellContextV1),
) -> CellVersionManifestV1 {
    let old = parent.model().closure();
    let mut context = old.release().context().clone();
    context.parent = parent.model().id();
    change_context(&mut context);
    let mut files = old.files().to_vec();
    let mut manifests: Vec<_> = parent
        .manifests()
        .iter()
        .filter(|m| parent.environment().release().cells().contains(&m.id()))
        .cloned()
        .collect();
    for file in &mut files {
        let old_manifest = manifest(parent, file.manifest).unwrap();
        let new_manifest = if file.role == changed {
            let bytes = vec![seed; 32769];
            let chunks: Vec<_> = bytes
                .chunks(16384)
                .map(|part| CellChunkV1 {
                    size: part.len() as u32,
                    sha256: Sha256::digest(part).into(),
                })
                .collect();
            for (chunk, data) in chunks.iter().zip(bytes.chunks(16384)) {
                store.put_chunk(chunk, data).unwrap();
            }
            CellManifestV1::new(
                context.clone(),
                bytes.len() as u64,
                Sha256::digest(&bytes).into(),
                16384,
                chunks,
            )
            .unwrap()
        } else {
            CellManifestV1::new(
                context.clone(),
                old_manifest.size(),
                old_manifest.payload_sha256(),
                old_manifest.chunk_bytes(),
                old_manifest.chunks().to_vec(),
            )
            .unwrap()
        };
        store
            .put_manifest(new_manifest.id(), &new_manifest.encode())
            .unwrap();
        file.manifest = new_manifest.id();
        file.payload_sha256 = new_manifest.payload_sha256();
        file.payload_bytes = new_manifest.size();
        manifests.push(new_manifest);
    }
    let closure = CellReleaseClosureV1::new(
        context,
        old.selected_generation() + 1,
        old.loader_profile(),
        old.roots().to_vec(),
        files,
    )
    .unwrap();
    manifests.sort_by_key(CellManifestV1::id);
    CellVersionManifestV1::new(
        CellModelReleaseRootV1::new(closure, vec![parent.model().id()]).unwrap(),
        parent.environment().clone(),
        manifests,
    )
    .unwrap()
}

#[test]
fn permitted_weights_change_without_changing_frozen_tokenizer_or_environment() {
    let (_directory, store, anchor) = fixture();
    let policy = boundary(&anchor);
    let candidate = successor(&store, &anchor, 81);
    policy.verify_version(&anchor).unwrap();
    policy.verify_version(&candidate).unwrap();
    candidate
        .model()
        .verify_parent_roots(&[anchor.model().clone()])
        .unwrap();
    assert_ne!(candidate.commitment(), anchor.commitment());
    assert_ne!(candidate.model().id(), anchor.model().id());
    assert_eq!(candidate.environment(), anchor.environment());
    assert_ne!(
        candidate.model().closure().files()[1].manifest,
        anchor.model().closure().files()[1].manifest
    );
    assert_eq!(
        candidate.model().closure().files()[1].payload_sha256,
        anchor.model().closure().files()[1].payload_sha256
    );
}

#[test]
fn candidate_cannot_replace_frozen_tokenizer_or_model_interface() {
    let (_directory, store, anchor) = fixture();
    let policy = boundary(&anchor);
    let tokenizer = rewrite(&store, &anchor, CellFileRoleV1::Tokenizer, 82, |_| {});
    assert!(policy.verify_version(&tokenizer).is_err());
    for field in 0..3 {
        let changed = rewrite(
            &store,
            &anchor,
            CellFileRoleV1::Base,
            83,
            |context| match field {
                0 => context.base = [71; 32],
                1 => context.tokenizer = [72; 32],
                _ => context.layout = [73; 32],
            },
        );
        assert!(policy.verify_version(&changed).is_err());
    }
}

#[test]
fn a_consistent_complete_version_still_cannot_replace_the_environment() {
    let (_directory, _store, anchor) = fixture();
    let original_environment = anchor.environment();
    let environment = CellReleaseClosureV1::new(
        original_environment.release().context().clone(),
        original_environment.selected_generation() + 1,
        original_environment.loader_profile(),
        original_environment.roots().to_vec(),
        original_environment.files().to_vec(),
    )
    .unwrap();
    let original_model = anchor.model().closure();
    let mut context = original_model.release().context().clone();
    context.runtime = environment.id();
    let mut files = original_model.files().to_vec();
    let mut manifests: Vec<_> = anchor
        .manifests()
        .iter()
        .filter(|m| environment.release().cells().contains(&m.id()))
        .cloned()
        .collect();
    for file in &mut files {
        let old = manifest(&anchor, file.manifest).unwrap();
        let new = CellManifestV1::new(
            context.clone(),
            old.size(),
            old.payload_sha256(),
            old.chunk_bytes(),
            old.chunks().to_vec(),
        )
        .unwrap();
        file.manifest = new.id();
        manifests.push(new);
    }
    manifests.sort_by_key(CellManifestV1::id);
    let closure = CellReleaseClosureV1::new(
        context,
        original_model.selected_generation(),
        original_model.loader_profile(),
        original_model.roots().to_vec(),
        files,
    )
    .unwrap();
    let changed = CellVersionManifestV1::new(
        CellModelReleaseRootV1::new(closure, vec![]).unwrap(),
        environment,
        manifests,
    )
    .unwrap();
    changed.validate().unwrap();
    assert!(boundary(&anchor).verify_version(&changed).is_err());
}

#[test]
fn candidate_cannot_change_loader_file_roles_paths_or_dependency_graph() {
    let (_directory, _store, anchor) = fixture();
    let policy = boundary(&anchor);
    for change in 0..4 {
        let original = anchor.model().closure();
        let mut files = original.files().to_vec();
        let mut roots = original.roots().to_vec();
        let mut loader = original.loader_profile();
        match change {
            0 => loader = [75; 32],
            1 => files[0].path = "base-renamed.bin".into(),
            2 => files[0].role = CellFileRoleV1::Adapter,
            _ => {
                files[0].dependencies.clear();
                roots = vec![0, 1];
            }
        }
        let closure = CellReleaseClosureV1::new(
            original.release().context().clone(),
            original.selected_generation(),
            loader,
            roots,
            files,
        )
        .unwrap();
        let candidate = CellVersionManifestV1::new(
            CellModelReleaseRootV1::new(closure, vec![]).unwrap(),
            anchor.environment().clone(),
            anchor.manifests().to_vec(),
        )
        .unwrap();
        assert!(policy.verify_version(&candidate).is_err());
    }
}

#[test]
fn model_policy_cannot_allow_configuration_or_unbounded_payloads() {
    let (_directory, _store, anchor) = fixture();
    for roles in [
        vec![CellFileRoleV1::Configuration],
        vec![CellFileRoleV1::Tokenizer],
        vec![CellFileRoleV1::Preprocessor],
        vec![CellFileRoleV1::Base, CellFileRoleV1::Base],
        vec![CellFileRoleV1::Router, CellFileRoleV1::Adapter],
    ] {
        assert!(
            CellModelUpdateBoundaryV1::new(&anchor, roles, execution(), 1_000_000, 64).is_err()
        );
    }
    for (bytes, chunks) in [(0, 64), (1, 64), (1_000_000, 0), (1_000_000, 1)] {
        assert!(CellModelUpdateBoundaryV1::new(
            &anchor,
            vec![CellFileRoleV1::Base],
            execution(),
            bytes,
            chunks,
        )
        .is_err());
    }
}

#[test]
fn each_protected_execution_identity_is_rechecked_independently() {
    let (_directory, _store, anchor) = fixture();
    let policy = boundary(&anchor);
    policy.verify_execution(&execution()).unwrap();
    for field in 0..6 {
        let mut changed = execution();
        let pin = match field {
            0 => &mut changed.network,
            1 => &mut changed.consensus,
            2 => &mut changed.fees,
            3 => &mut changed.root_authority,
            4 => &mut changed.node_software,
            _ => &mut changed.protocol_configuration,
        };
        pin[0] ^= 1;
        assert!(policy.verify_execution(&changed).is_err());
        let alternative = CellModelUpdateBoundaryV1::new(
            &anchor,
            vec![CellFileRoleV1::Base],
            changed,
            1_000_000,
            64,
        )
        .unwrap();
        assert_ne!(policy.digest(), alternative.digest());
    }
}
