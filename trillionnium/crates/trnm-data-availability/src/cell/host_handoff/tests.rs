use std::{io::Read, sync::atomic::AtomicBool, time::Duration};

use sha2::Sha256;
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

use super::*;
use crate::cell::{
    pq::{
        CellPqContentAuthorizationV4, CellPqContentStatementV4, CellPqKeyPinV2,
        CellPqReleaseExpectationV2,
    },
    version::tests::owner,
    version_content::tests::{captured, session},
    CellResidencyConfigV1, CellResidencyV1, CellSealedLoaderLimitsV1, CellVersionContentV2,
    CellVersionLoaderContextV1,
};

fn descriptor(content: &CellVersionContentV2) -> CellHostHandoffDescriptorV1 {
    let version = content.version();
    let mut worker_context = version.model().closure().release().context().clone();
    // Opaque unit fixture data; this does not pretend to run a Python worker.
    let worker = &version.environment().files()[0];
    let snapshot = &version.environment().files()[1];
    worker_context.runtime = worker.payload_sha256;
    CellHostHandoffDescriptorV1 {
        operation: [77; 32],
        owner_generation: 99,
        content: content.commitment(),
        version: version.commitment(),
        model_closure: version.model().closure().id(),
        environment_closure: version.environment().id(),
        model_generation: version.model().closure().selected_generation(),
        environment_generation: version.environment().selected_generation(),
        worker_context,
        worker_path: worker.path.clone(),
        runtime_snapshot_path: snapshot.path.clone(),
        runtime_snapshot_sha256: snapshot.payload_sha256,
    }
}

fn key() -> (PqNativeSigningKey, CellPqKeyPinV2) {
    let seed = Zeroizing::new([94; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    let key_id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
    (
        PqNativeSigningKey::from_owned_seed(seed, key_id).unwrap(),
        CellPqKeyPinV2 {
            key_id,
            generation: 2,
            spki,
            not_before: 100,
            expires_at: 1000,
            revoked_at: None,
        },
    )
}

#[test]
fn host_handoff_chb1_keeps_both_contexts_and_rejects_old_wire_aliases() {
    // Independent Python struct/hashlib frame with both runtime domains kept
    // explicit; content digests here are metadata vector inputs only.
    let vector = CellHostHandoffDescriptorV1 {
        operation: [6; 32],
        owner_generation: 9,
        content: [7; 64],
        version: [8; 64],
        model_closure: [9; 32],
        environment_closure: [10; 32],
        model_generation: 2,
        environment_generation: 1,
        worker_context: CellContextV1 {
            family: "host-handoff-vector-v1".into(),
            base: [1; 32],
            parent: [2; 32],
            tokenizer: [3; 32],
            layout: [4; 32],
            runtime: [5; 32],
        },
        worker_path: "worker.py".into(),
        runtime_snapshot_path: "runtime.json".into(),
        runtime_snapshot_sha256: [11; 32],
    };
    assert_eq!(vector.encode().unwrap().len(), 492);
    assert_eq!(hex::encode(vector.commitment().unwrap()), "2de70ca8e4b01971ec058bc7449c8c63f7a05bd49e829524cb5cf0d381c74d08e0b0863c11c673c5bc7e0efac3d049ad54cd947d400fb77490fc22e9428df4cc");
    let (_dir, _store, content) = captured();
    let value = descriptor(&content);
    let wire = value.encode().unwrap();
    assert_eq!(
        CellHostHandoffDescriptorV1::decode_pinned(&wire, value.commitment().unwrap()).unwrap(),
        value
    );
    assert_ne!(value.worker_context.runtime, value.environment_closure);
    assert_ne!(value.model_generation, value.environment_generation);
    assert!(CellHostHandoffDescriptorV1::decode_pinned(&wire, [9; 64]).is_err());
    for magic in [*b"TCV1", *b"TCV2", *b"CPV4", *b"TCR1"] {
        let mut changed = wire.clone();
        changed[..4].copy_from_slice(&magic);
        assert!(
            CellHostHandoffDescriptorV1::decode_pinned(&changed, descriptor_id(&changed)).is_err()
        );
    }
    let mut trailing = wire;
    trailing.push(0);
    assert!(
        CellHostHandoffDescriptorV1::decode_pinned(&trailing, descriptor_id(&trailing)).is_err()
    );
    for path in [
        "../worker.py",
        "/worker.py",
        "a//worker.py",
        "a/./worker.py",
    ] {
        let mut changed = value.clone();
        changed.worker_path = path.into();
        assert!(changed.encode().is_err());
    }
    let mut changed = value;
    changed.runtime_snapshot_path = changed.worker_path.clone();
    assert!(changed.encode().is_err());
}

#[test]
fn host_handoff_cpv4_and_both_real_sealed_scopes_are_required_for_exact_fd_data() {
    let (_dir, store, content) = captured();
    let (signer, pin) = key();
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    let mut current = CellPqContentExpectationV4 {
        authority: CellPqReleaseExpectationV2 {
            network: [6; 32],
            parameters: [7; 32],
            key: &pin,
            sequence: 4,
            now: 300,
        },
        loader: CellVersionLoaderContextV1 {
            commitment: content.version().commitment(),
            model: &model,
            environment: &environment,
        },
        content: content.commitment(),
    };
    let signed = CellPqContentAuthorizationV4::sign(
        CellPqContentStatementV4 {
            network: [6; 32],
            parameters: [7; 32],
            content: content.commitment(),
            signer_key_id: pin.key_id,
            signer_spki_sha512: CellPqContentStatementV4::signer_commitment(&pin.spki),
            generation: 2,
            sequence: 4,
            issued_at: 200,
            expires_at: 900,
            withdrawn: false,
        },
        &signer,
    )
    .unwrap();
    let authorization = signed
        .verify_cached_at(&content, &store, &current, &mut session(1))
        .unwrap();
    let end = Instant::now() + Duration::from_secs(15);
    let cancelled = AtomicBool::new(false);
    let mut pool = CellResidencyV1::new(CellResidencyConfigV1 {
        max_resident_bytes: 4 * 32769,
        max_resident_closures: 2,
        max_chunk_references: 12,
    })
    .unwrap();
    pool.prepare_cached(
        &store,
        content.version().model().closure(),
        &model,
        end,
        &cancelled,
    )
    .unwrap();
    pool.prepare_cached(
        &store,
        content.version().environment(),
        &environment,
        end,
        &cancelled,
    )
    .unwrap();
    let limits = CellSealedLoaderLimitsV1 {
        max_snapshot_bytes: 2 * 32769,
        max_files: 2,
    };
    let model_bundle = pool
        .seal_declared_loader(&model, limits, end, &cancelled)
        .unwrap();
    let environment_bundle = pool
        .seal_declared_loader(&environment, limits, end, &cancelled)
        .unwrap();
    let value = descriptor(&content);
    let independent = value.commitment().unwrap();
    let result = value
        .bind_authenticated(
            independent,
            &authorization,
            &current,
            (&model_bundle, &environment_bundle),
            end,
        )
        .unwrap();
    let mut worker = Vec::new();
    result
        .worker_source()
        .unwrap()
        .read_to_end(&mut worker)
        .unwrap();
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&worker)),
        value.worker_context.runtime
    );
    let mut snapshot = Vec::new();
    result
        .runtime_snapshot()
        .unwrap()
        .read_to_end(&mut snapshot)
        .unwrap();
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&snapshot)),
        value.runtime_snapshot_sha256
    );
    let mut model_bytes = Vec::new();
    result
        .model_file("base.bin", CellFileRoleV1::Base)
        .unwrap()
        .read_to_end(&mut model_bytes)
        .unwrap();
    assert_eq!(model_bytes.len(), 32769);
    assert_eq!(model.context.runtime, value.environment_closure);
    assert_ne!(
        model.context.runtime,
        result.descriptor().worker_context.runtime
    );
    assert_eq!(result.descriptor().owner_generation, 99);
    assert!(result
        .model_file("base.bin", CellFileRoleV1::Configuration)
        .is_err());
    assert!(result
        .model_file("../base.bin", CellFileRoleV1::Base)
        .is_err());
    assert!(value
        .bind_authenticated(
            independent,
            &authorization,
            &current,
            (&model_bundle, &model_bundle),
            end
        )
        .is_err());
    assert!(value
        .bind_authenticated(
            independent,
            &authorization,
            &current,
            (&environment_bundle, &model_bundle),
            end
        )
        .is_err());
    assert!(value
        .bind_authenticated(
            independent,
            &authorization,
            &current,
            (&model_bundle, &environment_bundle),
            Instant::now() - Duration::from_secs(1)
        )
        .is_err());
    let mut changed = value.clone();
    changed.worker_context.runtime = value.environment_closure;
    assert!(changed
        .bind_authenticated(
            changed.commitment().unwrap(),
            &authorization,
            &current,
            (&model_bundle, &environment_bundle),
            end
        )
        .is_err());
    changed = value.clone();
    changed.runtime_snapshot_sha256[0] ^= 1;
    assert!(changed
        .bind_authenticated(
            changed.commitment().unwrap(),
            &authorization,
            &current,
            (&model_bundle, &environment_bundle),
            end
        )
        .is_err());
    changed = value.clone();
    changed.environment_generation = changed.model_generation;
    assert!(changed
        .bind_authenticated(
            changed.commitment().unwrap(),
            &authorization,
            &current,
            (&model_bundle, &environment_bundle),
            end
        )
        .is_err());
    current.authority.sequence += 1;
    assert!(value
        .bind_authenticated(
            independent,
            &authorization,
            &current,
            (&model_bundle, &environment_bundle),
            end
        )
        .is_err());
    current.authority.sequence -= 1;
    current.authority.now = 900;
    assert!(value
        .bind_authenticated(
            independent,
            &authorization,
            &current,
            (&model_bundle, &environment_bundle),
            end
        )
        .is_err());
}

#[path = "tests/research_fds.rs"]
mod research_fds;
