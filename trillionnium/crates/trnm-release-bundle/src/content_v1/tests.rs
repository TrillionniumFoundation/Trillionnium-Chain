use super::*;
use crate::Digest32V0;
use trnm_protocol::crypto_profile::{CryptoProfile, ProfileBinding, ProfileScope};

fn context() -> ContentContextV1 {
    let profile = CryptoProfile::CandidateMlDsa65V1
        .bind(ProfileBinding {
            network: [1; 32],
            parameters: [2; 32],
            genesis: [3; 32],
            protocol_version: 1,
            scope: ProfileScope::WholeSystemCandidate,
            activation_height: 0,
            retirement_height: None,
        })
        .unwrap();
    ContentContextV1::new(&profile, ContentKind::ReleaseArtifact, [7; 64], 1).unwrap()
}
fn artifact(bytes: &[u8]) -> ArtifactEntryV0 {
    ArtifactEntryV0 {
        logical_name: b"node".to_vec(),
        media_type: b"application/octet-stream".to_vec(),
        size_bytes: bytes.len() as u64,
        content_digest: Digest32V0(Sha256::digest(bytes).into()),
        executable: true,
        platform_digest: Digest32V0([1; 32]),
        source_path_digest: Digest32V0([2; 32]),
    }
}
fn budget() -> ContentReadBudget {
    ContentReadBudget::new(100, 1_000_000).unwrap()
}

#[test]
fn complete_artifact_and_all_metadata_enter_the_strong_commitment() {
    let bytes = b"real executable content";
    let a = artifact(bytes);
    let original =
        observe_release_artifact_v1(&context(), &mut budget(), &a, &mut Cursor::new(bytes))
            .unwrap();
    verify_release_artifact_v1(original.claim(), &mut budget(), &a, &mut Cursor::new(bytes))
        .unwrap();
    let mut changes = vec![a.clone(); 5];
    changes[0].logical_name.push(b'2');
    changes[1].media_type.push(b'2');
    changes[2].executable = false;
    changes[3].platform_digest.0[0] ^= 1;
    changes[4].source_path_digest.0[0] ^= 1;
    for changed in changes {
        assert!(verify_release_artifact_v1(
            original.claim(),
            &mut budget(),
            &changed,
            &mut Cursor::new(bytes)
        )
        .is_err());
    }
    let other = b"fake executable content";
    let replacement = artifact(other); // An internally consistent new legacy locator still fails.
    assert!(verify_release_artifact_v1(
        original.claim(),
        &mut budget(),
        &replacement,
        &mut Cursor::new(other)
    )
    .is_err());
}

#[test]
fn short_long_wrong_locator_and_old_digest_wrapper_are_refused() {
    let bytes = [3u8; 32];
    let a = artifact(&bytes);
    for supplied in [
        bytes[..31].to_vec(),
        vec![3; 33],
        a.content_digest.0.to_vec(),
    ] {
        assert!(observe_release_artifact_v1(
            &context(),
            &mut budget(),
            &a,
            &mut Cursor::new(supplied)
        )
        .is_err());
    }
    let mut wrong = a;
    wrong.content_digest.0[0] ^= 1;
    assert!(matches!(
        observe_release_artifact_v1(&context(), &mut budget(), &wrong, &mut Cursor::new(bytes)),
        Err(ReleaseContentError::LegacyLocatorMismatch)
    ));
}

#[test]
#[cfg(unix)]
fn retained_file_reads_exact_bytes_and_refuses_partial_offset() {
    use std::io::{Seek, SeekFrom};
    let path = std::env::temp_dir().join(format!("trnm-cch1-release-{}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let bytes = b"candidate artifact on a real descriptor";
    std::io::Write::write_all(&mut file, bytes).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    let a = artifact(bytes);
    let observed = observe_release_file_v1(&context(), &mut budget(), &a, &mut file).unwrap();
    let expected =
        observe_release_artifact_v1(&context(), &mut budget(), &a, &mut Cursor::new(bytes))
            .unwrap();
    expected.claim().verify(&observed).unwrap();
    assert!(matches!(
        observe_release_file_v1(&context(), &mut budget(), &a, &mut file),
        Err(ReleaseContentError::FileIdentity)
    ));
    std::fs::remove_file(path).unwrap();
}
