use super::*;

#[test]
fn unsupported_directory_profile_returns_typed_error_without_touching_a_path() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("must-not-be-created.sqlite");
    let context = CellDiscoveryContextV1 {
        namespace: [1; 32],
        network: [2; 32],
        parameters: [3; 32],
        genesis: [4; 32],
    };
    assert!(matches!(
        CellProviderDirectoryV1::open(&path, context),
        Err(CellErrorV1::Invalid("discovery file identity unsupported"))
    ));
    assert!(!path.exists());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}
