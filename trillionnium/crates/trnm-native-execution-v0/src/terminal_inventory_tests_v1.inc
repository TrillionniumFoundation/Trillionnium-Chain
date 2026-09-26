#[test]
fn ordinary_terminal_inventory_detects_genuine_prepared_append_without_head_change_v1() {
    let temporary = TempDir::new().unwrap();
    let (path, application, head, request) = initialized(&temporary);
    let before = fs::read(&path).unwrap();
    let initial = application
        .confirm_ordinary_terminal_inventory_v1()
        .unwrap();
    assert_eq!(initial.head_v1(), &head);
    assert_eq!(initial.prepared_count_v1(), 0);
    assert!(initial.belongs_to_application_at_path_v1(&application, &path));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(matches!(
        application.execute_block(request).unwrap(),
        NativeBlockExecutionResultV0::Valid(_)
    ));
    let prepared_bytes = fs::read(&path).unwrap();
    let appended = application
        .confirm_ordinary_terminal_inventory_v1()
        .unwrap();
    assert_eq!(appended.head_v1(), initial.head_v1());
    assert_eq!(appended.prepared_count_v1(), 1);
    assert_eq!(
        appended.durable_sequence_v1(),
        initial.durable_sequence_v1() + 1
    );
    assert_eq!(fs::read(&path).unwrap(), prepared_bytes);
    // A fresh owner at the same persisted path cannot adopt the old affinity.
    drop(application);
    let reopened = DurableNativeApplicationV0::open(&path, config(STORE_A)).unwrap();
    assert!(!appended.belongs_to_application_at_path_v1(&reopened, &path));
    let cold = reopened.confirm_ordinary_terminal_inventory_v1().unwrap();
    assert_eq!(cold.head_v1(), appended.head_v1());
    assert_eq!(cold.durable_sequence_v1(), appended.durable_sequence_v1());
    assert_eq!(cold.prepared_count_v1(), 1);
}
