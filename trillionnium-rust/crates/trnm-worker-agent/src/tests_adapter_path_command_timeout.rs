use super::*;
#[test]
fn llm_adapter_timeout_triggers() {
    let base_args = vec![
        "-lc".to_string(),
        "sleep 0.2; echo '{\"output_text\":\"late\"}'".to_string(),
    ];
    let err =
        run_command_with_timeout("sh", &base_args, &[], Duration::from_millis(30)).unwrap_err();
    assert!(err.to_string().contains("timeout"));
}
