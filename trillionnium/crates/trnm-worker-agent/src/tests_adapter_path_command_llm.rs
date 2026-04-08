use super::*;
#[test]
fn llm_adapter_non_timeout_path_is_ok() {
    let base_args = vec![
        "-c".to_string(),
        "import sys; print(sys.argv[1])".to_string(),
    ];
    let extra_args = vec!["{\"output_text\":\"ok\",\"provider_request_id\":\"r1\"}".to_string()];
    let out = run_command_with_timeout("python3", &base_args, &extra_args, Duration::from_secs(1))
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let parsed: LlmAdapterResponse = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r1"));
}

#[test]
fn llm_adapter_accepts_last_json_line_when_stdout_has_noise() {
    let prompt = "debug: adapter warmup\n{\"output_text\":\"ok\",\"provider_request_id\":\"r1\"}";
    let parsed = run_llm_adapter_once(
        "python3 -c 'import sys; print(sys.argv[1])'",
        prompt,
        Duration::from_secs(1),
        &StandardProofAdapter,
    )
    .unwrap();
    assert_eq!(parsed.output_text, "ok");
    assert_eq!(parsed.provider_request_id.as_deref(), Some("r1"));
}

#[test]
fn llm_adapter_rejects_stdout_without_any_json_line() {
    let err = run_llm_adapter_once(
        "python3 -c 'import sys; print(sys.argv[1])'",
        "debug: adapter warmup\nstatus=ok",
        Duration::from_secs(1),
        &StandardProofAdapter,
    )
    .unwrap_err();
    assert_eq!(err.kind, AdapterErrorKind::NonRetriable);
    assert!(err.context.contains("no-json-line"));
}

#[test]
fn llm_adapter_prompt_shell_chars_are_treated_as_plain_text() {
    let marker = env::temp_dir().join(format!("trnm-worker-agent-shell-marker-{}.tmp", now_ms()));
    let prompt = format!(
        "{{\"output_text\":\"$(touch {})\",\"provider_request_id\":\"r-safe\"}}",
        marker.display()
    );

    let parsed = run_llm_adapter_once(
        "python3 -c 'import sys; print(sys.argv[1])'",
        &prompt,
        Duration::from_secs(1),
        &StandardProofAdapter,
    )
    .expect("payload should parse without shell evaluation");
    assert_eq!(parsed.output_text, format!("$(touch {})", marker.display()));
    assert!(
        fs::metadata(&marker).is_err(),
        "prompt shell metacharacters must never execute"
    );
}
