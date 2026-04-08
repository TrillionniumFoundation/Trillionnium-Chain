use super::*;
#[test]
fn parse_command_spec_rejects_invalid_quote() {
    let err = parse_command_spec("python3 -c 'print(1)").expect_err("unbalanced quote must fail");
    assert!(err.to_string().contains("invalid command spec quoting"));
}

#[test]
fn parse_command_spec_rejects_shell_interpreter_programs() {
    for spec in [
        "sh -c 'echo pwn'",
        "/bin/bash -lc 'echo pwn'",
        "pwsh -c echo",
    ] {
        let err = parse_command_spec(spec).expect_err("shell program must be rejected");
        assert!(
            err.to_string()
                .contains("shell interpreter is forbidden in adapter command spec"),
            "unexpected error for {spec}: {err}"
        );
    }
}

#[test]
fn parse_command_spec_accepts_non_shell_binary() {
    let (program, args) =
        parse_command_spec("python3 -c 'print(1)'").expect("python must be accepted");
    assert_eq!(program, "python3");
    assert_eq!(args, vec!["-c".to_string(), "print(1)".to_string()]);
}
