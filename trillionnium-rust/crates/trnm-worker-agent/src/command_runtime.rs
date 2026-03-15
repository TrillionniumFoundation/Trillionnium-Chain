use anyhow::{anyhow, Result};
use std::{
    path::Path,
    process::{Command as ProcCommand, Output, Stdio},
    time::Duration,
};
use wait_timeout::ChildExt;

pub(crate) fn is_forbidden_shell_program(program: &str) -> bool {
    let leaf = Path::new(program)
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or(program)
        .to_ascii_lowercase();
    matches!(
        leaf.as_str(),
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "csh"
            | "tcsh"
            | "fish"
            | "cmd"
            | "powershell"
            | "pwsh"
    )
}

pub(crate) fn parse_command_spec(spec: &str) -> Result<(String, Vec<String>)> {
    let tokens = shlex::split(spec).ok_or_else(|| anyhow!("invalid command spec quoting"))?;
    if tokens.is_empty() {
        anyhow::bail!("empty command spec");
    }
    let program = tokens[0].clone();
    if is_forbidden_shell_program(&program) {
        anyhow::bail!("shell interpreter is forbidden in adapter command spec");
    }
    let args = tokens[1..].to_vec();
    Ok((program, args))
}

pub(crate) fn run_command_with_timeout(
    program: &str,
    base_args: &[String],
    extra_args: &[String],
    timeout: Duration,
) -> Result<Output> {
    let mut child = ProcCommand::new(program)
        .args(base_args)
        .args(extra_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    match child.wait_timeout(timeout)? {
        Some(_) => Ok(child.wait_with_output()?),
        None => {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("llm adapter timeout after {}ms", timeout.as_millis());
        }
    }
}
