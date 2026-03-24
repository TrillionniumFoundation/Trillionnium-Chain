use crate::{is_deterministic_rejection, parse_tx_hash, AdapterExecResult, RC_OK};
use anyhow::{anyhow, Result};
use std::{
    path::Path,
    process::{Command as ProcCommand, Output, Stdio},
    thread,
    time::Duration,
};
use wait_timeout::ChildExt;

use crate::llm_retry::backoff_delay_ms;

fn is_forbidden_shell_program(program: &str) -> bool {
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

pub(crate) fn run_adapter_with_retry(
    adapter_cmd: &str,
    action_args: &[String],
    max_retries: u32,
    backoff_ms: u64,
) -> Result<AdapterExecResult> {
    let (program, base_args) = parse_command_spec(adapter_cmd)?;
    let mut last_rc = 1;
    let mut last_tx_hash: Option<String> = None;

    for attempt in 0..=max_retries {
        let out = ProcCommand::new(&program)
            .args(&base_args)
            .args(action_args)
            .output()?;
        let rc = out.status.code().unwrap_or(1);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tx_hash = parse_tx_hash(&stdout).or_else(|| parse_tx_hash(&stderr));

        if out.status.success() {
            return Ok(AdapterExecResult {
                ok: true,
                rc: RC_OK,
                tx_hash,
                terminal: true,
            });
        }

        last_rc = rc;
        if tx_hash.is_some() {
            last_tx_hash = tx_hash;
        }

        if is_deterministic_rejection(rc) {
            return Ok(AdapterExecResult {
                ok: false,
                rc,
                tx_hash: last_tx_hash,
                terminal: true,
            });
        }

        if attempt < max_retries {
            thread::sleep(Duration::from_millis(backoff_delay_ms(backoff_ms, attempt)));
        }
    }

    Ok(AdapterExecResult {
        ok: false,
        rc: last_rc,
        tx_hash: last_tx_hash,
        terminal: false,
    })
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
