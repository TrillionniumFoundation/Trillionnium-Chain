use anyhow::Result;
use std::{
    process::{Command as ProcCommand, Output, Stdio},
    time::Duration,
};
use wait_timeout::ChildExt;

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
