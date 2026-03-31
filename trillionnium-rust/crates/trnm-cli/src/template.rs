use super::*;

pub(crate) fn parse_template_command(cmd: &str) -> Result<(String, Vec<String>)> {
    let parts = shell_words::split(cmd)
        .map_err(|e| anyhow!("invalid template command (shell-words parse failed): {e}"))?;
    let Some((program, args)) = parts.split_first() else {
        bail!("template command must not be empty");
    };
    Ok((program.clone(), args.to_vec()))
}

pub(crate) fn run_template(cmd: &str) -> Result<String> {
    let (program, args) = parse_template_command(cmd)?;
    let out = ProcCommand::new(&program).args(&args).output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let merged = format!("{}\n{}", stdout, stderr);

    if !out.status.success() {
        bail!(
            "tx command failed rc={}: {}",
            out.status.code().unwrap_or(1),
            merged
        );
    }

    if let Some(txh) = extract_tx_hash(&merged) {
        return Ok(txh);
    }

    Ok(format!("0x{}", hash(&["fallback", &merged])))
}

pub(crate) fn run_template_raw(cmd: &str) -> Result<String> {
    let (program, args) = parse_template_command(cmd)?;
    let out = ProcCommand::new(&program).args(&args).output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        bail!(
            "query command failed rc={}: {}{}",
            out.status.code().unwrap_or(1),
            stdout,
            stderr
        );
    }

    let mut merged = stdout.to_string();
    merged.push_str(&stderr);
    Ok(merged)
}

pub(crate) fn tpl(mut s: String, key: &str, val: &str) -> String {
    s = s.replace(&format!("{{{}}}", key), val);
    s
}
