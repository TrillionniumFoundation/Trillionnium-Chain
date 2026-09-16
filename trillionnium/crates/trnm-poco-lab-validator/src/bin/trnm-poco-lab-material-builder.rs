#![forbid(unsafe_code)]

use std::{env, path::PathBuf};

use anyhow::{bail, Context, Result};
use trnm_poco_lab_validator::{
    bootstrap_material::build_public_native_bootstrap_v1,
    workload_corpus::{build_public_workload_corpus_range_v1, MAX_WORKLOAD_HEIGHT_V1},
};

fn usage() -> &'static str {
    "usage:\n  trnm-poco-lab-material-builder workload-corpus <chain-id> <ordinary-start-height> <max-height> <absolute-corpus-output> <absolute-policy-output>\n  trnm-poco-lab-material-builder native-only-bootstrap <absolute-validator-set-template> <absolute-workload-corpus> <workload-corpus-sha256> <absolute-workload-policy> <workload-policy-sha256> <absolute-consensus-secret-directory> <absolute-validator-set-output> <absolute-bootstrap-output-directory>"
}

fn parse_height(value: Option<std::ffi::OsString>, field: &str) -> Result<u64> {
    let value = value
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| anyhow::anyhow!(usage()))?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("{field} must be canonical positive decimal");
    }
    let parsed = value
        .parse::<u64>()
        .with_context(|| format!("parse {field}"))?;
    if parsed == 0 || parsed > MAX_WORKLOAD_HEIGHT_V1 {
        bail!("{field} is outside the bounded campaign range");
    }
    Ok(parsed)
}

fn main() -> Result<()> {
    let mut arguments = env::args_os().skip(1);
    let command = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| anyhow::anyhow!(usage()))?;
    match command.as_str() {
        "native-client-profile" => build_native_profile(arguments),
        "native-client-bootstrap" => build_native_client_bootstrap(arguments),
        "workload-corpus" => build_workload(arguments),
        "native-only-bootstrap" => build_bootstrap(arguments),
        _ => bail!(usage()),
    }
}

fn build_workload(mut arguments: impl Iterator<Item = std::ffi::OsString>) -> Result<()> {
    let chain_id = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| anyhow::anyhow!(usage()))?;
    let ordinary_start_height = parse_height(arguments.next(), "ordinary-start-height")?;
    let max_height = parse_height(arguments.next(), "max-height")?;
    if ordinary_start_height > max_height {
        bail!("ordinary-start-height exceeds max-height");
    }
    let corpus_output = PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
    let policy_output = PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
    if arguments.next().is_some() {
        bail!(usage());
    }
    let summary = build_public_workload_corpus_range_v1(
        &chain_id,
        ordinary_start_height,
        max_height,
        corpus_output,
        policy_output,
    )?;
    println!("{}", serde_json::to_string(&summary)?);
    Ok(())
}

fn build_bootstrap(mut arguments: impl Iterator<Item = std::ffi::OsString>) -> Result<()> {
    let validator_set_template =
        PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
    let workload_corpus = PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
    let workload_corpus_sha256 = parse_hash(arguments.next(), "workload-corpus-sha256")?;
    let workload_policy = PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
    let workload_policy_sha256 = parse_hash(arguments.next(), "workload-policy-sha256")?;
    let consensus_secret_directory =
        PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
    let validator_set_output =
        PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
    let bootstrap_output_directory =
        PathBuf::from(arguments.next().ok_or_else(|| anyhow::anyhow!(usage()))?);
    if arguments.next().is_some() {
        bail!(usage());
    }
    let summary = build_public_native_bootstrap_v1(
        validator_set_template,
        workload_corpus,
        workload_corpus_sha256,
        workload_policy,
        workload_policy_sha256,
        consensus_secret_directory,
        validator_set_output,
        bootstrap_output_directory,
    )?;
    println!("{}", serde_json::to_string(&summary)?);
    Ok(())
}

fn parse_hash(value: Option<std::ffi::OsString>, field: &str) -> Result<[u8; 32]> {
    let value = value
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| anyhow::anyhow!(usage()))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{field} must be canonical lowercase 32-byte hex");
    }
    let bytes = hex::decode(value).with_context(|| format!("decode {field}"))?;
    Ok(bytes
        .try_into()
        .expect("64 hex characters decode to exactly 32 bytes"))
}

fn build_native_profile(mut arguments: impl Iterator<Item = std::ffi::OsString>) -> Result<()> {
    let chain = arguments
        .next()
        .and_then(|s| s.into_string().ok())
        .context("native-client-profile requires chain ID")?;
    let directory = PathBuf::from(
        arguments
            .next()
            .context("native-client-profile requires fresh absolute isolated key directory")?,
    );
    if arguments.next().is_some() {
        bail!("unexpected native profile argument");
    }
    let profile =
        trnm_poco_lab_validator::native_client_profile::generate_isolated_native_client_profile_v1(
            &directory, &chain,
        )?;
    println!(
        "{}",
        serde_json::json!({"profile_sha256":hex::encode(profile.digest_v1()?),"profile":profile.schema,"production_activation":false})
    );
    Ok(())
}
fn build_native_client_bootstrap(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<()> {
    let template = PathBuf::from(arguments.next().context("missing validator-set template")?);
    let profile = PathBuf::from(arguments.next().context("missing native public profile")?);
    let digest = parse_hash(arguments.next(), "native-client-profile-sha256")?;
    let secrets = PathBuf::from(
        arguments
            .next()
            .context("missing consensus key directory")?,
    );
    let set_output = PathBuf::from(arguments.next().context("missing validator-set output")?);
    let bootstrap_output = PathBuf::from(arguments.next().context("missing bootstrap output")?);
    if arguments.next().is_some() {
        bail!("unexpected native bootstrap argument");
    }
    let result =
        trnm_poco_lab_validator::bootstrap_material::build_public_native_client_bootstrap_v1(
            template,
            profile,
            digest,
            secrets,
            set_output,
            bootstrap_output,
        )?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
