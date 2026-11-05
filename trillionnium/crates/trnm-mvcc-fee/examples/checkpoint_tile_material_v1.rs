//! Finite local replay of explicit checkpoint/activation/A/B pinnings.
//! No model forward, Node, ledger execution or chain authority.
use serde::Deserialize;
use sha2::{Digest, Sha256};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    path::Path,
    time::{Duration, Instant},
};
use trnm_crypto_primitives::{
    pon_work,
    qualified_work_task::{
        derive_matrices, lifecycle_v2::verify_lifecycle_admission, TaskMaterial,
    },
};
use trnm_mvcc_fee::{
    checkpoint_tile_material_v1::*, pon_executor::Config, qualified_task_lifecycle,
};
use trnm_protocol::qualified_work_task::lifecycle_v4::PROFILE;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pins {
    network: String,
    parameters: String,
    checkpoint_sha256: String,
    checkpoint_bytes: u64,
    activation_sha256: String,
    model: String,
    input: String,
    a_sha256: String,
    b_sha256: String,
}
fn hash(v: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if v.len() != 64
        || !v
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("PIN_HEX".into());
    }
    Ok(hex::decode(v)?.try_into().map_err(|_| "PIN_HEX")?)
}
fn file(path: &Path) -> Result<File, Box<dyn std::error::Error>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    options.custom_flags(0x20000); // Verified Linux x86_64 O_NOFOLLOW ABI.
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    return Err("EXAMPLE_LINUX_X86_64_FILE_ADAPTER_REQUIRED".into());
    let f = options.open(path)?;
    if !f.metadata()?.is_file() {
        return Err("REGULAR_FILE".into());
    }
    Ok(f)
}
fn bytes(path: &Path, max: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let f = file(path)?;
    if f.metadata()?.len() > max as u64 {
        return Err("FILE_LIMIT".into());
    }
    let mut raw = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut raw)?;
    if raw.len() > max {
        return Err("FILE_LIMIT".into());
    }
    Ok(raw)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--development-context" {
        let cfg = Config::installed_with_profiles("native-public-evaluation-dev-v1", PROFILE)?;
        println!(
            "{}",
            serde_json::json!({"network":hex::encode(cfg.network),"parameters":hex::encode(cfg.parameters),"policy":hex::encode(policy_id()),"chain_authority":false})
        );
        return Ok(());
    }
    if args.len() != 7 {
        return Err("usage: checkpoint_tile_material_v1 checkpoint activation A B pinned-context output-new-directory".into());
    }
    let start = Instant::now();
    let mut checkpoint = file(Path::new(&args[1]))?;
    let before = checkpoint.metadata()?;
    let activation = bytes(Path::new(&args[2]), MAX_ACTIVATION_BYTES)?;
    let a = bytes(Path::new(&args[3]), 16384)?;
    let b = bytes(Path::new(&args[4]), 16384)?;
    let pins_raw = bytes(Path::new(&args[5]), 4096)?;
    let pins: Pins = serde_json::from_slice(&pins_raw)?;
    if <[u8; 32]>::from(Sha256::digest(&a)) != hash(&pins.a_sha256)?
        || <[u8; 32]>::from(Sha256::digest(&b)) != hash(&pins.b_sha256)?
    {
        return Err("ORIGINAL_MATRIX_SHA".into());
    }
    let ctx = PinnedTileContextV1 {
        network: hash(&pins.network)?,
        parameters: hash(&pins.parameters)?,
        checkpoint_sha256: hash(&pins.checkpoint_sha256)?,
        checkpoint_bytes: pins.checkpoint_bytes,
        activation_sha256: hash(&pins.activation_sha256)?,
        model: hash(&pins.model)?,
        input: hash(&pins.input)?,
    };
    let cfg = Config::installed_with_profiles("native-public-evaluation-dev-v1", PROFILE)?;
    if ctx.network != cfg.network || ctx.parameters != cfg.parameters {
        return Err("ACTUAL_CONFIG_CONTEXT".into());
    }
    let checked =
        derive_checkpoint_tile_material_v1(&mut checkpoint, &activation, &a, &b, &ctx, |_| {
            if start.elapsed() < Duration::from_secs(90) {
                Ok(())
            } else {
                Err("REPLAY_WALL")
            }
        })?;
    let boot = qualified_task_lifecycle::bootstrap_state(&cfg, &a, &b)?;
    let (aa, bb) = derive_matrices(&a, &b).map_err(|_| "MATRIX_DECODE")?;
    let signed = boot.signed.encode().map_err(|_| "SOURCE_ENCODING")?;
    let admission = verify_lifecycle_admission(
        &signed,
        TaskMaterial {
            model: &a,
            input: &b,
            a: &aa,
            b: &bb,
        },
        &boot.lease,
        0,
    )
    .map_err(|_| "SIGNED_SOURCE_ADMISSION")?;
    let binding = checked.bind_admission(&admission)?;
    let after = checkpoint.metadata()?;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err("CHECKPOINT_FILE_CHANGED".into());
    }
    let (product, _) = pon_work::evaluate([1; 32], &aa, &bb).map_err(|_| "WORK_RELATION")?;
    let out = Path::new(&args[6]);
    std::fs::create_dir(out)?;
    std::fs::write(out.join("descriptor.json"), checked.canonical_descriptor())?;
    std::fs::write(
        out.join("product.field-u32le"),
        product
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>(),
    )?;
    std::fs::write(out.join("source-statement.bin"), signed)?;
    let result = serde_json::json!({"schema":"checkpoint-tile-material-actual-local-replay-v1","descriptor_id":hex::encode(checked.descriptor_id()),"admission_binding":hex::encode(binding),"checkpoint_bytes":ctx.checkpoint_bytes,"checkpoint_bytes_read":checked.checkpoint_bytes_read(),"a_values_compared":4096,"b_values_compared":4096,"product_values":4096,"elapsed_ns":start.elapsed().as_nanos(),"policy":hex::encode(policy_id()),"network":pins.network,"parameters":pins.parameters,"source_signature_checked":true,"source_identity":"explicit-known-development-key-zero","native_branch_eligibility_checked":false,"chain_authority":false,"full_forward_verified":false,"hardness_accepted":false,"genuine_demand_verified":false,"marginal_contribution_accepted":false,"public_network_ready":false});
    std::fs::write(out.join("result.json"), serde_json::to_vec_pretty(&result)?)?;
    println!("{}", result);
    Ok(())
}
