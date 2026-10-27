use super::*;

pub fn export_segments(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 7,
        "export-segments <r0vm> <elf> <input> <po2> <new-dir>"
    );
    let elf = bounded_read(Path::new(&args[3]), MAX_ELF_BYTES)?;
    require_pinned_image(&elf)?;
    let input = bounded_read(Path::new(&args[4]), full_relation::INPUT_BYTES)?;
    let expected = full_relation::execute_input(&input).map_err(|error| anyhow!("{error:?}"))?;
    let po2: u32 = args[5].parse()?;
    ensure!(
        po2 == 18,
        "this measured scheduler keeps the original segment profile"
    );
    let dir = Path::new(&args[6]);
    fs::create_dir(dir)?;
    let dir = fs::canonicalize(dir)?;
    let client = ApiClient::new_sub_process(&args[2])?;
    let mut items = Vec::new();
    let mut exported_bytes = 0u64;
    let start = Instant::now();
    let executed = client.execute(
        &environment(&input, po2)?,
        Asset::Inline(elf.clone().into()),
        AssetRequest::Path(dir.clone()),
        |info, asset| {
            let index = items.len();
            ensure!(index < receipt_bounds::MAX_SEGMENTS, "segment count budget");
            let Asset::Path(path) = asset else {
                anyhow::bail!("segment was not exported to disk")
            };
            ensure!(
                path == dir.join(format!("segment-{index}")),
                "unexpected exported path"
            );
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "regular exported segment required"
            );
            let bytes = bounded_read(&path, MAX_SEGMENT_ASSET_BYTES)?;
            exported_bytes = exported_bytes
                .checked_add(bytes.len() as u64)
                .context("segment byte count overflow")?;
            ensure!(
                exported_bytes <= MAX_ALL_SEGMENT_ASSETS,
                "exported trace byte budget"
            );
            let item = json!({"index":index,"po2":info.po2,"user_cycles":info.cycles,
                "file":format!("segment-{index}"),"bytes":bytes.len(),"sha256":sha(&bytes)});
            eprintln!("W1_SEGMENT_EXPORTED {item}");
            items.push(item);
            Ok(())
        },
    )?;
    ensure!(
        executed.exit_code == ExitCode::Halted(0),
        "guest did not halt successfully"
    );
    ensure!(
        executed.journal.bytes == expected.journal(),
        "actual full guest differs from native W1"
    );
    ensure!(
        items.len() == executed.segments.len() && !items.is_empty(),
        "incomplete session export"
    );
    let claim = executed
        .receipt_claim
        .as_ref()
        .context("actual session claim unavailable")?;
    let claim_bytes = bincode::serialize(claim)?;
    receipt_bounds::preflight_claim(&claim_bytes)?;
    write_new(&dir.join("session.claim.bin"), &claim_bytes)?;
    let result = json!({"schema":"pon-w1-full-session-assets-v1",
        "image_id":compute_image_id(&elf)?.to_string(),"elf_sha256":sha(&elf),
        "input_sha256":sha(&input),"statement_id":hex::encode(expected.statement_id()),
        "journal_hex":hex::encode(&executed.journal.bytes),
        "session_claim_sha256":sha(&claim_bytes),"session_claim_digest":claim.digest::<risc0_zkvm::sha::Impl>().to_string(),
        "user_cycles":executed.cycles(),"segment_po2_limit":po2,
        "exported_segment_bytes":exported_bytes,"segments":items,
        "execute_and_export_wall_ns":start.elapsed().as_nanos(),
        "full_w1_guest_executed":true,"cryptographic_proof_verified":false,
        "assumptions_requested":false,"povw_requested":false,"consensus_authority":false});
    write_new(
        &dir.join("session.json"),
        &serde_json::to_vec_pretty(&result)?,
    )?;
    println!("{result}");
    Ok(())
}
