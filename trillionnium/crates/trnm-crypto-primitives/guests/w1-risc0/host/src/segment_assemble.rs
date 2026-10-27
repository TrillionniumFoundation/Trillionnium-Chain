use super::*;

pub fn assemble_segments(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 7,
        "assemble-segments <elf> <input> <session-dir> <receipt-dir> <new-receipt>"
    );
    let elf = bounded_read(Path::new(&args[2]), MAX_ELF_BYTES)?;
    require_pinned_image(&elf)?;
    let input = bounded_read(Path::new(&args[3]), full_relation::INPUT_BYTES)?;
    let journal =
        full_relation::unverified_claimed_journal(&input).map_err(|error| anyhow!("{error:?}"))?;
    let dir = Path::new(&args[4]);
    let session = session(dir)?;
    ensure!(
        session["elf_sha256"] == sha(&elf) && session["input_sha256"] == sha(&input),
        "session input/image changed"
    );
    ensure!(
        session["journal_hex"] == hex::encode(&journal),
        "session public statement differs"
    );
    let claim_bytes = bounded_read(&dir.join("session.claim.bin"), 16 * 1024)?;
    receipt_bounds::preflight_claim(&claim_bytes)?;
    ensure!(
        session["session_claim_sha256"] == sha(&claim_bytes),
        "session claim bytes changed"
    );
    let expected_claim: ReceiptClaim = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024)
        .reject_trailing_bytes()
        .deserialize(&claim_bytes)?;
    ensure!(
        expected_claim.exit_code == ExitCode::Halted(0),
        "non-successful session claim"
    );
    ensure!(
        session["session_claim_digest"]
            == expected_claim.digest::<risc0_zkvm::sha::Impl>().to_string(),
        "session claim digest changed"
    );
    let items = session["segments"]
        .as_array()
        .context("missing session inventory")?;
    let mut segments = Vec::with_capacity(items.len());
    let receipt_dir = Path::new(&args[5]);
    let mut receipt_bytes = 0usize;
    for (index, item) in items.iter().enumerate() {
        let encoded = bounded_read(
            &receipt_dir.join(format!("segment-{index}.bin")),
            2 * 1024 * 1024,
        )?;
        let cycles = receipt_bounds::preflight_segment(&encoded, index)?;
        ensure!(
            cycles == 1u64 << number(item, "po2")?,
            "segment receipt dimension changed"
        );
        receipt_bytes = receipt_bytes
            .checked_add(encoded.len())
            .context("receipt size overflow")?;
        ensure!(
            receipt_bytes <= MAX_RECEIPT_BYTES,
            "aggregate receipt byte budget"
        );
        let receipt = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(2 * 1024 * 1024)
            .reject_trailing_bytes()
            .deserialize::<risc0_zkvm::SegmentReceipt>(&encoded)?;
        segments.push(receipt);
    }
    // Mirror the SDK's final output disclosure, with an explicit digest check.
    // This is not proof substitution: the unchanged full verifier below checks
    // every STARK, segment order, chained pre/post states, image, journal and
    // the empty assumptions list. No unproven assumptions or PoVW job is used.
    let last = segments.last_mut().context("missing final segment")?;
    ensure!(
        last.claim.output.digest::<risc0_zkvm::sha::Impl>()
            == expected_claim.output.digest::<risc0_zkvm::sha::Impl>(),
        "final segment output differs from the complete session claim"
    );
    last.claim.output = expected_claim.output.clone();
    let context = VerifierContext::default().with_dev_mode(false);
    let verifier_parameters = context
        .composite_verifier_parameters()
        .context("missing Composite parameters")?
        .digest::<risc0_zkvm::sha::Impl>();
    // The pinned SDK marks CompositeReceipt non_exhaustive and provides no
    // external constructor. Its bincode struct has exactly these three fields.
    // All external segment/claim bytes were scanned before decoding above;
    // this only serializes already bounded owned values, not arbitrary input.
    // The explicit SDK-shape regression keeps this versioned assembly honest.
    let composite_bytes = bincode::serialize(&(
        segments,
        Vec::<risc0_zkvm::InnerAssumptionReceipt>::new(),
        verifier_parameters,
    ))?;
    ensure!(
        composite_bytes.len() <= MAX_RECEIPT_BYTES,
        "assembled byte budget"
    );
    let composite: CompositeReceipt = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_RECEIPT_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(&composite_bytes)?;
    ensure!(
        composite.claim()?.digest::<risc0_zkvm::sha::Impl>()
            == expected_claim.digest::<risc0_zkvm::sha::Impl>(),
        "assembled claim differs"
    );
    let receipt = Receipt::new(InnerReceipt::Composite(composite), journal.clone());
    let cpu = process_cpu::nanoseconds()?;
    let start = Instant::now();
    strict_verify(&receipt, &elf, &journal)?;
    let verify_ns = start.elapsed().as_nanos();
    let verify_cpu_ns = process_cpu::nanoseconds()?
        .checked_sub(cpu)
        .context("CPU clock moved backwards")?;
    let encoded = bincode::serialize(&receipt)?;
    receipt_bounds::preflight(&encoded)?;
    write_new(Path::new(&args[6]), &encoded)?;
    println!(
        "{}",
        json!({"schema":"pon-w1-segmented-assembly-v1",
        "real_composite_stark_verified":true,"image_id":session["image_id"],
        "statement_id":session["statement_id"],"segments":items.len(),
        "user_cycles":number(&session,"user_cycles")?,"segment_po2_limit":18,
        "receipt_bytes":encoded.len(),"receipt_sha256":sha(&encoded),
        "additional_verify_wall_ns":verify_ns,"additional_verify_process_cpu_ns":verify_cpu_ns,
        "native_w1_recomputed":false,"assumption_receipts":0,"povw_requested":false,
        "public_ingress_qualified":false,"consensus_authority":false})
    );
    Ok(())
}
