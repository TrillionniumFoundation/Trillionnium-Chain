// Appended to an independently SHA-pinned original Rust qualification
// harness. This test-only entry reuses its fixed signer keys and unchanged
// original business methods, never keys or data from a deployment.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Harness::new();
    let first = ConsumptionSettlementCommandV1::AdmitReceipt {
        receipt: fixture.receipt(None, 10, 100),
    };
    let initial = engine::initial_state(&fixture.trust);
    let (partial, no_id) = engine::apply_transition(&fixture.trust, &initial, 10, &first)?;
    assert!(no_id.is_none());
    let rollup = fixture.rollup(&partial, 10);
    let second = ConsumptionSettlementCommandV1::AdmitRollup {
        rollup,
        receipts: partial.receipts.iter().map(|r| r.receipt.clone()).collect(),
    };
    let (final_state, no_id) = engine::apply_transition(&fixture.trust, &partial, 10, &second)?;
    assert!(no_id.is_none());
    let mut out = std::io::stdout().lock();
    for field in [bytes(&fixture.trust), bytes(&first), bytes(&second),
                  bytes(&initial), bytes(&partial), bytes(&final_state)] {
        out.write_all(&u32::try_from(field.len())?.to_le_bytes())?;
        out.write_all(&field)?;
    }
    Ok(())
}
