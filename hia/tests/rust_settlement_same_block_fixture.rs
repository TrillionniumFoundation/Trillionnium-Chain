// Appended to an independently SHA-pinned original Rust qualification
// harness. This test-only entry reuses its fixed signer keys and unchanged
// original business methods, never keys or data from a deployment.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Harness::new();
    if let Some(profile) = std::env::args().nth(1) {
        let (name, pair) = match profile.strip_suffix("-pair") {
            Some(name) => (name, true),
            None => (profile.as_str(), false),
        };
        fixture.trust.context.chain_id = match name {
            "short" => "m12".into(),
            "utf8" => "結算鏈🌱 native fixture".into(),
            _ => return Err("unrecognized owned sizing fixture".into()),
        };
        let command = ConsumptionSettlementCommandV1::AdmitReceipt {
            receipt: fixture.receipt(None, 10, 100),
        };
        let initial = engine::initial_state(&fixture.trust);
        let (state, no_id) = engine::apply_transition(&fixture.trust, &initial, 10, &command)?;
        assert!(no_id.is_none());
        let mut fields = vec![bytes(&fixture.trust), bytes(&command), bytes(&initial), bytes(&state)];
        if pair {
            let second = ConsumptionSettlementCommandV1::AdmitReceipt {
                receipt: fixture.receipt(state.receipts.last(), 11, 50),
            };
            let (successor, no_id) = engine::apply_transition(&fixture.trust, &state, 11, &second)?;
            assert!(no_id.is_none());
            fields.extend([bytes(&second), bytes(&successor)]);
        }
        let mut out = std::io::stdout().lock();
        for field in fields {
            out.write_all(&u32::try_from(field.len())?.to_le_bytes())?;
            out.write_all(&field)?;
        }
        return Ok(());
    }
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
