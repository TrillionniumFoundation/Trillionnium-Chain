// Appended to an independently SHA-pinned original Rust qualification
// harness. This test-only entry reuses its fixed signer keys and unchanged
// original business methods, never keys or data from a deployment.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Harness::new();
    let mode = std::env::args().nth(1);
    let mode = if mode.as_deref() == Some("short-same-block") {
        fixture.trust.context.chain_id = "m12".into();
        None
    } else {
        mode
    };
    if let Some(profile) = mode {
        if ["six-admits", "short-linear-admits", "utf8-linear-admits"].contains(&profile.as_str()) {
            match profile.as_str() {
                "short-linear-admits" => fixture.trust.context.chain_id = "x".into(),
                "utf8-linear-admits" => fixture.trust.context.chain_id = "原生區塊🧪".into(),
                _ => (),
            }
            let mut state = engine::initial_state(&fixture.trust);
            let mut out = std::io::stdout().lock();
            let mut frame = |field: Vec<u8>| -> Result<(), Box<dyn std::error::Error>> {
                out.write_all(&u32::try_from(field.len())?.to_le_bytes())?;
                out.write_all(&field)?;
                Ok(())
            };
            frame(bytes(&fixture.trust))?;
            // Preserve the earlier exact six-command fixture; long variants
            // also cover the new upper-bound original read-only control.
            let end = if profile == "six-admits" { 16 } else { 19 };
            for height in 10..end {
                let cmd = ConsumptionSettlementCommandV1::AdmitReceipt {
                    receipt: fixture.receipt(state.receipts.last(), height, 1),
                };
                let (next, no_id) = engine::apply_transition(&fixture.trust, &state, height, &cmd)?;
                assert!(no_id.is_none());
                state = next;
                frame(bytes(&cmd))?;
            }
            return Ok(());
        }
        let (name, rows) = if let Some(name) = profile.strip_suffix("-settle") {
            (name, 4)
        } else if let Some(name) = profile.strip_suffix("-rollup") {
            (name, 3)
        } else if let Some(name) = profile.strip_suffix("-pair") {
            (name, 2)
        } else {
            (profile.as_str(), 1)
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
        if rows >= 2 {
            let second = ConsumptionSettlementCommandV1::AdmitReceipt {
                receipt: fixture.receipt(state.receipts.last(), 11, 50),
            };
            let (successor, no_id) = engine::apply_transition(&fixture.trust, &state, 11, &second)?;
            assert!(no_id.is_none());
            fields.extend([bytes(&second), bytes(&successor)]);
            if rows >= 3 {
                let third = ConsumptionSettlementCommandV1::AdmitRollup {
                    rollup: fixture.rollup(&successor, 12),
                    receipts: successor.receipts.iter().map(|r| r.receipt.clone()).collect(),
                };
                let (rolled, no_id) = engine::apply_transition(&fixture.trust, &successor, 12, &third)?;
                assert!(no_id.is_none());
                fields.extend([bytes(&third), bytes(&rolled)]);
                if rows == 4 {
                    let fourth = fixture.settle(&rolled);
                    assert!(engine::apply_transition(&fixture.trust, &rolled, 14, &fourth).is_err());
                    let (settled, final_id) = engine::apply_transition(&fixture.trust, &rolled, 15, &fourth)?;
                    assert!(final_id.is_some());
                    fields.extend([bytes(&fourth), bytes(&settled), bytes(&final_id.unwrap())]);
                }
            }
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
