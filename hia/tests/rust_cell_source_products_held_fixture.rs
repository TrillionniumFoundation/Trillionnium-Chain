// Additional read-only numeric observers for the original held execute fixture.
// Weight order and scalar arithmetic are injected as exact frozen source spans.
// @FROZEN_DOT_AND_WEIGHT_ORDER@

fn feature_receipts(prepared:&source::PreparedInputs)->Vec<Vec<u8>> {
    let source_rows=prepared.stages[0].outputs["rows"].as_array().unwrap();
    let masked=&prepared.stages[1].outputs["values"];
    assert_eq!(prepared.stages[0].stage,"source-preprocessing");
    assert_eq!(prepared.stages[1].stage,"feature-mask");
    assert_eq!(source_rows.len(),prepared.features.len());
    source_rows.iter().enumerate().map(|(i,row)| {
        let normalized=hex::decode(row["normalized_hex"].as_str().unwrap()).unwrap();
        let mut result=Vec::new();
        result.extend_from_slice(&(normalized.len() as u64).to_le_bytes());
        result.extend_from_slice(&row["used_tokens"].as_u64().unwrap().to_le_bytes());
        result.extend_from_slice(&hex::decode(row["raw_sha256"].as_str().unwrap()).unwrap());
        for lanes in [&row["features"],&masked[i]] {
            for v in lanes.as_array().unwrap() {result.extend_from_slice(&signed(v).to_le_bytes());}
        }
        assert_eq!(result.len(),4160);
        assert_eq!(masked[i],json!(&prepared.features[i]));
        result.extend(normalized);
        result
    }).collect()
}

fn frozen_numeric_products(model:&Model,features:&[Vec<i64>])->Vec<Vec<i64>> {
    weights(model).iter().map(|weight| {
        features.iter().map(|row| {
            let w: [i32;DIM]=std::array::from_fn(|k|i32::try_from(weight[k]).unwrap());
            let x: [i32;DIM]=std::array::from_fn(|k|i32::try_from(row[k]).unwrap());
            let numeric=dot(&w,&x);
            // @FROZEN_CELL_SCALAR_EXPRESSION@
            assert_eq!(numeric,scalar);
            numeric
        }).collect()
    }).collect()
}

fn stage_trace(prepared:&source::PreparedInputs,products:&[Vec<i64>],out:&mut impl Write)->io::Result<()> {
    let nonce_free=feature_receipts(prepared);
    assert_eq!(products.len(),15);
    out.write_all(&(nonce_free.len() as u32).to_le_bytes())?;
    for (i,receipt) in nonce_free.into_iter().enumerate() {
        out.write_all(&(receipt.len() as u32).to_le_bytes())?;
        out.write_all(&receipt)?;
        for lane in products {
            out.write_all(&lane[i].to_le_bytes())?;
        }
    }
    Ok(())
}
