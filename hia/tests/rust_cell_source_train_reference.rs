// Temporary source-bound adapter: append only to the existing exact Rust
// held-training referee. No verification/proof routine is included.
// @FROZEN_WEIGHTS@

fn numeric_products(model:&Model,features:&[Vec<i64>])->Vec<Vec<i64>> {
    weights(model).iter().map(|weight| features.iter().map(|row| {
        // @FROZEN_CELL_SCALAR@
        scalar
    }).collect()).collect()
}

fn write_source_trace(prepared:&source::PreparedInputs,products:&[Vec<i64>],
                      policy:&Policy,inputs:&[SourceSnippet],out:&mut impl Write)->io::Result<()> {
    let source_rows=prepared.stages[0].outputs["rows"].as_array().unwrap();
    let masked=prepared.stages[1].outputs["values"].as_array().unwrap();
    assert_eq!((&*prepared.stages[0].stage,&*prepared.stages[1].stage),
               ("source-preprocessing","feature-mask"));
    assert_eq!(source_rows.len(),inputs.len());
    assert_eq!(products.len(),15);
    out.write_all(&[0])?;
    out.write_all(&(inputs.len() as u32).to_le_bytes())?;
    for (j,snippet) in inputs.iter().enumerate() {
        let row=&source_rows[j];
        assert_eq!(row["id"],snippet.id);
        let normal=hex::decode(row["normalized_hex"].as_str().unwrap()).unwrap();
        let digest=hex::decode(row["raw_sha256"].as_str().unwrap()).unwrap();
        let mask=policy.expert_mask[j].iter().enumerate().map(|(k,&x)|u64::from(x)<<k).sum::<u64>();
        out.write_all(&(normal.len() as u64).to_le_bytes())?;
        out.write_all(&row["used_tokens"].as_u64().unwrap().to_le_bytes())?;
        assert_eq!(digest.len(),32);
        out.write_all(&digest)?;
        for field in [row["features"].as_array().unwrap(),masked[j].as_array().unwrap()] {
            assert_eq!(field.len(),DIM);
            for v in field { out.write_all(&signed(v).to_le_bytes())?; }
        }
        assert_eq!(masked[j],json!(&prepared.features[j]));
        out.write_all(&normal)?;
        out.write_all(&mask.to_le_bytes())?;
        out.write_all(&u64::from(snippet.label).to_le_bytes())?;
        for lane in products { out.write_all(&lane[j].to_le_bytes())?; }
    }
    Ok(())
}
