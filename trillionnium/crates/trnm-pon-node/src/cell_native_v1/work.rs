//! Full W1 verification and signed tensor reconstruction for all 257 features.
use super::*;
use trnm_crypto_primitives::pon_work;

struct Material {
    a: Vec<u32>,
    b: Vec<u32>,
    task: Hash,
    bounds: Vec<i64>,
}

fn weights(model: &Model) -> Vec<&Vec<i64>> {
    model
        .base
        .iter()
        .chain(&model.router)
        .chain(model.deltas.iter().flatten())
        .collect()
}

fn material(model: &Model, features: &[Vec<i64>], index: usize) -> Result<Material> {
    let weights = weights(model);
    let start = index * pon_work::N;
    let width = pon_work::N.min(DIM - start);
    let mut a = vec![0; pon_work::CELLS];
    let mut b = vec![0; pon_work::CELLS];
    let mut bounds = vec![0i64; 15];
    let q = pon_work::Q as i64;
    for k in 0..width {
        let maximum = features
            .iter()
            .map(|row| row[start + k].abs())
            .max()
            .ok_or("CELL_BATCH")?;
        for output in 0..15 {
            let weight = weights[output][start + k];
            a[output * pon_work::N + k] = weight.rem_euclid(q) as u32;
            bounds[output] += weight.abs() * maximum;
        }
        for (column, row) in features.iter().enumerate() {
            b[k * pon_work::N + column] = row[start + k].rem_euclid(q) as u32;
        }
    }
    ensure(
        bounds.iter().all(|bound| 2 * bound < q),
        "CELL_SIGNED_BOUND",
    )?;
    let task = pon_work::task_id(&a, &b).map_err(|_| Error::from("CELL_WORK_MATERIAL"))?;
    Ok(Material { a, b, task, bounds })
}

fn challenge(
    expected: &ExpectedCellTask,
    material: &Material,
    index: usize,
    nonce: u64,
) -> Result<Hash> {
    let before: Hash = Sha256::digest(canonical(&expected.admission.before)?).into();
    Ok(hash(
        b"pon-cell-stateful-native-int257-v1/challenge",
        &[
            &expected.contract_id,
            &before,
            &material.task,
            &(index as u64).to_le_bytes(),
            &nonce.to_le_bytes(),
        ],
    ))
}

pub(super) fn prove(
    expected: &ExpectedCellTask,
    features: &[Vec<i64>],
    attempts: u64,
) -> Result<Vec<TileProof>> {
    let target = digest(&expected.admission.work_target)?;
    let mut tiles = Vec::with_capacity(5);
    for index in 0..5 {
        let material = material(&expected.admission.model, features, index)?;
        let mut found = None;
        for nonce in 0..attempts {
            let challenge = challenge(expected, &material, index, nonce)?;
            let proof = pon_work::prove(challenge, &material.a, &material.b)
                .map_err(|_| Error::from("CELL_WORK_PROVE"))?;
            let ticket = hash(b"ticket", &[&challenge, &proof[proof.len() - 32..]]);
            if ticket <= target {
                found = Some(TileProof {
                    index,
                    nonce,
                    proof_hex: hex::encode(proof),
                });
                break;
            }
        }
        tiles.push(found.ok_or("CELL_SEARCH_EXHAUSTED")?);
    }
    Ok(tiles)
}

pub(super) fn verify(
    expected: &ExpectedCellTask,
    features: &[Vec<i64>],
    tiles: &[TileProof],
) -> Result<Vec<Vec<i64>>> {
    ensure(tiles.len() == 5, "CELL_TILE_COUNT")?;
    let target = digest(&expected.admission.work_target)?;
    let mut products = vec![vec![0i64; features.len()]; 15];
    let q = pon_work::Q as i64;
    for (index, tile) in tiles.iter().enumerate() {
        ensure(tile.index == index, "CELL_TILE_ORDER")?;
        ensure(
            tile.proof_hex.len() == 2 * pon_work::PROOF_BYTES
                && tile
                    .proof_hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "CELL_PROOF_HEX",
        )?;
        let raw = hex::decode(&tile.proof_hex).map_err(|_| Error::from("CELL_PROOF_HEX"))?;
        let material = material(&expected.admission.model, features, index)?;
        // Compare all A/B cells, including padding and the final one-coordinate
        // tile, before executing the complete native W1 verifier.
        let expected_material: Vec<u8> = material
            .a
            .iter()
            .chain(&material.b)
            .flat_map(|value| value.to_le_bytes())
            .collect();
        ensure(
            raw[4..4 + 2 * pon_work::CELLS * 4] == expected_material,
            "CELL_WORK_MATERIAL",
        )?;
        let verified = pon_work::verify(
            challenge(expected, &material, index, tile.nonce)?,
            material.task,
            target,
            &raw,
        )
        .map_err(|_| Error::from("CELL_FULL_W1_RELATION"))?;
        // Iterate all 64 x 64 verified cells, not only the 15 active accumulator
        // rows. Inactive row/column padding remains part of the relation.
        for (output, row) in verified.product().chunks_exact(pon_work::N).enumerate() {
            for (column, value) in row.iter().enumerate() {
                let value = i64::from(*value);
                if output >= 15 || column >= features.len() {
                    ensure(value == 0, "CELL_PRODUCT_PADDING")?;
                } else {
                    let signed = if 2 * value > q { value - q } else { value };
                    ensure(
                        signed.abs() <= material.bounds[output],
                        "CELL_PRODUCT_SIGNED_BOUND",
                    )?;
                    products[output][column] += signed;
                }
            }
        }
    }
    // Independent scalar signed accumulation is intentionally distinct from
    // field reconstruction. A tile cannot supply a different intermediate
    // tensor merely by making every later hash agree with that substitution.
    for (output, weight) in weights(&expected.admission.model).iter().enumerate() {
        for (column, row) in features.iter().enumerate() {
            let scalar: i64 = weight.iter().zip(row).map(|(w, x)| w * x).sum();
            ensure(
                products[output][column] == scalar,
                "CELL_SCALAR_PRODUCT_RELATION",
            )?;
        }
    }
    Ok(products)
}
