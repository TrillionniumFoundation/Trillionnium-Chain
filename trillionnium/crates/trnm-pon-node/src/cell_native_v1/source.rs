//! Raw UTF-8 admission bytes -> ASCII-whitespace normalization -> ASCII token
//! hash counts -> clipping -> explicit feature mask. No caller feature vector is
//! accepted and no source-provenance assertion substitutes for this computation.
use super::*;

pub(super) struct PreparedInputs {
    pub features: Vec<Vec<i64>>,
    pub stages: Vec<Stage>,
}

pub(super) fn decode_input(input: &SourceSnippet) -> Result<Vec<u8>> {
    ensure(
        !input.content_hex.is_empty()
            && input.content_hex.len() <= 2 * 4096
            && input.content_hex.len().is_multiple_of(2)
            && input
                .content_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "CELL_SOURCE_HEX",
    )?;
    let raw = hex::decode(&input.content_hex).map_err(|_| Error::from("CELL_SOURCE_HEX"))?;
    std::str::from_utf8(&raw).map_err(|_| Error::from("CELL_SOURCE_UTF8"))?;
    Ok(raw)
}

fn normalize(raw: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(raw.len());
    let mut gap = false;
    for &byte in raw {
        if matches!(byte, b'\t'..=b'\r' | b' ') {
            gap = !normalized.is_empty();
        } else {
            if gap {
                normalized.push(b' ');
                gap = false;
            }
            normalized.push(byte);
        }
    }
    normalized
}

fn features(raw: &[u8]) -> (Vec<i64>, usize) {
    let mut counts = vec![0i64; 256];
    let mut index = 0;
    let mut used = 0;
    while index < raw.len() && used < 1024 {
        if !raw[index].is_ascii_alphabetic() && raw[index] != b'_' {
            index += 1;
            continue;
        }
        let start = index;
        index += 1;
        while index < raw.len() && (raw[index].is_ascii_alphanumeric() || raw[index] == b'_') {
            index += 1;
        }
        let token: Vec<u8> = raw[start..index]
            .iter()
            .map(u8::to_ascii_lowercase)
            .collect();
        if token.starts_with(b"trnm")
            || [b"m00".as_slice(), b"m04", b"m10"].contains(&token.as_slice())
        {
            continue;
        }
        let digest = Sha256::digest(&token);
        // LE16 modulo 256 is exactly byte zero. Keep the declared expression.
        let coordinate = usize::from(u16::from_le_bytes([digest[0], digest[1]])) % 256;
        counts[coordinate] += if digest[2] & 1 == 1 { 1 } else { -1 };
        used += 1;
    }
    for value in &mut counts {
        *value = (*value).clamp(-8, 8);
    }
    counts.push(8);
    (counts, used)
}

pub(super) fn prepare(admission: &OwnerAdmission) -> Result<PreparedInputs> {
    let mut rows = Vec::with_capacity(admission.inputs.len());
    let mut preprocessing = Vec::with_capacity(admission.inputs.len());
    for input in &admission.inputs {
        let raw = decode_input(input)?;
        let normalized = normalize(&raw);
        let (row, count) = features(&normalized);
        preprocessing.push(json!({
            "id":input.id,"raw_sha256":hex::encode(Sha256::digest(&raw)),
            "normalized_hex":hex::encode(&normalized),"used_tokens":count,"features":row,
        }));
        rows.push(row);
    }
    let masked: Vec<Vec<i64>> = rows
        .iter()
        .map(|row| {
            row.iter()
                .zip(&admission.policy.feature_mask)
                .map(|(value, enabled)| if *enabled { *value } else { 0 })
                .collect()
        })
        .collect();
    Ok(PreparedInputs {
        features: masked.clone(),
        stages: vec![
            Stage {
                stage: "source-preprocessing".into(),
                inputs: json!({"profile":INPUT_PROFILE,"snippets":admission.inputs}),
                outputs: json!({"rows":preprocessing,"shape":[rows.len(), DIM],"dtype":"signed-integer"}),
            },
            Stage {
                stage: "feature-mask".into(),
                inputs: json!({"values":rows,"mask":admission.policy.feature_mask}),
                outputs: json!({"values":masked,"shape":[rows.len(), DIM],"dtype":"signed-integer"}),
            },
        ],
    })
}
