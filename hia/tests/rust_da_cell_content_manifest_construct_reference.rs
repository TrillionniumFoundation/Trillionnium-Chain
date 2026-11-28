use std::io::{self, Read, Write};
use trnm_data_availability::cell::{CellContentErrorV2, CellContentManifestV2, CellContextV1};
use trnm_protocol::content_commitment::{
    observe_bytes, ContentClaimV1, ContentCommitmentError, ContentReadBudget,
};

fn produce(bytes: &[u8]) -> Result<Vec<u8>, u8> {
    if bytes.len() < 318 || bytes.len() > 1 << 20 {
        return Err(100);
    }
    let family_len = bytes[157] as usize;
    let after_family = 158 + family_len;
    let data_at = after_family + 160;
    if bytes.len() < data_at {
        return Err(100);
    }
    let mut context_frame = [0; 213];
    context_frame[..141].copy_from_slice(&bytes[..141]);
    let typed_context = ContentClaimV1::decode(&context_frame).map_err(|e| match e {
        ContentCommitmentError::Encoding => 31_u8,
        ContentCommitmentError::InvalidContext => 32,
        other => panic!("unexpected context error {other:?}"),
    })?;
    let reads = u64::from_be_bytes(bytes[141..149].try_into().unwrap());
    let byte_cap = u64::from_be_bytes(bytes[149..157].try_into().unwrap());
    let mut budget = ContentReadBudget::new(reads, byte_cap).map_err(|e| match e {
        ContentCommitmentError::Budget => 30_u8,
        other => panic!("unexpected fresh budget error {other:?}"),
    })?;
    let inert = &bytes[data_at..];
    let observation = observe_bytes(typed_context.context(), &mut budget, inert).map_err(|e| {
        match e {
            ContentCommitmentError::Budget => {
                assert_eq!((budget.reads_reserved(), budget.bytes_reserved()), (reads, byte_cap));
                assert!(budget.exhausted());
                35_u8
            }
            other => panic!("unexpected in-memory original observation error {other:?}"),
        }
    })?;
    assert_eq!((budget.reads_reserved(), budget.bytes_reserved()), (1, inert.len() as u64 + 1));
    let family = std::str::from_utf8(&bytes[158..after_family])
        .map_err(|_| 5_u8)?
        .to_owned();
    let alias = |i: usize| -> [u8; 32] {
        bytes[after_family + i * 32..after_family + (i + 1) * 32]
            .try_into()
            .unwrap()
    };
    let legacy = CellContextV1 {
        family,
        base: alias(0),
        parent: alias(1),
        tokenizer: alias(2),
        layout: alias(3),
        runtime: alias(4),
    };
    let value =
        CellContentManifestV2::from_observed_payload(legacy, &observation).map_err(|e| match e {
            CellContentErrorV2::Metadata(e) if format!("{e:?}") == "Invalid(\"model family\")" => 8_u8,
            CellContentErrorV2::Invalid("payload purpose") => 9,
            CellContentErrorV2::Invalid("payload size") => 10,
            other => panic!("unexpected original TCM2 constructor error {other:?}"),
        })?;
    assert_eq!(value.payload_claim(), observation.claim());
    let canonical = value.encode();
    assert_eq!(CellContentManifestV2::decode(&canonical).unwrap(), value);
    Ok(canonical)
}

fn main() -> io::Result<()> {
    let mut all = Vec::new();
    io::stdin().read_to_end(&mut all)?;
    let mut input = all.as_slice();
    let mut out = io::BufWriter::new(io::stdout().lock());
    while !input.is_empty() {
        let n = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
        let (data, rest) = input[4..].split_at(n);
        input = rest;
        match produce(data) {
            Ok(record) => {
                out.write_all(&[0])?;
                out.write_all(&(record.len() as u16).to_le_bytes())?;
                out.write_all(&record)?;
            }
            Err(status) => out.write_all(&[status, 0, 0])?,
        }
    }
    out.flush()
}
