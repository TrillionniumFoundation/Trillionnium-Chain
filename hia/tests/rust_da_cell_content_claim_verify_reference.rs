use std::io::{self, Read, Write};
use trnm_data_availability::cell::{CellContentClosureV2, CellContentManifestV2, CellContentErrorV2 as CellError};
use trnm_protocol::content_commitment::{
    ContentClaimV1, ContentCommitmentError, ContentReadBudget, ObservedContentV1,
};

fn structural(err: CellError) -> u8 {
    match err {
        CellError::Invalid("manifest length") => 1,
        CellError::Invalid("manifest version") => 2,
        CellError::Invalid("family length") => 3,
        CellError::Invalid("manifest exact coverage") => 4,
        CellError::Invalid("family encoding") => 5,
        CellError::Commitment(ContentCommitmentError::Encoding) => 6,
        CellError::Commitment(ContentCommitmentError::InvalidContext) => 7,
        CellError::Metadata(err) if format!("{err:?}") == "Invalid(\"model family\")" => 8,
        CellError::Invalid("payload purpose") => 9,
        CellError::Invalid("payload size") => 10,
        CellError::Invalid("closure length") => 20,
        CellError::Invalid("closure version") => 21,
        CellError::Invalid("closure exact coverage") => 22,
        CellError::Invalid("closure canonical role order") => 23,
        CellError::Invalid("dependency purpose") => 26,
        CellError::Invalid("dependency profile") => 27,
        CellError::Invalid("dependency size") => 28,
        other => panic!("unexpected original closure structural result: {other:?}"),
    }
}


fn compare(bytes: &[u8]) -> u8 {
    if bytes.len() < 371 || bytes[370] > 1 {
        return 100;
    }
    fn observe_with(
        bytes: &[u8],
        call: impl FnOnce(
            &trnm_protocol::content_commitment::ContentContextV1,
            &mut ContentReadBudget,
        ) -> Result<ObservedContentV1, CellError>,
    ) -> u8 {
        let expected = match ContentClaimV1::decode(&bytes[157..370]) {
            Ok(x) => x,
            Err(ContentCommitmentError::Encoding) => return 36,
            Err(ContentCommitmentError::InvalidContext) => return 37,
            Err(e) => panic!("unexpected expected claim result: {e:?}"),
        };
        let mut detached = [0; 213];
        detached[..141].copy_from_slice(&bytes[..141]);
        let context = match ContentClaimV1::decode(&detached) {
            Ok(x) => x,
            Err(ContentCommitmentError::Encoding) => return 31,
            Err(ContentCommitmentError::InvalidContext) => return 32,
            Err(e) => panic!("unexpected independent context result: {e:?}"),
        };
        let mr = u64::from_be_bytes(bytes[141..149].try_into().unwrap());
        let mb = u64::from_be_bytes(bytes[149..157].try_into().unwrap());
        let mut budget = match ContentReadBudget::new(mr, mb) {
            Ok(x) => x,
            Err(ContentCommitmentError::Budget) => return 30,
            Err(e) => panic!("unexpected budget constructor result: {e:?}"),
        };
        let obs = match call(context.context(), &mut budget) {
            Ok(x) => x,
            Err(CellError::Invalid("manifest purpose")) => return 33,
            Err(CellError::Invalid("manifest/payload context")) => return 34,
            Err(CellError::Commitment(ContentCommitmentError::Budget)) => return 35,
            Err(e) => panic!("unexpected original declared observation result: {e:?}"),
        };
        assert_eq!(budget.reads_reserved(), 1);
        assert_eq!(budget.bytes_reserved(), bytes[371..].len() as u64 + 1);
        match expected.verify(&obs) {
            Ok(()) => 0,
            Err(ContentCommitmentError::Mismatch) => 38,
            Err(other) => panic!("unexpected actual original verify result: {other:?}"),
        }
    }
    if bytes[370] == 0 {
        match CellContentManifestV2::decode(&bytes[371..]) {
            Ok(x) => {
                assert_eq!(x.encode(), &bytes[371..]);
                observe_with(bytes, |context, budget| x.observe_manifest(context, budget))
            }
            Err(e) => structural(e),
        }
    } else {
        match CellContentClosureV2::decode(&bytes[371..]) {
            Ok(x) => {
                assert_eq!(x.encode(), &bytes[371..]);
                observe_with(bytes, |context, budget| x.observe_closure(context, budget))
            }
            Err(e) => structural(e),
        }
    }
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
        out.write_all(&[compare(data)])?;
    }
    out.flush()
}
