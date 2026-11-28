use std::io::{self, Read, Write};
use trnm_data_availability::cell::{CellContentClosureV2, CellContentDependencyV2, CellContentErrorV2 as Error};

fn original(bytes: &[u8]) -> (u8, Vec<u8>) {
    let code = match CellContentClosureV2::decode(bytes) {
        Ok(value) => {
            value.validate().expect("original decoded value validates");
            let manifest = value.manifest().encode();
            let mut cursor = 8 + manifest.len();
            assert_eq!(manifest, bytes[8..cursor]);
            for role in CellContentDependencyV2::ALL {
                let claim = value.dependency_claim(role).encode();
                assert_eq!(bytes[cursor], role as u8);
                cursor += 1;
                assert_eq!(claim, bytes[cursor..cursor + claim.len()]);
                cursor += claim.len();
            }
            assert_eq!(cursor, bytes.len());
            return (0, value.encode());
        }
        Err(Error::Invalid("manifest length")) => 1,
        Err(Error::Invalid("manifest version")) => 2,
        Err(Error::Invalid("family length")) => 3,
        Err(Error::Invalid("manifest exact coverage")) => 4,
        Err(Error::Invalid("family encoding")) => 5,
        Err(Error::Commitment(cause)) => match format!("{cause:?}").as_str() {
            "Encoding" => 6,
            "InvalidContext" => 7,
            other => panic!("unexpected original inner claim error: {other}"),
        },
        Err(Error::Metadata(err)) => match format!("{err:?}").as_str() {
            "Invalid(\"model family\")" => 8,
            other => panic!("unexpected original context error: {other}"),
        },
        Err(Error::Invalid("payload purpose")) => 9,
        Err(Error::Invalid("payload size")) => 10,
        Err(Error::Invalid("closure length")) => 20,
        Err(Error::Invalid("closure version")) => 21,
        Err(Error::Invalid("closure exact coverage")) => 22,
        Err(Error::Invalid("closure canonical role order")) => 23,
        Err(Error::Invalid("dependency purpose")) => 26,
        Err(Error::Invalid("dependency profile")) => 27,
        Err(Error::Invalid("dependency size")) => 28,
        Err(other) => panic!("unexpected original closure error {other:?}"),
    };
    (code, Vec::new())
}

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();
    let mut input = input.as_slice();
    let mut stdout = io::stdout().lock();
    while !input.is_empty() {
        let n = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
        let (status, bytes) = original(&input[4..4 + n]);
        input = &input[4 + n..];
        stdout.write_all(&[status]).unwrap();
        stdout.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
        stdout.write_all(&bytes).unwrap();
    }
}
