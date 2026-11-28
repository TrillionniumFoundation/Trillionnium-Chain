use std::io::{self, Read, Write};
use trnm_data_availability::cell::{CellContentErrorV2 as Error, CellContentManifestV2};

fn original(bytes: &[u8]) -> (u8, Vec<u8>) {
    let code = match CellContentManifestV2::decode(bytes) {
        Ok(value) => return (0, value.encode()),
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
        Err(other) => panic!("unexpected original manifest error {other:?}"),
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
