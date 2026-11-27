use std::io::{self, Read, Write};
use trnm_data_availability::{
    DaErrorCodeV1, DaNamespaceV1, DaObjectKindV1, Hash32V1, TypedDaObjectIdV1,
};

fn main() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut raw = [0; 35];
        if input.read(&mut raw[..1])? == 0 {
            return Ok(());
        }
        input.read_exact(&mut raw[1..])?;
        let ns = match DaNamespaceV1::transaction_batch_only(raw[0]) {
            Ok(ns) => ns,
            Err(error) => {
                assert_eq!(error.code(), DaErrorCodeV1::UnsupportedNamespace);
                let status = match error.message() {
                    "ArtifactEvidence is outside this candidate tranche" => 2,
                    "unknown DA namespace" => 3,
                    other => panic!("unexpected Rust error: {other}"),
                };
                output.write_all(&[status])?;
                continue;
            }
        };
        let typed_tag = u16::from_le_bytes(raw[1..3].try_into().unwrap());
        let kind = match typed_tag {
            1 => DaObjectKindV1::BATCH,
            2 => DaObjectKindV1::CHUNK,
            3 => DaObjectKindV1::ATTESTATION,
            4 => DaObjectKindV1::CERTIFICATE,
            5 => DaObjectKindV1::OBLIGATION,
            6 => DaObjectKindV1::WITHHOLDING_EVIDENCE,
            _ => panic!("only real Rust typed kinds enter the positive comparison"),
        };
        let digest = Hash32V1::new(raw[3..].try_into().unwrap());
        let value = TypedDaObjectIdV1::new(ns, kind, digest);
        assert_eq!(value.namespace().tag(), raw[0]);
        assert_eq!(value.kind().tag(), typed_tag);
        assert_eq!(value.digest(), digest);
        let encoded = borsh::to_vec(&value).unwrap();
        assert_eq!(
            borsh::from_slice::<TypedDaObjectIdV1>(&encoded).unwrap(),
            value
        );
        assert_eq!(encoded.len(), raw.len());
        output.write_all(&[0])?;
        output.write_all(&encoded)?;
    }
}
