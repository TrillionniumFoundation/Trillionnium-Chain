use borsh::{from_slice, to_vec};
use std::io::{self, Read, Write};
use trnm_data_availability::{DaAttestationBodyV1, DaAttestationV1, DaCommitteeDescriptorV1, DaErrorCodeV1};

fn main() -> io::Result<()> {
    let mut stream = Vec::new();
    io::stdin().read_to_end(&mut stream)?;
    let mut cases = stream.as_slice();
    let mut output = io::stdout().lock();
    while !cases.is_empty() {
        let width = u32::from_le_bytes(cases[..4].try_into().unwrap()) as usize;
        let wire = &cases[4..4 + width];
        cases = &cases[4 + width..];
        let cut = wire.len() - 4;
        let at = u32::from_le_bytes(wire[cut..].try_into().unwrap()) as usize;
        let committee = from_slice::<DaCommitteeDescriptorV1>(&wire[..at]).unwrap();
        let body = from_slice::<DaAttestationBodyV1>(&wire[at..cut]).unwrap();
        assert_eq!(to_vec(&committee).unwrap(), &wire[..at]);
        assert_eq!(to_vec(&body).unwrap(), &wire[at..cut]);
        // The assertion ensures none of these generated bodies reaches
        // signature checking. This is a public observation of the old prefix.
        assert!(committee.member(body.attestor_id()).is_none());
        let error = DaAttestationV1::from_signature(&committee, body, Vec::new()).unwrap_err();
        use DaErrorCodeV1::*;
        let (code, status) = match error.message() {
            "attestor is not a committee member" => (InvalidCommittee, 0),
            "invalid DA member definition" => (InvalidCommittee, 201),
            "weak DA member key is forbidden" => (InvalidCommittee, 203),
            "DA committee must not be empty" => (InvalidCommittee, 204),
            "unsupported context version" => (InvalidContext, 208),
            "chain ID must be bounded nonempty ASCII" => (InvalidContext, 209),
            "invalid committee bounds" => (InvalidCommittee, 210),
            "committee threshold is not floor(2W/3)+1" => (InvalidCommittee, 212),
            "ArtifactEvidence is outside this candidate tranche" => (UnsupportedNamespace, 213),
            "unknown DA namespace" => (UnsupportedNamespace, 214),
            "attestation does not bind the exact committed DA context" => (InvalidContext, 221),
            other => panic!("unobserved original prefix result: {other}"),
        };
        assert_eq!(error.code(), code);
        output.write_all(&[status])?;
    }
    output.flush()
}
