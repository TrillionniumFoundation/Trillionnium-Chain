use borsh::{from_slice, to_vec};
use std::io::{self, Read, Write};
use trnm_data_availability::DaAttestationBodyV1;

fn main() -> io::Result<()> {
    let mut stream = Vec::new();
    io::stdin().read_to_end(&mut stream)?;
    let mut frames = stream.as_slice();
    let mut out = io::stdout().lock();
    while !frames.is_empty() {
        let length = u32::from_le_bytes(frames[..4].try_into().unwrap()) as usize;
        let wire = &frames[4..4 + length];
        frames = &frames[4 + length..];
        let parsed = from_slice::<DaAttestationBodyV1>(wire)
            .ok()
            .filter(|body| to_vec(body).unwrap() == wire);
        match parsed {
            Some(body) => {
                let digest = body.conflict_coordinate().expect("original public typed coordinate");
                out.write_all(&[0])?;
                out.write_all(digest.as_bytes())?;
            }
            None => out.write_all(&[100])?,
        }
    }
    out.flush()
}
