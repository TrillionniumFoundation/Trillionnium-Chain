//! Isolated original full module plus a forwarding witness only. No checkpoint file.
#[allow(dead_code)]
#[path = "frozen_tile_material.rs"]
mod original;

use std::io::{self, Read, Write};

fn main() {
    let mut data=Vec::new();
    io::stdin().read_to_end(&mut data).unwrap();
    assert_eq!(data.len()%5,0);
    let mut out=io::stdout().lock();
    for row in data.chunks_exact(5) {
        let bits=u32::from_le_bytes(row[1..].try_into().unwrap());
        let profile=row[0];
        assert!(profile==1 || profile==2);
        let (value,status)=match original::quantize_witness(bits,profile) {
            Ok((value,clipped))=>(value,u64::from(clipped)),
            Err(error)=>{assert_eq!(error,"NONFINITE"); (0,2)}
        };
        out.write_all(&value.to_le_bytes()).unwrap();
        out.write_all(&status.to_le_bytes()).unwrap();
    }
}
