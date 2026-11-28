//! Invokes the test-only witness in the full original frozen module.
#[allow(dead_code)]
#[path="frozen_tile_material.rs"]
mod original;
use std::io::{self, Read, Write};

fn main() {
    let mut raw=Vec::new();
    io::stdin().read_to_end(&mut raw).unwrap();
    let mut at=0;
    let mut out=io::stdout().lock();
    while at<raw.len() {
        let size=u32::from_le_bytes(raw[at..at+4].try_into().unwrap()) as usize;
        at+=4;
        let frame=&raw[at..at+size];
        at+=size;
        assert_eq!(&frame[..8],b"TMA1\0\0\0\0");
        let n=u64::from_le_bytes(frame[8..16].try_into().unwrap()) as usize;
        assert!((1..=64).contains(&n));
        assert_eq!(frame.len(),8208+2304*n);
        let value=original::assemble_witness(&frame[16..8208],&frame[8208..],n);
        let (status, bytes)=match value {
            Ok((a,b,ca,cb))=>{
                let mut bytes=(ca as u64).to_le_bytes().to_vec();
                bytes.extend_from_slice(&(cb as u64).to_le_bytes());
                bytes.extend_from_slice(&a);
                bytes.extend_from_slice(&b);
                (0u32,bytes)
            }
            Err(e)=>{assert_eq!(e,"NONFINITE");(1,Vec::new())}
        };
        out.write_all(&status.to_le_bytes()).unwrap();
        out.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
        out.write_all(&bytes).unwrap();
    }
}
