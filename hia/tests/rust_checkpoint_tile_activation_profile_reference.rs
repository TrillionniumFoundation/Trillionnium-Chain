//! Original private activation via isolated whole frozen module and synthetic fixtures.
#[allow(dead_code)]
#[path="frozen_tile_material.rs"]
mod original;
use std::io::{self,Read,Write};

fn main() {
    let mut raw=Vec::new();
    io::stdin().read_to_end(&mut raw).unwrap();
    let mut at=0;
    let mut out=io::stdout().lock();
    while at<raw.len() {
        let n=u32::from_le_bytes(raw[at..at+4].try_into().unwrap()) as usize;
        at+=4;
        let f=&raw[at..at+n];
        at+=n;
        assert_eq!(&f[..8],b"TAP1\0\0\0\0");
        let expected=f[8..40].try_into().unwrap();
        let num=(40..80).step_by(8).map(|p|u64::from_le_bytes(f[p..p+8].try_into().unwrap())).collect::<Vec<_>>();
        let mut start=200;
        let fields=(80..200).step_by(8).map(|p| {
            let len=u64::from_le_bytes(f[p..p+8].try_into().unwrap()) as usize;
            let value=std::str::from_utf8(&f[start..start+len]).unwrap();
            start+=len;
            value
        }).collect::<Vec<_>>();
        assert_eq!(start,f.len());
        let status=match original::activation_profile_witness(expected,&num,&fields) {
            Ok((count, hidden))=>{
                assert_eq!(count,1);
                assert_eq!(hidden,vec![0;2304]);
                0u32
            }
            Err(error)=>match error {
                "ACTIVATION_PROFILE"=>1,"HASH_ENCODING"=>2,"ACTIVATION_OBSERVATION_SCOPE"=>3,
                e=>panic!("unexpected original result {e}"),
            }
        };
        out.write_all(&status.to_le_bytes()).unwrap();
    }
}
