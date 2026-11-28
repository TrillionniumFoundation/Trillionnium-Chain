//! Isolated frozen private activation reference, synthetic fixture fields only.
#[allow(dead_code)]
#[path="frozen_tile_material.rs"]
mod original;
use std::io::{self,Read,Write};

fn take_u64(frame:&[u8], at:&mut usize)->u64{
    let x=u64::from_le_bytes(frame[*at..*at+8].try_into().unwrap());
    *at+=8;
    x
}

fn main(){
    let mut raw=Vec::new();
    io::stdin().read_to_end(&mut raw).unwrap();
    let mut p=0;
    let mut out=io::stdout().lock();
    while p<raw.len(){
        let size=u32::from_le_bytes(raw[p..p+4].try_into().unwrap()) as usize;
        p+=4;
        let f=&raw[p..p+size];
        p+=size;
        assert_eq!(&f[..8],b"TAV1\0\0\0\0");
        let mut at=8;
        let shape=[take_u64(f,&mut at),take_u64(f,&mut at),take_u64(f,&mut at)];
        let lens=[take_u64(f,&mut at),take_u64(f,&mut at),take_u64(f,&mut at)];
        let hlen=take_u64(f,&mut at) as usize;
        let ids=(0..lens[0]).map(|_|take_u64(f,&mut at)).collect::<Vec<_>>();
        let masks=(0..lens[1]).map(|_|take_u64(f,&mut at)).collect::<Vec<_>>();
        let pos=(0..lens[2]).map(|_|take_u64(f,&mut at)).collect::<Vec<_>>();
        assert_eq!(at+hlen,f.len());
        let hex=std::str::from_utf8(&f[at..]).unwrap();
        let (code,output)=match original::activation_value_witness(shape,ids,masks,pos,hex) {
            Ok((n,hidden))=>{
                let mut result=(n as u64).to_le_bytes().to_vec();
                result.extend_from_slice(&hidden);
                (0u32,result)
            }
            Err(error)=>(match error {
                "ACTIVATION_SHAPE"=>1, "TOKEN_FIELDS"=>2, "ACTIVATION_BITS"=>3,
                e=>panic!("unexpected original result: {e}"),
            },Vec::new()),
        };
        out.write_all(&code.to_le_bytes()).unwrap();
        out.write_all(&(output.len() as u32).to_le_bytes()).unwrap();
        out.write_all(&output).unwrap();
    }
}
