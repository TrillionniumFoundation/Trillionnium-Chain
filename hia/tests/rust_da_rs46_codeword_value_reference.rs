//! Locked public TCM1 + typed CRC1 decode, canonical encode and ID only.
use std::io::{self, ErrorKind, Read, Write};
use trnm_data_availability::cell::{
    CellContextV1, CellErrorV1, CellManifestV1, CellRs46ChunkBindingV1, CellRs46CodewordV1,
};

fn bytes<const N:usize>(raw:&[u8],p:usize)->[u8;N] {
    raw[p..p+N].try_into().unwrap()
}

fn check(wire:&[u8])->Result<[u8;300],CellErrorV1> {
    assert_eq!(&wire[..4],b"RCB1");
    let n=wire[72] as usize;
    let digest=73+n;
    let expected=CellContextV1{
        family:std::str::from_utf8(&wire[73..digest]).unwrap().to_owned(),
        base:bytes(wire,digest),parent:bytes(wire,digest+32),
        tokenizer:bytes(wire,digest+64),layout:bytes(wire,digest+96),runtime:bytes(wire,digest+128),
    };
    let m=digest+160;
    let length=u32::from_be_bytes(bytes(wire,m)) as usize;
    let at=m+4;
    let manifest=CellManifestV1::decode(&wire[at..at+length])?;
    assert_eq!(manifest.encode(),&wire[at..at+length]);
    let original=CellRs46ChunkBindingV1::from_pinned_manifest(
        &manifest,bytes(wire,8),&expected,u32::from_be_bytes(bytes(wire,4)),
    )?;
    let word=&wire[at+length..];
    let observed=CellRs46CodewordV1::decode_pinned(word,&original,bytes(wire,40))?;
    let mut out=[0;300];
    out[..32].copy_from_slice(&observed.id());
    out[32..].copy_from_slice(&observed.encode());
    assert_eq!(&out[32..],word);
    assert_eq!(&out[..32],&wire[40..72]);
    Ok(out)
}

fn main()->io::Result<()> {
    let mut input=io::stdin().lock();
    let mut output=io::stdout().lock();
    loop {
        let mut b=[0;4];
        match input.read(&mut b[..1]) {
            Ok(0)=>return Ok(()),
            Ok(1)=>input.read_exact(&mut b[1..])?,
            Ok(_)=>unreachable!(),
            Err(e) if e.kind()==ErrorKind::Interrupted=>continue,
            Err(e)=>return Err(e),
        }
        let n=u32::from_le_bytes(b) as usize;
        assert!((233..=1_048_576).contains(&n));
        let mut raw=vec![0;n];
        input.read_exact(&mut raw)?;
        match check(&raw) {
            Ok(out)=>{output.write_all(&[0])?;output.write_all(&out)?;}
            Err(CellErrorV1::Io(error)) if error.kind()==ErrorKind::UnexpectedEof=>output.write_all(&[2])?,
            Err(CellErrorV1::Invalid(reason))=>{
                let s=match reason {
                    "manifest length"=>1,"manifest version"=>3,"family length"=>4,"family encoding"=>5,
                    "chunk count"=>6,"manifest coverage"=>7,"model family"=>8,"chunk size"=>9,
                    "cell size"=>10,"chunk coverage"=>11,"chunk length"=>12,
                    "RS46 chunk index"=>13,"RS46 context pin"=>14,"RS46 manifest pin"=>15,
                    "RS46 codeword wire size"=>20,"RS46 codeword version"=>21,
                    "RS46 codeword pin"=>22,"RS46 codeword original chunk pin"=>23,
                    "RS46 codeword shard identities"=>24,
                    _=>panic!("unanticipated original CRC1 rejection: {reason}"),
                };
                output.write_all(&[s])?;
            },
            Err(e)=>panic!("unanticipated original CRC1 error: {e:?}"),
        }
    }
}
