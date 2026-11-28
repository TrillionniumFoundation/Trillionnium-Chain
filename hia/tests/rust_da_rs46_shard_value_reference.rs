//! Original public CRS1 immutable shard API; no coding, retrieval or storage.
use std::io::{self, ErrorKind, Read, Write};
use trnm_data_availability::cell::{CellErrorV1, CellRs46ShardV1};

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
        assert!(n<=1_048_658);
        let mut raw=vec![0;n];
        input.read_exact(&mut raw)?;
        match CellRs46ShardV1::decode(&raw) {
            Ok(shard)=>{
                let canonical=shard.encode();
                assert_eq!(canonical,raw);
                assert_eq!(shard.index(),canonical[76]);
                assert_eq!(shard.payload(),&canonical[81..]);
                output.write_all(&[0])?;
                output.write_all(&shard.id())?;
                output.write_all(&canonical[..81])?;
            },
            Err(CellErrorV1::Invalid(reason))=>{
                let status=match reason {
                    "RS46 shard wire size"=>1,"RS46 shard version"=>2,
                    "RS46 source size"=>3,"RS46 shard index"=>4,
                    "RS46 shard coverage"=>5,
                    _=>panic!("unexpected original shard rejection: {reason}"),
                };
                output.write_all(&[status])?;
            },
            Err(error)=>panic!("unexpected original shard error: {error:?}"),
        }
    }
}
