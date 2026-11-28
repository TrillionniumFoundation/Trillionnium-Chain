//! Detached V6 identities from inert digest labels. No allocations or releases are executed.
use std::io::{self, Write};
use trnm_mvcc_fee::{model_source_composition_v6::{allocation_root, release_id}, pon_executor::Config};

type Hash = [u8; 32];

fn emit(out: &mut impl Write, status: u32, packet: &[u8], digest: Hash) {
    out.write_all(&status.to_le_bytes()).unwrap();
    out.write_all(&(packet.len() as u32).to_le_bytes()).unwrap();
    out.write_all(packet).unwrap();
    out.write_all(&digest).unwrap();
}

fn root(out: &mut impl Write, leaves: &[Hash]) {
    let (status, digest) = match allocation_root(leaves.to_vec()) {
        Ok(root) => (0, root),
        Err(e) => { assert_eq!(e,"MODEL_SOURCE_COUNT"); (1,[0;32]) }
    };
    let mut packet = b"AV61\0\0\0\0".to_vec();
    packet.extend_from_slice(&(leaves.len() as u64).to_le_bytes());
    for h in leaves { packet.extend_from_slice(h); }
    emit(out,status,&packet,digest);
}

fn release(out: &mut impl Write, cfg: &Config, parent: Hash, bundle: Hash, budget: u64, root: Hash, total: u64) {
    let mut packet = b"RV61\0\0\0\0".to_vec();
    for x in [cfg.network,cfg.parameters,parent,bundle] { packet.extend_from_slice(&x); }
    packet.extend_from_slice(&budget.to_le_bytes());
    packet.extend_from_slice(&root);
    packet.extend_from_slice(&total.to_le_bytes());
    emit(out,0,&packet,release_id(cfg,parent,bundle,budget,root,total));
}

fn main() {
    let mut out = io::stdout().lock();
    let a = [0xff;32];
    let mut b = a; b[31]=0xfe;
    let c = [1;32];
    let mut d = c; d[0]=2;
    for leaves in [vec![], vec![[0;32]], vec![a,b], vec![b,a], vec![a,b,c],
                   vec![a,b,c,c], vec![a,c,b,d], vec![a,b,c,d], vec![a,b,c,d,c]] {
        root(&mut out,&leaves);
    }

    let mut cfg=Config::installed().unwrap();
    cfg.network=[0x31;32]; cfg.parameters=[0x57;32];
    let r = allocation_root(vec![a,b,c]).unwrap();
    release(&mut out,&cfg,[0;32],[0;32],0,[0;32],0);
    release(&mut out,&cfg,a,b,u64::MAX,r,1);
    release(&mut out,&cfg,a,b,1,r,u64::MAX);
    release(&mut out,&cfg,b,a,u64::MAX,r,1);
    release(&mut out,&cfg,a,b,u64::MAX,d,1);
    cfg.parameters[31]^=1;
    release(&mut out,&cfg,a,b,u64::MAX,r,1);
    cfg.network[31]^=1;
    release(&mut out,&cfg,a,b,u64::MAX,r,1);
}
