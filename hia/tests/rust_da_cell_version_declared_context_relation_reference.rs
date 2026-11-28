//! Real public Cargo original, declared synthetic metadata only; no actual loader.
use std::io::{self, Write};
use trnm_data_availability::cell::{
    CellClosureFileV1, CellContextV1, CellErrorV1, CellFileRoleV1, CellLoaderContextV1,
    CellManifestV1, CellModelReleaseRootV1, CellReleaseClosureV1, CellVersionLoaderContextV1,
    CellVersionManifestV1,
};

const ROLES: [CellFileRoleV1; 6] = [
    CellFileRoleV1::Base, CellFileRoleV1::Tokenizer, CellFileRoleV1::Preprocessor,
    CellFileRoleV1::Adapter, CellFileRoleV1::Router, CellFileRoleV1::Configuration,
];
const CHUNK:u32 = 16384;

fn manifest(c: &CellContextV1, count: usize, fixture: u16) -> CellManifestV1 {
    // Exact actual public decoder, not a copied validation or generated payload.
    let mut bytes = b"TCM1".to_vec();
    bytes.push(c.family.len() as u8);
    bytes.extend_from_slice(c.family.as_bytes());
    for field in [c.base,c.parent,c.tokenizer,c.layout,c.runtime] { bytes.extend(field); }
    bytes.extend((u64::from(CHUNK)*count as u64).to_be_bytes());
    let mut digest = [57;32];
    digest[..2].copy_from_slice(&fixture.to_be_bytes());
    bytes.extend(digest);
    bytes.extend(CHUNK.to_be_bytes());
    bytes.extend((count as u32).to_be_bytes());
    for i in 0..count {
        bytes.extend(CHUNK.to_be_bytes());
        let mut leaf=[91;32];
        leaf[..2].copy_from_slice(&(i as u16).to_be_bytes());
        bytes.extend(leaf);
    }
    let parsed=CellManifestV1::decode(&bytes).unwrap();
    assert_eq!(parsed.encode(),bytes);
    parsed
}

fn closure(c: CellContextV1, counts: &[usize], is_env: bool)
    -> (Vec<CellManifestV1>,CellReleaseClosureV1,CellLoaderContextV1) {
    let ms:Vec<_> = counts.iter().enumerate()
        .map(|(i,&n)|manifest(&c,n,(if is_env{512}else{0})+i as u16)).collect();
    let files=ms.iter().enumerate().map(|(i,m)|CellClosureFileV1 {
        path:format!("data-{i:04}.bin"),
        role:if is_env{CellFileRoleV1::Configuration}else{ROLES[i%ROLES.len()]},
        manifest:m.id(),payload_sha256:m.payload_sha256(),payload_bytes:m.size(),dependencies:vec![],
    }).collect();
    let generation=if is_env {23} else {19};
    let profile=[if is_env{15}else{16};32];
    let value=CellReleaseClosureV1::new(c.clone(),generation,profile,(0..ms.len() as u16).collect(),files).unwrap();
    let expected=CellLoaderContextV1 {
        closure_id:value.id(),context:c,selected_generation:generation,loader_profile:profile,
        max_payload_bytes:ms.iter().map(|m|m.size()).sum(),
        max_chunks:counts.iter().sum::<usize>() as u64,
        required_roles:vec![if is_env {CellFileRoleV1::Configuration}else{CellFileRoleV1::Base}],
    };
    (ms,value,expected)
}

fn fixture(mc:&[usize],ec:&[usize],family:&str)
    -> (CellVersionManifestV1,CellLoaderContextV1,CellLoaderContextV1) {
    let env_ctx=CellContextV1 {
        family:family.to_owned(),base:[1;32],parent:[2;32],tokenizer:[3;32],layout:[4;32],runtime:[5;32],
    };
    let (es,ev,x)=closure(env_ctx,ec,true);
    let model_ctx=CellContextV1 {
        family:family.to_owned(),base:[6;32],parent:[7;32],tokenizer:[8;32],layout:[9;32],runtime:ev.id(),
    };
    let (mut ms,mv,y)=closure(model_ctx,mc,false);
    let root=CellModelReleaseRootV1::new(mv,vec![]).unwrap();
    ms.extend(es);
    ms.sort_by_key(|m|m.id());
    let whole=CellVersionManifestV1::new(root,ev,ms).unwrap();
    (whole,y,x)
}

fn append(target:&mut Vec<u8>, x:&CellLoaderContextV1) {
    let start=target.len();
    target.extend([0u8;4]);
    target.extend_from_slice(b"VRLC0001");
    target.extend_from_slice(&x.closure_id);
    target.extend(x.selected_generation.to_be_bytes());
    target.extend_from_slice(&x.loader_profile);
    target.extend(x.max_payload_bytes.to_be_bytes());
    target.extend(x.max_chunks.to_be_bytes());
    target.extend((x.context.family.len() as u16).to_be_bytes());
    target.extend((x.required_roles.len() as u16).to_be_bytes());
    for id in [x.context.base,x.context.parent,x.context.tokenizer,x.context.layout,x.context.runtime] {
        target.extend_from_slice(&id);
    }
    target.extend_from_slice(x.context.family.as_bytes());
    for r in &x.required_roles { target.push(*r as u8); }
    let len=target.len()-start-4;
    target[start..start+4].copy_from_slice(&(len as u32).to_be_bytes());
}

fn emit(out:&mut impl Write, v:&CellVersionManifestV1, m:&CellLoaderContextV1, e:&CellLoaderContextV1,
        broken_commitment:Option<usize>, want:u8) -> io::Result<()> {
    let mut packet=v.encode();
    let original=CellVersionManifestV1::decode(&packet).unwrap();
    let len=packet.len();
    assert_eq!(original.encode(),packet);
    let mut commitment=original.commitment();
    if let Some(i)=broken_commitment { commitment[i]^=0x80; }
    let x=CellVersionLoaderContextV1{commitment,model:m,environment:e};
    let status=match original.verify_for_loader(&x) {
        Ok(())=>0,
        Err(CellErrorV1::Invalid(reason))=>match reason {
            "closure loader context"=>60,"closure loader budget"=>61,"closure required roles"=>62,
            "closure missing required role"=>63,"closure payload budget"=>64,
            "version owner commitment"=>65,"version owner chunk budget"=>66,
            _=>panic!("unexpected original error: {reason}"),
        },
        Err(error)=>panic!("unexpected original error: {error:?}"),
    };
    assert_eq!(status,want);
    packet.extend(commitment);
    append(&mut packet,m);
    append(&mut packet,e);
    packet.extend((len as u32).to_be_bytes());
    assert!(packet.len()<=1024*1024);
    out.write_all(&(packet.len() as u32).to_le_bytes())?;
    out.write_all(&packet)?;
    out.write_all(&[status])
}

fn main() -> io::Result<()> {
    let mut out=io::stdout().lock();
    let (v,m,e)=fixture(&[1,3,2,4,1,5],&[2,7,6],"Declared-1");
    emit(&mut out,&v,&m,&e,None,0)?;
    for i in 0..64 { emit(&mut out,&v,&m,&e,Some(i),65)?; }
    for mask in 1usize..64 {
        let mut mm=m.clone();
        mm.required_roles=ROLES.iter().copied().enumerate().rev()
           .filter_map(|(i,r)|if mask&(1<<i)==0{None}else{Some(r)}).collect();
        emit(&mut out,&v,&mm,&e,None,0)?;
    }
    for model in [true,false] {
        for kind in 0..17 {
            let (mut mm,mut ee)=(m.clone(),e.clone());
            let p=if model{&mut mm}else{&mut ee};
            let want=match kind {
                0=>{p.closure_id[0]^=1;60}
                1=>{p.context.base[3]^=1;60}
                2=>{p.context.parent[9]^=1;60}
                3=>{p.context.tokenizer[31]^=1;60}
                4=>{p.context.layout[17]^=1;60}
                5=>{p.context.runtime[23]^=1;60}
                6=>{p.context.family.push('x');60}
                7=>{p.context.family="模型🙂".to_owned();60}
                8=>{p.loader_profile[3]^=1;60}
                9=>{p.selected_generation+=1;60}
                10=>{p.max_chunks=0;61}
                11=>{p.max_payload_bytes=0;61}
                12=>{p.required_roles.clear();62}
                13=>{p.required_roles.push(p.required_roles[0]);62}
                14=>{p.max_payload_bytes-=1;64}
                15=>{p.max_chunks-=1;66}
                16=>{p.max_chunks=u64::MAX;0}
                _=>unreachable!(),
            };
            emit(&mut out,&v,&mm,&ee,None,want)?;
        }
    }
    let mut mm=m.clone(); let mut ee=e.clone();
    // Preserve source order: global before either context, model before environmental,
    // both local contexts before checking either aggregate chunk cap.
    ee.required_roles=vec![CellFileRoleV1::Router]; mm.max_chunks-=1;
    emit(&mut out,&v,&mm,&ee,None,63)?;
    mm.max_payload_bytes-=1;
    emit(&mut out,&v,&mm,&ee,None,64)?;
    emit(&mut out,&v,&mm,&ee,Some(9),65)?;
    mm.max_chunks=0;
    emit(&mut out,&v,&mm,&ee,None,61)?;
    mm.closure_id[9]^=1;
    emit(&mut out,&v,&mm,&ee,None,60)?;

    // Very unequal caps and membership: neither pool may borrow the other's excess.
    for (mc,ec) in [(1,35),(36,1),(33,46),(46,33),(8192,1),(1,8192)] {
        let (v,m,e)=fixture(&[mc],&[ec],&"A".repeat(64));
        emit(&mut out,&v,&m,&e,None,0)?;
        if m.max_chunks>1 {
            let mut mm=m.clone(); mm.max_chunks-=1; emit(&mut out,&v,&mm,&e,None,66)?;
        }
        if e.max_chunks>1 {
            let mut ee=e.clone(); ee.max_chunks-=1; emit(&mut out,&v,&m,&ee,None,66)?;
        }
    }
    let (v,m,e)=fixture(&[1;256],&[1;256],"Full-512");
    assert_eq!(v.manifests().len(),512);
    emit(&mut out,&v,&m,&e,None,0)?;
    let mut ee=e.clone(); ee.max_chunks-=1;
    emit(&mut out,&v,&m,&ee,None,66)?;
    Ok(())
}
