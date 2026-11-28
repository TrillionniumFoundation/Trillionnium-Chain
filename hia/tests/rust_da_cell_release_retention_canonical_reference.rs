//! Locked original public validation and commitment on owned typed metadata.
use std::io::{self, Write};
use trnm_data_availability::cell::{
    CellClosureFileV1, CellErrorV1, CellFileRoleV1, CellManifestV1,
    CellModelReleaseRootV1, CellReleaseClosureV1, CellReleaseRetentionConfigV2,
    CellReleaseRetentionContractV2, CellRetentionConfigV1, CellRetentionContractV1,
    CellTensorContractV1, CellTensorDTypeV1, CellTensorFileV1, CellTensorModelManifestV1,
    CellTensorSpecV1,
};

fn id(kind: u8, i: u16) -> [u8;32] {
    let mut out = [kind;32];
    out[30..].copy_from_slice(&i.to_be_bytes());
    out
}

fn manifest(size: u64, kind: u8, i: u16, family: &str) -> CellManifestV1 {
    let mut wire = b"TCM1".to_vec();
    wire.push(family.len().try_into().unwrap());
    wire.extend_from_slice(family.as_bytes());
    for digest in [[1;32],[2;32],[3;32],[4;32],[5;32]] {
        wire.extend_from_slice(&digest);
    }
    wire.extend_from_slice(&size.to_be_bytes());
    wire.extend_from_slice(&id(kind, i));
    wire.extend_from_slice(&16384_u32.to_be_bytes());
    let chunks = size.div_ceil(16384);
    wire.extend_from_slice(&(chunks as u32).to_be_bytes());
    for j in 0..chunks {
        wire.extend_from_slice(&((size-16384*j).min(16384) as u32).to_be_bytes());
        wire.extend_from_slice(&id(kind, i));
    }
    let m=CellManifestV1::decode(&wire).unwrap();
    assert_eq!(m.encode(),wire);
    m
}

fn model(root: CellModelReleaseRootV1) -> CellTensorModelManifestV1 {
    let files=(0..root.closure().files().len() as u16).map(|file_index|CellTensorFileV1 {
        file_index,tensors:vec![CellTensorSpecV1 {
            name:"archive.fixture".into(),dtype:CellTensorDTypeV1::F32,shape:vec![1],
        }],
    }).collect();
    let contract=CellTensorContractV1::new(root.id(),files).unwrap();
    CellTensorModelManifestV1::new(root,contract).unwrap()
}

fn fixture(sizes:&[u64],family:&str) -> (CellReleaseRetentionContractV2, CellReleaseRetentionConfigV2) {
    let mut manifests:Vec<_>=sizes.iter().enumerate()
        .map(|(i,s)|manifest(*s,0x11,i as u16,family)).collect();
    let files=manifests.iter().enumerate().map(|(i,m)|CellClosureFileV1{
        path:format!("part-{i:04}.bin"),role:CellFileRoleV1::Base, manifest:m.id(),
        payload_sha256:m.payload_sha256(),payload_bytes:m.size(),dependencies:vec![],
    }).collect();
    let closure=CellReleaseClosureV1::new(manifests[0].context().clone(),11,[51;32],
        (0..manifests.len() as u16).collect(),files).unwrap();
    let root=CellModelReleaseRootV1::new(closure,vec![]).unwrap();
    manifests.sort_by_key(|m|m.id());
    let objects=manifests.into_iter().enumerate().map(|(i,m)|{
        let size=m.size();
        CellRetentionContractV1 {
            operation:id(0xe1,i as u16),funding_operation:id(0xf1,i as u16),manifest:m,
            retain_from_height:8,retain_until_height:40,maximum_repair_bytes:size,successor:None,
        }
    }).collect();
    let value=CellReleaseRetentionContractV2 {
        operation:id(0x71,0),funding_operation:id(0x72,0),responsible_owner:id(0x73,0),
        failure_domain:id(0x74,0),replica_index:0,required_replicas:1,retain_from_height:10,
        retain_until_height:30,repair_deadline_height:20,root,tensor_model:None,objects,
    };
    let config=CellReleaseRetentionConfigV2 {
        retention:CellRetentionConfigV1{
            store_id:id(0xc1,0),capacity_bytes:1<<28,maximum_obligations:4096,
        },
        maximum_releases:128,
    };
    (value,config)
}

// TCA2 encode/decode are private. This fixture framing does not replace
// the oracle: the genuine public commitment hashes its own original encoder.
fn frame(c:&CellReleaseRetentionContractV2, config:&CellReleaseRetentionConfigV2) -> Vec<u8> {
    fn sized(w:&mut Vec<u8>, bytes:&[u8]) {
        w.extend((bytes.len() as u32).to_be_bytes());w.extend_from_slice(bytes);
    }
    let mut wire=b"NTA20001".to_vec();
    wire.extend(config.retention.store_id);
    wire.extend(config.retention.capacity_bytes.to_be_bytes());
    wire.extend(config.retention.maximum_obligations.to_be_bytes());
    wire.extend(config.maximum_releases.to_be_bytes());
    wire.extend([0;8]);
    wire.extend_from_slice(b"TCA2");
    for id in [c.operation,c.funding_operation,c.responsible_owner,c.failure_domain] {wire.extend(id);}
    wire.extend(c.replica_index.to_be_bytes());wire.extend(c.required_replicas.to_be_bytes());
    for height in [c.retain_from_height,c.retain_until_height,c.repair_deadline_height] {
        wire.extend(height.to_be_bytes());
    }
    sized(&mut wire,&c.root.encode());
    if let Some(t)=&c.tensor_model {wire.push(1);sized(&mut wire,&t.encode());} else {wire.push(0);}
    wire.extend((c.objects.len() as u16).to_be_bytes());
    for o in &c.objects {
        wire.extend(o.operation);wire.extend(o.funding_operation);
        for v in [o.retain_from_height,o.retain_until_height,o.maximum_repair_bytes] {wire.extend(v.to_be_bytes());}
        if let Some((s,x))=o.successor {wire.push(1);wire.extend(s);wire.extend(x);} else {wire.push(0);}
        sized(&mut wire,&o.manifest.encode());
    }
    wire
}

fn emit(out:&mut impl Write,c:&CellReleaseRetentionContractV2,config:&CellReleaseRetentionConfigV2,
        want:u32)->io::Result<()> {
    let actual=c.validate(config);
    let commitment=c.commitment(config);
    let (status,digest)=match actual {
        Ok(())=>(0,commitment.unwrap()),
        Err(CellErrorV1::Invalid(reason))=>{
            assert!(matches!(commitment,Err(CellErrorV1::Invalid(r)) if r==reason));
            (match reason {
                "closure unexpected manifest"=>80,"closure manifest payload"=>81,
                "archive complete dependency set"=>311,"retention configuration"=>320,
                "archive configuration"=>321,"archive duty identity"=>322,
                "archive replica declaration"=>323,"archive lease/repair deadline"=>324,
                "archive tensor model root"=>326,"retention contract"=>421,"retention successor"=>422,
                "archive canonical object order"=>423,"archive object operation/funding alias"=>424,
                "archive object lease coverage"=>425,"archive payload capacity"=>427,
                _=>panic!("unanticipated original typed error: {reason}"),
            },[0;32])
        },
        Err(e)=>panic!("unanticipated original failure: {e:?}"),
    };
    assert_eq!(status,want);
    let wire=frame(c,config);
    assert!(wire.len()<=1024*1024);
    out.write_all(&(wire.len() as u32).to_le_bytes())?;
    out.write_all(&wire)?;
    out.write_all(&status.to_le_bytes())?;
    out.write_all(&digest)
}

fn main()->io::Result<()> {
    let mut out=io::stdout().lock();
    let (base,config)=fixture(&[2024,1700,257],"Archive-2");
    emit(&mut out,&base,&config,0)?;
    for i in 0..64 {
        let mut conf=config.clone();conf.retention.store_id[i%32]^=if i<32{1}else{128};
        emit(&mut out,&base,&conf,0)?;
    }
    let mut conf=config.clone();conf.retention.capacity_bytes=4096;
    // The original archive applies raw accounting: 3981 <= 4096, unlike aligned TCA3.
    emit(&mut out,&base,&conf,0)?;
    let (too_big,_)=fixture(&[2048,2049],"Archive-2");
    emit(&mut out,&too_big,&conf,427)?;
    conf.retention.capacity_bytes=8192;emit(&mut out,&too_big,&conf,0)?;
    let (edge,_)=fixture(&[2048,2048],"Archive-2");
    conf.retention.capacity_bytes=4096;emit(&mut out,&edge,&conf,0)?;
    conf.retention.capacity_bytes=4097;emit(&mut out,&edge,&conf,320)?;

    for count in [0,1,128,129,u32::MAX] {
        let mut c=config.clone();c.maximum_releases=count;
        emit(&mut out,&base,&c,if (1..=128).contains(&count){0}else{321})?;
    }
    for i in 0..4 {
        let mut v=base.clone();
        *match i{0=>&mut v.operation,1=>&mut v.funding_operation,2=>&mut v.responsible_owner,
                 3=>&mut v.failure_domain,_=>unreachable!()}=[0;32];
        emit(&mut out,&v,&config,322)?;
    }
    for (index,count) in [(0,0),(1,1),(15,16),(16,16),(0,17),(2,4)] {
        let mut v=base.clone();v.replica_index=index;v.required_replicas=count;
        emit(&mut out,&v,&config,if (1..=16).contains(&count)&&index<count{0}else{323})?;
    }
    for (a,b,c) in [(10,10,10),(30,10,20),(10,30,9),(10,30,30),(10,30,10),(10,30,29)] {
        let mut v=base.clone();v.retain_from_height=a;v.retain_until_height=b;v.repair_deadline_height=c;
        emit(&mut out,&v,&config,if a<b&&a<=c&&c<b {0}else{324})?;
    }
    let mut v=base.clone();v.objects.pop();emit(&mut out,&v,&config,311)?;
    let mut v=base.clone();v.objects.swap(0,1);emit(&mut out,&v,&config,423)?;
    let mut v=base.clone();v.objects[0].manifest=manifest(2222,99,1,"Archive-2");emit(&mut out,&v,&config,80)?;
    let mut v=base.clone();
    let cl=v.root.closure();let mut files=cl.files().to_vec();
    files[0].payload_sha256[0]^=1;
    let root=CellReleaseClosureV1::new(cl.release().context().clone(),cl.selected_generation(),
        cl.loader_profile(),cl.roots().to_vec(),files).unwrap();
    v.root=CellModelReleaseRootV1::new(root,vec![]).unwrap();
    emit(&mut out,&v,&config,81)?;
    let mut v=base.clone();v.objects[0].operation=[0;32];emit(&mut out,&v,&config,421)?;
    let mut v=base.clone();v.objects[0].maximum_repair_bytes=0;emit(&mut out,&v,&config,425)?;
    let mut v=base.clone();v.objects[0].retain_from_height=11;emit(&mut out,&v,&config,425)?;
    let mut v=base.clone();v.objects[0].retain_until_height=29;emit(&mut out,&v,&config,425)?;
    let mut v=base.clone();v.objects[0].successor=Some((id(0x91,1),id(0x92,1)));
    emit(&mut out,&v,&config,0)?;
    v.objects[0].successor=Some((config.retention.store_id,id(0x92,1)));
    emit(&mut out,&v,&config,422)?;
    let mut v=base.clone();v.objects[1].operation=v.objects[0].operation;emit(&mut out,&v,&config,424)?;
    let mut v=base.clone();v.objects[1].funding_operation=v.objects[0].funding_operation;emit(&mut out,&v,&config,424)?;
    // Original typed precedence holds across fields, root, and objects.
    v.responsible_owner=[0;32];emit(&mut out,&v,&config,322)?;
    let mut c=config.clone();c.maximum_releases=0;emit(&mut out,&v,&c,321)?;
    c.retention.maximum_obligations=0;emit(&mut out,&v,&c,320)?;
    let mut v=base.clone();v.tensor_model=Some(model(v.root.clone()));emit(&mut out,&v,&config,0)?;
    let other=CellModelReleaseRootV1::new(v.root.closure().clone(),vec![id(0x91,0)]).unwrap();
    v.tensor_model=Some(model(other));v.required_replicas=0;
    emit(&mut out,&v,&config,326)?;
    let (big,c)=fixture(&[17;256],&"A".repeat(64));emit(&mut out,&big,&c,0)?;
    let (dense,c)=fixture(&[12288,8192,((16384_u64*10000)-37)],"Archive-2");
    emit(&mut out,&dense,&c,0)?;
    Ok(())
}
