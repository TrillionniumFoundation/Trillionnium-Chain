//! Pure original Cargo decode + commitment over owned synthetic declarations.
use std::io::{self, Write};
use trnm_data_availability::cell::{
    CellClosureFileV1, CellErrorV1, CellFileRoleV1, CellManifestV1,
    CellModelReleaseRootV1, CellReleaseClosureV1, CellRetentionConfigV1, CellRetentionContractV1,
    CellVersionLoaderPinV3, CellVersionManifestV1, CellVersionRetentionConfigV3,
    CellVersionRetentionContractV3, CellVersionSnapshotLinkV3, CellTensorContractV1,
    CellTensorDTypeV1, CellTensorFileV1, CellTensorModelManifestV1, CellTensorSpecV1,
};

fn id(kind: u8, i: u16) -> [u8;32] {
    let mut out = [kind;32];
    out[30..].copy_from_slice(&i.to_be_bytes());
    out
}

fn manifest(runtime: [u8;32], size: u64, kind: u8, i: u16) -> CellManifestV1 {
    let family = b"Retained-Test";
    let mut wire = b"TCM1".to_vec();
    wire.push(family.len().try_into().unwrap());
    wire.extend_from_slice(family);
    for digest in [[1;32],[2;32],[3;32],[4;32],runtime] {
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
    CellManifestV1::decode(&wire).unwrap()
}

fn fixture(
    env_sizes: &[u64], model_sizes: &[u64],
) -> (CellVersionRetentionContractV3, CellVersionRetentionConfigV3) {
    fn closure(
        manifests: &[CellManifestV1], role: CellFileRoleV1, generation: u64,
    ) -> (CellReleaseClosureV1, CellVersionLoaderPinV3) {
        let files = manifests.iter().enumerate().map(|(i,m)| CellClosureFileV1 {
            path: format!("part-{i:04}.bin"), role, manifest: m.id(),
            payload_sha256: m.payload_sha256(), payload_bytes: m.size(), dependencies: vec![],
        }).collect();
        let owners = (0..manifests.len() as u16).collect();
        let x = CellReleaseClosureV1::new(
            manifests[0].context().clone(), generation, [51;32], owners, files,
        ).unwrap();
        let pin = CellVersionLoaderPinV3 {
            closure_id: x.id(), context: x.release().context().clone(),
            selected_generation: x.selected_generation(), loader_profile: x.loader_profile(),
            required_roles: vec![role], max_payload_bytes: 1<<32, max_chunks: 1<<22,
        };
        (x,pin)
    }
    let env: Vec<_> = env_sizes.iter().enumerate().map(|(i,n)| manifest([70;32], *n, 0x11, i as u16)).collect();
    let (environment, env_pin) = closure(&env, CellFileRoleV1::Configuration, 11);
    let model: Vec<_> = model_sizes.iter().enumerate().map(|(i,n)| manifest(environment.id(), *n, 0x22, i as u16)).collect();
    let (model_closure, model_pin) = closure(&model, CellFileRoleV1::Base, 17);
    let mut manifests: Vec<_> = env.into_iter().chain(model).collect();
    manifests.sort_by_key(CellManifestV1::id);
    let version = CellVersionManifestV1::new(
        CellModelReleaseRootV1::new(model_closure, vec![]).unwrap(), environment, manifests,
    ).unwrap();
    let objects = version.manifests().iter().enumerate().map(|(i,m)| CellRetentionContractV1 {
        operation: id(0xe1,i as u16), funding_operation: id(0xf1,i as u16), manifest: m.clone(),
        retain_from_height: 8, retain_until_height: 40, maximum_repair_bytes: m.size(),
        successor: None,
    }).collect();
    let config = CellVersionRetentionConfigV3 {
        retention: CellRetentionConfigV1 {
            store_id: id(0xc1,0), capacity_bytes: 1<<28, maximum_obligations: 4096,
        },
        maximum_versions: 128, maximum_metadata_bytes: 64<<20,
    };
    let value = CellVersionRetentionContractV3 {
        operation: id(0x71,0), funding_operation: id(0x72,0),
        responsible_owner: id(0x73,0), failure_domain: id(0x74,0),
        replica_index: 0, required_replicas: 1, retain_from_height: 10, retain_until_height: 30,
        repair_deadline_height: 20, version, model: model_pin, environment: env_pin,
        tensor_model: None, snapshot: None, objects,
    };
    (value,config)
}

fn shape(value:&CellVersionRetentionContractV3) -> (usize,usize,usize,usize,usize) {
    fn pin_len(pin:&CellVersionLoaderPinV3) -> usize {
        234 + 8 + 8 + pin.context.family.len() + pin.required_roles.len()
    }
    let model = 164 + value.version.encode().len();
    let env=model+pin_len(&value.model);
    let tensor=env+pin_len(&value.environment);
    let link=tensor+1+value.tensor_model.as_ref().map_or(0,|p|4+p.encode().len());
    let first=link+1+value.snapshot.as_ref().map_or(0,|_|112)+2;
    (model,env,tensor,link,first)
}

fn emit(out:&mut impl Write, wire:&[u8], config:&CellVersionRetentionConfigV3, expected:u32) -> io::Result<()> {
    let (status,dig) = match CellVersionRetentionContractV3::decode(wire,config) {
        Ok(value) => {
            assert_eq!(value.encode(config).unwrap(),wire);
            (0,value.commitment(config).unwrap())
        },
        Err(CellErrorV1::Invalid(reason)) => (match reason {
            "version retention contract namespace"=>300,
            "version retention truncated contract"=>301,
            "version retention family size"=>303,
            "version retention family encoding"=>304,
            "version retention role size"=>305,
            "version retention role encoding"=>306,
            "model family"=>307,
            "version retention loader policy"=>308,
            "version retention tensor plan tag"=>309,
            "version retention snapshot tag"=>310,
            "version retention complete dependency set"=>311,
            "version retention successor tag"=>312,
            "version retention trailing contract"=>313,
            "retention configuration"=>320,
            "version retention configuration"=>321,
            "version retention identity"=>322,
            "version retention replica declaration"=>323,
            "version retention lease/repair deadline"=>324,
            "version retention snapshot link"=>325,
            "version retention tensor root"=>326,
            "closure loader context"=>60,
            "closure missing required role"=>63,
            "closure payload budget"=>64,
            "version owner chunk budget"=>66,
            "retention contract"=>421,
            "retention successor"=>422,
            "version retention canonical object coverage"=>423,
            "version retention object identity alias"=>424,
            "version retention object lease coverage"=>425,
            "version retention operation/funding alias"=>426,
            "version retention physical capacity"=>427,
            "version magic"=>616,
            _=>panic!("unexpected original rejection {reason}"),
        },[0;32]),
        Err(error)=>panic!("unexpected original error {error:?}"),
    };
    assert_eq!(status,expected);
    let mut frame=b"NTA30001".to_vec();
    frame.extend(config.retention.store_id);
    frame.extend(config.retention.capacity_bytes.to_be_bytes());
    frame.extend(config.retention.maximum_obligations.to_be_bytes());
    frame.extend(config.maximum_versions.to_be_bytes());
    frame.extend(config.maximum_metadata_bytes.to_be_bytes());
    frame.extend(wire);
    assert!(frame.len() <= 1024*1024);
    out.write_all(&(frame.len() as u32).to_le_bytes())?;
    out.write_all(&frame)?;
    out.write_all(&status.to_le_bytes())?;
    out.write_all(&dig)
}

fn replace(src:&[u8], at:usize, value:&[u8])->Vec<u8> {
    let mut dest=src.to_vec();
    dest[at..at+value.len()].copy_from_slice(value);
    dest
}

fn tensor(root:CellModelReleaseRootV1) -> CellTensorModelManifestV1 {
    let contract=CellTensorContractV1::new(root.id(),vec![CellTensorFileV1 {
        file_index:0,tensors:vec![CellTensorSpecV1 {
            name:"typed.fixture".into(), dtype:CellTensorDTypeV1::F32, shape:vec![1],
        }],
    }]).unwrap();
    CellTensorModelManifestV1::new(root,contract).unwrap()
}

fn main() -> io::Result<()> {
    let mut out=io::stdout().lock();
    let (base,cfg)=fixture(&[17409,16385],&[567,32770,243]);
    let good=base.encode(&cfg).unwrap();
    let (m,e,t,l,obj)=shape(&base);
    assert_eq!(good[t],0); assert_eq!(good[l],0);
    assert_eq!(&good[obj..obj+32],&base.objects[0].operation);
    emit(&mut out,&good,&cfg,0)?;
    for i in 0..64 {
        let mut c=cfg.clone();
        c.retention.store_id[i%32] ^= if i<32 {1} else {128};
        emit(&mut out,&good,&c,0)?;
    }
    for &(at,code) in &[(0,300),(164,616),(t,309),(l,310),(l+2,311),(obj+88,312)] {
        emit(&mut out,&replace(&good,at,&[0xff]),&cfg,code)?;
    }
    for n in [0,1,3,4,80,155,160,163,164,m,e,t,l,obj,obj+10,obj+88,obj+89,good.len()-1] {
        emit(&mut out,&good[..n],&cfg,301)?;
    }
    let mut trailing=good.clone(); trailing.push(0); emit(&mut out,&trailing,&cfg,313)?;
    for &(at,field) in &[(m,&base.model),(e,&base.environment)] {
        let after_family=at+33+field.context.family.len();
        let role_len=after_family+200;
        let role=role_len+1;
        let caps=role+field.required_roles.len();
        for &(at,bad,want) in &[(at+32,0,303),(at+32,65,303),(at+33,0xff,304),
          (at+33,b'/',307),(role_len,0,305),(role_len,7,305),(role,7,306),(role,0,306)] {
            emit(&mut out,&replace(&good,at,&[bad]),&cfg,want)?;
        }
        for &(idx,want) in &[(caps,308),(caps+8,308)] {
            emit(&mut out,&replace(&good,idx,&[0;8]),&cfg,want)?;
        }
        for diff in [0,8,31,33,34,35,after_family-at,after_family-at+41,after_family-at+160,after_family-at+168] {
            let pos=at+diff;
            emit(&mut out,&replace(&good,pos,&[good[pos]^1]),&cfg,60)?;
        }
        // Positive declared limits, but insufficient for this closure only.
        emit(&mut out,&replace(&good,caps,&1_u64.to_be_bytes()),&cfg,64)?;
        emit(&mut out,&replace(&good,caps+8,&1_u64.to_be_bytes()),&cfg,66)?;
        emit(&mut out,&replace(&good,role,&[5]),&cfg,63)?;
    }
    let mut c=cfg.clone(); c.retention.capacity_bytes=4095; emit(&mut out,&good,&c,320)?;
    let mut c=cfg.clone(); c.maximum_metadata_bytes=0; emit(&mut out,&good,&c,321)?;
    let mut c=cfg.clone(); c.retention.capacity_bytes=4096; emit(&mut out,&good,&c,427)?;
    emit(&mut out,&replace(&good,4,&[0;32]),&cfg,322)?;
    emit(&mut out,&replace(&good,132,&[0,1]),&cfg,323)?;
    emit(&mut out,&replace(&good,152,&30_u64.to_be_bytes()),&cfg,324)?;
    emit(&mut out,&replace(&good,obj,&[0;32]),&cfg,421)?;
    emit(&mut out,&replace(&good,obj,&base.operation),&cfg,424)?;
    emit(&mut out,&replace(&good,obj,&base.funding_operation),&cfg,426)?;
    emit(&mut out,&replace(&good,obj+80,&0_u64.to_be_bytes()),&cfg,425)?;
    let size_pos=obj+89;
    let clen=u32::from_be_bytes(good[size_pos..size_pos+4].try_into().unwrap()) as usize;
    let a=size_pos+4;
    let d=6+base.objects[0].manifest.context().family.len()+160+8;
    assert!(d < clen);
    emit(&mut out,&replace(&good,a+d,&[good[a+d]^7]),&cfg,423)?;
    let mut v=base.clone();
    v.objects[0].successor=Some((id(0x88,1),id(0x89,2)));
    let with_successor=v.encode(&cfg).unwrap();
    emit(&mut out,&with_successor,&cfg,0)?;
    emit(&mut out,&replace(&with_successor,obj+89,&cfg.retention.store_id),&cfg,422)?;
    let mut v=base.clone();
    v.snapshot=Some(CellVersionSnapshotLinkV3 {
        schedule:id(0x91,0),ordinal:2,due_height:19,
        predecessor_operation:id(0x92,0),predecessor_contract:id(0x93,0),
    });
    let with_snapshot=v.encode(&cfg).unwrap();
    emit(&mut out,&with_snapshot,&cfg,0)?;
    emit(&mut out,&replace(&with_snapshot,l+41,&30_u64.to_be_bytes()),&cfg,325)?;
    emit(&mut out,&replace(&with_snapshot,l+49,&base.operation),&cfg,325)?;
    let (mut v,c)=fixture(&[57],&[256]);
    v.tensor_model=Some(tensor(v.version.model().clone()));
    let matching=v.encode(&c).unwrap();
    let (_,_,tt,_,_)=shape(&v);
    emit(&mut out,&matching,&c,0)?;
    let bad_root=CellModelReleaseRootV1::new(v.version.model().closure().clone(),vec![id(0x77,0)]).unwrap();
    let other=tensor(bad_root).encode();
    let width=u32::from_be_bytes(matching[tt+1..tt+5].try_into().unwrap()) as usize;
    let mut mismatched=matching[..tt+1].to_vec();
    mismatched.extend((other.len() as u32).to_be_bytes());
    mismatched.extend(&other);
    mismatched.extend(&matching[tt+5+width..]);
    emit(&mut out,&mismatched,&c,326)?;
    // Decoder fields outrank config; then before TMA root equality, the TCV pins.
    let mut c_bad=c.clone(); c_bad.maximum_versions=0;
    emit(&mut out,&mismatched,&c_bad,321)?;
    let (mp,_,_,_,_)=shape(&v);
    emit(&mut out,&replace(&mismatched,mp,&[mismatched[mp]^1]),&c,60)?;
    emit(&mut out,&replace(&mismatched,tt,&[2]),&c_bad,309)?;
    let (v,c)=fixture(&[1;256],&[1;256]);
    emit(&mut out,&v.encode(&c).unwrap(),&c,0)?;
    Ok(())
}
