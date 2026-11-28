//! Real immutable Rust validate on declared in-memory graph/TCM1 objects only.
use std::io::{self, Write};
use trnm_data_availability::cell::{
    CellClosureFileV1, CellErrorV1, CellFileRoleV1, CellManifestV1,
    CellModelReleaseRootV1, CellReleaseClosureV1, CellRetentionConfigV1, CellRetentionContractV1,
    CellVersionLoaderPinV3, CellVersionManifestV1, CellVersionRetentionConfigV3,
    CellVersionRetentionContractV3,
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

fn encode(x: &CellVersionRetentionContractV3, c: &CellVersionRetentionConfigV3) -> Vec<u8> {
    fn sized(out: &mut Vec<u8>, m: &CellManifestV1) {
        let m=m.encode();
        out.extend_from_slice(&(m.len() as u32).to_be_bytes());
        out.extend_from_slice(&m);
    }
    let mut out = b"NTO30001".to_vec();
    out.extend_from_slice(&c.retention.store_id);
    out.extend_from_slice(&c.retention.capacity_bytes.to_be_bytes());
    out.extend_from_slice(&x.operation);
    out.extend_from_slice(&x.funding_operation);
    out.extend_from_slice(&x.retain_from_height.to_be_bytes());
    out.extend_from_slice(&x.retain_until_height.to_be_bytes());
    out.extend_from_slice(&(x.version.manifests().len() as u16).to_be_bytes());
    out.extend_from_slice(&(x.objects.len() as u16).to_be_bytes());
    for (reference, obj) in x.version.manifests().iter().zip(&x.objects) {
        sized(&mut out, reference);
        out.extend_from_slice(&obj.operation);
        out.extend_from_slice(&obj.funding_operation);
        for h in [obj.retain_from_height,obj.retain_until_height,obj.maximum_repair_bytes] {
            out.extend_from_slice(&h.to_be_bytes());
        }
        if let Some((store,operation)) = obj.successor {
            out.push(1);
            out.extend_from_slice(&store);
            out.extend_from_slice(&operation);
        } else { out.push(0); }
        sized(&mut out,&obj.manifest);
    }
    out
}

fn emit(
    out: &mut impl Write, x: &CellVersionRetentionContractV3,
    c: &CellVersionRetentionConfigV3, intended: u8,
) -> io::Result<()> {
    let actual = match x.validate(c) {
        Ok(()) => 0,
        Err(CellErrorV1::Invalid(reason)) => match reason {
            "version retention complete dependency set" => 20,
            "retention contract" => 21,
            "retention successor" => 22,
            "version retention canonical object coverage" => 23,
            "version retention object identity alias" => 24,
            "version retention object lease coverage" => 25,
            "version retention operation/funding alias" => 26,
            "version retention physical capacity" => 27,
            _ => panic!("fixture reached unexpected original condition: {reason}"),
        },
        Err(e) => panic!("fixture reached unexpected original error: {e:?}"),
    };
    assert_eq!(actual,intended);
    let value = encode(x,c);
    out.write_all(&(value.len() as u32).to_le_bytes())?;
    out.write_all(&value)?;
    out.write_all(&[actual])
}

fn main() -> io::Result<()> {
    let mut out = io::stdout().lock();
    let (x,c) = fixture(&[1,4095,4096],&[4097,8192,8193,16385]);
    emit(&mut out,&x,&c,0)?;
    for i in 0..x.objects.len() {
        let mut a=x.clone();
        a.objects[i].successor=Some((id(0xc2,i as u16),id(0x75,i as u16)));
        emit(&mut out,&a,&c,0)?;
        for case in 0..16 {
            let mut b=a.clone();
            let status;
            match case {
                0 => { b.objects[i].operation=[0;32]; status=21; },
                1 => { b.objects[i].funding_operation=[0;32]; status=21; },
                2 => { b.objects[i].retain_until_height=0; status=21; },
                3 => { b.objects[i].maximum_repair_bytes=u64::MAX; status=21; },
                4 => { b.objects[i].successor=Some((c.retention.store_id,id(0x75,0))); status=22; },
                5 => { b.objects[i].successor=Some(([0;32],id(0x75,0))); status=22; },
                6 => { b.objects[i].successor=Some((id(0xc2,0),[0;32])); status=22; },
                7 => { b.objects[i].manifest=x.objects[(i+1)%x.objects.len()].manifest.clone(); status=23; },
                8 => { b.objects[i].operation=x.operation; status=24; },
                9 => { b.objects[i].funding_operation=x.funding_operation; status=24; },
                10 => { b.objects[i].retain_from_height=11; status=25; },
                11 => { b.objects[i].retain_until_height=29; status=25; },
                12 => { b.objects[i].maximum_repair_bytes-=1; status=25; },
                13 => { b.objects[i].operation=x.funding_operation; status=26; },
                14 => { b.objects[i].funding_operation=x.operation; status=26; },
                15 => { b.objects[i].operation=id(0xd1,99); b.objects[i].funding_operation=id(0xd1,99); status=26; },
                _ => unreachable!(),
            }
            emit(&mut out,&b,&c,status)?;
        }
    }
    let mut b=x.clone(); b.objects.reverse(); emit(&mut out,&b,&c,23)?;
    let mut b=x.clone(); b.objects.truncate(3); emit(&mut out,&b,&c,20)?;
    let mut b=x.clone(); b.objects.push(x.objects[0].clone()); emit(&mut out,&b,&c,20)?;
    let mut b=x.clone(); b.objects[1].operation=b.objects[0].operation; emit(&mut out,&b,&c,24)?;
    let mut b=x.clone(); b.objects[1].funding_operation=b.objects[0].funding_operation; emit(&mut out,&b,&c,24)?;
    let mut b=x.clone(); b.objects[1].funding_operation=b.objects[0].operation; emit(&mut out,&b,&c,26)?;
    let mut b=x.clone(); b.objects[1].operation=b.objects[0].funding_operation; emit(&mut out,&b,&c,26)?;
    let mut b=x.clone(); b.objects[0].operation=[0;32]; b.objects[0].manifest=x.objects[1].manifest.clone();
    emit(&mut out,&b,&c,21)?;
    let mut b=x.clone(); b.objects[0].manifest=x.objects[1].manifest.clone(); b.objects[0].operation=x.operation;
    emit(&mut out,&b,&c,23)?;
    let mut b=x.clone(); b.objects[0].operation=x.operation; b.objects[0].maximum_repair_bytes=0;
    emit(&mut out,&b,&c,24)?;
    let mut b=x.clone(); b.objects[0].operation=x.funding_operation; b.objects[0].maximum_repair_bytes=0;
    emit(&mut out,&b,&c,25)?;
    let mut b=x.clone(); b.objects[0].operation=x.funding_operation;
    let mut low=c.clone(); low.retention.capacity_bytes=4096; emit(&mut out,&b,&low,26)?;
    for (env,model) in [(&[1][..],&[4097][..]), (&[4095,4096],&[16384,16385]),
                        (&[255,4097,8192],&[30000,32768]), (&[17;256],&[19;256])] {
        let (x,mut c)=fixture(env,model);
        // This computes fixture positions around the declared threshold; the
        // actual accept/deny is exclusively the locked original above.
        let taken: u64 = env.iter().chain(model).map(|n| n.div_ceil(4096)*4096).sum();
        c.retention.capacity_bytes=taken;
        emit(&mut out,&x,&c,0)?;
        c.retention.capacity_bytes-=4096;
        emit(&mut out,&x,&c,27)?;
    }
    Ok(())
}
