//! Exact declared metadata comparison on synthetic values; no loader.
use std::io::{self, Write};
use trnm_data_availability::cell::{
    CellClosureFileV1, CellContextV1, CellErrorV1, CellFileRoleV1, CellLoaderContextV1,
    CellReleaseClosureV1,
};
const ROLES: [CellFileRoleV1;6] = [
    CellFileRoleV1::Base, CellFileRoleV1::Tokenizer, CellFileRoleV1::Preprocessor,
    CellFileRoleV1::Adapter, CellFileRoleV1::Router, CellFileRoleV1::Configuration,
];

fn fixture(n: usize, all: bool, size: u64, family: &str) -> (CellReleaseClosureV1, CellLoaderContextV1) {
    let c = CellContextV1 {
        family: family.to_owned(),
        base: [1;32], parent: [2;32], tokenizer: [3;32], layout: [4;32], runtime: [5;32],
    };
    let files = (0..n).map(|i| {
        let mut id = [7;32];
        id[30..].copy_from_slice(&(i as u16).to_be_bytes());
        CellClosureFileV1 {
            path: format!("part-{i:04}.bin"),
            role: if all { ROLES[i%6] } else { CellFileRoleV1::Configuration },
            manifest: id, payload_sha256: [6;32], payload_bytes: size, dependencies: vec![],
        }
    }).collect();
    let closure = CellReleaseClosureV1::new(
        c.clone(), 17, [8;32], (0..n as u16).collect(), files,
    ).unwrap();
    let expected = CellLoaderContextV1 {
        closure_id: closure.id(), context: c, selected_generation: 17, loader_profile: [8;32],
        required_roles: if all { vec![CellFileRoleV1::Base] } else { vec![CellFileRoleV1::Configuration] },
        max_payload_bytes: size*n as u64, max_chunks: 1,
    };
    (closure,expected)
}

fn emit(out: &mut impl Write, c: &CellReleaseClosureV1, expected: &CellLoaderContextV1,
        want: u8) -> io::Result<()> {
    let mut wire = c.encode();
    let original = CellReleaseClosureV1::decode(&wire).unwrap();
    assert_eq!(original.encode(),wire);
    let observed = match original.verify_for_loader(expected) {
        Ok(()) => 0,
        Err(CellErrorV1::Invalid(reason)) => match reason {
            "closure loader context" => 60,
            "closure loader budget" => 61,
            "closure required roles" => 62,
            "closure missing required role" => 63,
            "closure payload budget" => 64,
            _ => panic!("unanticipated immutable closure predicate: {reason}"),
        },
        Err(e) => panic!("unanticipated original error: {e:?}"),
    };
    assert_eq!(observed,want);
    let start = wire.len();
    wire.extend_from_slice(b"VRLC0001");
    wire.extend_from_slice(&expected.closure_id);
    wire.extend_from_slice(&expected.selected_generation.to_be_bytes());
    wire.extend_from_slice(&expected.loader_profile);
    wire.extend_from_slice(&expected.max_payload_bytes.to_be_bytes());
    wire.extend_from_slice(&expected.max_chunks.to_be_bytes());
    wire.extend_from_slice(&(expected.context.family.len() as u16).to_be_bytes());
    wire.extend_from_slice(&(expected.required_roles.len() as u16).to_be_bytes());
    for id in [expected.context.base,expected.context.parent,expected.context.tokenizer,
               expected.context.layout,expected.context.runtime] {
        wire.extend_from_slice(&id);
    }
    wire.extend_from_slice(expected.context.family.as_bytes());
    for role in &expected.required_roles { wire.push(*role as u8); }
    let descriptor = (wire.len()-start) as u32;
    wire.extend_from_slice(&descriptor.to_be_bytes());
    out.write_all(&(wire.len() as u32).to_le_bytes())?;
    out.write_all(&wire)?;
    out.write_all(&[observed])
}

fn main() -> io::Result<()> {
    let mut out = io::stdout().lock();
    let (c,x) = fixture(6,true,4097,"Cell-1");
    emit(&mut out,&c,&x,0)?;
    for mask in 1_usize..64 {
        let mut w = x.clone();
        // Required roles are distinct, but order is not an admission gate.
        w.required_roles = ROLES.iter().copied().enumerate().rev()
            .filter_map(|(i,r)| if mask & (1<<i)==0 {None} else {Some(r)}).collect();
        emit(&mut out,&c,&w,0)?;
    }
    for i in 0..32 {
        for field in 0..7 {
            let mut w = x.clone();
            let v = match field {
                0 => &mut w.closure_id, 1 => &mut w.context.base, 2 => &mut w.context.parent,
                3 => &mut w.context.tokenizer, 4 => &mut w.context.layout, 5 => &mut w.context.runtime,
                6 => &mut w.loader_profile, _ => unreachable!(),
            };
            v[i] ^= 0x80;
            emit(&mut out,&c,&w,60)?;
        }
    }
    for bad in ["", "Cell-2", "Cell-1x", "Cell/1", "模型🙂"] {
        let mut w=x.clone(); w.context.family=bad.to_owned(); emit(&mut out,&c,&w,60)?;
    }
    for bad in [0,16,18,u64::MAX] {
        let mut w=x.clone(); w.selected_generation=bad; emit(&mut out,&c,&w,60)?;
    }
    let mut w=x.clone(); w.max_payload_bytes=0; emit(&mut out,&c,&w,61)?;
    let mut w=x.clone(); w.max_chunks=0; emit(&mut out,&c,&w,61)?;
    let mut w=x.clone(); w.max_chunks=u64::MAX; emit(&mut out,&c,&w,0)?;
    let mut w=x.clone(); w.required_roles.clear(); emit(&mut out,&c,&w,62)?;
    for role in ROLES {
        let mut w=x.clone(); w.required_roles=vec![role,role]; emit(&mut out,&c,&w,62)?;
    }
    let mut w=x.clone(); w.max_payload_bytes-=1; emit(&mut out,&c,&w,64)?;
    let (e,y)=fixture(23,false,1,"env1");
    emit(&mut out,&e,&y,0)?;
    for role in ROLES[..5].iter().copied() {
        let mut w=y.clone(); w.required_roles.insert(0,role); emit(&mut out,&e,&w,63)?;
        w.max_payload_bytes=1; emit(&mut out,&e,&w,63)?;
        w.required_roles.push(role); emit(&mut out,&e,&w,62)?;
        w.max_chunks=0; emit(&mut out,&e,&w,61)?;
        w.closure_id[0] ^= 0x80; emit(&mut out,&e,&w,60)?;
    }
    let (max,mut w) = fixture(256,true,64<<30,&"Z".repeat(64));
    w.required_roles=ROLES.to_vec();
    emit(&mut out,&max,&w,0)?;
    w.max_payload_bytes-=1;
    emit(&mut out,&max,&w,64)?;
    Ok(())
}
