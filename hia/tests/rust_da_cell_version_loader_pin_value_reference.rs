//! Public Rust owned-value conversions only; not loader policy validation.
use std::io::{self, Read, Write};
use trnm_data_availability::cell::{
    CellContextV1, CellFileRoleV1, CellLoaderContextV1, CellVersionLoaderPinV3,
};

fn read<const N: usize>(b: &[u8], start: usize) -> [u8; N] {
    b[start..start + N].try_into().unwrap()
}

fn role(v: u8) -> CellFileRoleV1 {
    match v {
        1 => CellFileRoleV1::Base,
        2 => CellFileRoleV1::Tokenizer,
        3 => CellFileRoleV1::Preprocessor,
        4 => CellFileRoleV1::Adapter,
        5 => CellFileRoleV1::Router,
        6 => CellFileRoleV1::Configuration,
        _ => panic!("ordinary typed fixture has no such original role"),
    }
}

fn main() -> io::Result<()> {
    let mut blob = Vec::new();
    io::stdin().lock().read_to_end(&mut blob)?;
    let mut output = io::stdout().lock();
    let mut rows = blob.as_slice();
    while !rows.is_empty() {
        let size = u32::from_le_bytes(read(rows, 0)) as usize;
        let (b, tail) = rows[4..].split_at(size);
        rows = tail;
        assert_eq!(&b[..8], b"NVLP0001");
        let mode = b[8];
        let family_len = usize::from(u16::from_be_bytes(read(b, 9)));
        let roles_len = usize::from(u16::from_be_bytes(read(b, 11)));
        let family_end = 261 + family_len;
        assert_eq!(b.len(), family_end + roles_len);
        let shared = CellContextV1 {
            family: std::str::from_utf8(&b[261..family_end]).unwrap().to_owned(),
            base: read(b, 45),
            parent: read(b, 77),
            tokenizer: read(b, 109),
            layout: read(b, 141),
            runtime: read(b, 173),
        };
        let roles = b[family_end..].iter().copied().map(role).collect();
        let cid = read(b, 13);
        let generation = u64::from_be_bytes(read(b, 205));
        let profile = read(b, 213);
        let max_payload_bytes = u64::from_be_bytes(read(b, 245));
        let max_chunks = u64::from_be_bytes(read(b, 253));
        let (closure_id, context, selected_generation, loader_profile, required_roles, bytes, chunks) = match mode {
            0 => {
                let original = CellVersionLoaderPinV3::from_context(&CellLoaderContextV1 {
                    closure_id: cid, context: shared, selected_generation: generation, loader_profile: profile,
                    required_roles: roles, max_payload_bytes, max_chunks,
                });
                (original.closure_id, original.context, original.selected_generation, original.loader_profile,
                 original.required_roles, original.max_payload_bytes, original.max_chunks)
            }
            1 => {
                let original = CellVersionLoaderPinV3 {
                    closure_id: cid, context: shared, selected_generation: generation, loader_profile: profile,
                    required_roles: roles, max_payload_bytes, max_chunks,
                }.loader_context();
                (original.closure_id, original.context, original.selected_generation, original.loader_profile,
                 original.required_roles, original.max_payload_bytes, original.max_chunks)
            }
            _ => panic!("fixture mode outside immutable conversion"),
        };
        output.write_all(&u32::try_from(size).unwrap().to_le_bytes())?;
        output.write_all(b"NVLP0001")?;
        output.write_all(&[mode])?;
        output.write_all(&u16::try_from(context.family.len()).unwrap().to_be_bytes())?;
        output.write_all(&u16::try_from(required_roles.len()).unwrap().to_be_bytes())?;
        for id in [closure_id, context.base, context.parent, context.tokenizer, context.layout, context.runtime] {
            output.write_all(&id)?;
        }
        output.write_all(&selected_generation.to_be_bytes())?;
        output.write_all(&loader_profile)?;
        output.write_all(&bytes.to_be_bytes())?;
        output.write_all(&chunks.to_be_bytes())?;
        output.write_all(context.family.as_bytes())?;
        output.write_all(&required_roles.into_iter().map(|x| x as u8).collect::<Vec<_>>())?;
    }
    Ok(())
}
