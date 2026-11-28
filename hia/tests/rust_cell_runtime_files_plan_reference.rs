use std::{collections::BTreeSet, io::{self, Write}, path::Path,
          time::{Duration, Instant}};
use sha2::{Digest, Sha256};
use trnm_data_availability::cell::{
    runtime_files_root_v1, CellContextV1, CellErrorV1, CellManifestV1,
    CellResultV1, CellRuntimeFileV1, CellRuntimeRoleV1, MAX_CHUNK_BYTES,
};

// The test composes exact byte slices from the frozen original rather than
// exposing extra symbols from the production crate. All types and methods in
// the validation body resolve to the unchanged linked original crate.
include!("runtime_plan_body.rs");

const ROLES: [CellRuntimeRoleV1; 11] = {
    use CellRuntimeRoleV1::*;
    [Interpreter, StandardLibrary, SitePackage, Native, Wheel, Distribution, Source,
        Launcher, LauncherSource, LauncherRecipe, Provenance]
};
const HOST: u64 = 2 * 1024 * 1024 * 1024;

fn context() -> CellContextV1 {
    CellContextV1 {
        family: "Synthetic.Plan_1".into(), base: [1; 32], parent: [2; 32],
        tokenizer: [3; 32], layout: [4; 32], runtime: [5; 32],
    }
}

fn context_bytes(ctx: &CellContextV1) -> Vec<u8> {
    let mut bytes = vec![ctx.family.len() as u8];
    bytes.extend_from_slice(ctx.family.as_bytes());
    for dig in [ctx.base, ctx.parent, ctx.tokenizer, ctx.layout, ctx.runtime] {
        bytes.extend(dig);
    }
    bytes
}

fn segment(ctx: &CellContextV1, sizes: &[u32], chunk: u32, salt: u8) -> CellManifestV1 {
    let mut bytes = b"TCM1".to_vec();
    bytes.extend(context_bytes(ctx));
    let total: u64 = sizes.iter().map(|size| u64::from(*size)).sum();
    bytes.extend(total.to_be_bytes());
    bytes.extend([salt; 32]);
    bytes.extend(chunk.to_be_bytes());
    bytes.extend((sizes.len() as u32).to_be_bytes());
    for (i, size) in sizes.iter().enumerate() {
        bytes.extend(size.to_be_bytes());
        bytes.extend([salt.wrapping_add(i as u8).wrapping_add(1); 32]);
    }
    CellManifestV1::decode(&bytes).unwrap()
}

fn row(path: &str, role: usize, bytes: u64, seg: Vec<CellManifestV1>)
    -> (usize, CellRuntimeFileV1) {
    let sha256 = if bytes == 0 { Sha256::digest([]).into() } else { [42; 32] };
    (role, CellRuntimeFileV1 { path: path.into(), role: ROLES[role], bytes, sha256, segments: seg })
}

fn emit(out: &mut impl Write, ctx: &CellContextV1, cap: u64,
        rows: Vec<(usize, CellRuntimeFileV1)>) {
    let files = rows.iter().map(|(_, file)| file.clone()).collect::<Vec<_>>();
    let (status, payload, metadata) = match validate_files(
        &files, ctx, Instant::now() + Duration::from_secs(86_400), cap
    ) {
        Ok((payload, metadata)) => (0u32, payload, metadata),
        Err(CellErrorV1::Invalid("runtime file count")) => (1, 0, 0),
        Err(CellErrorV1::Invalid("runtime relative path")) => (2, 0, 0),
        Err(CellErrorV1::Invalid("runtime sorted unique paths")) => (3, 0, 0),
        Err(CellErrorV1::Invalid("runtime file/directory collision")) => (4, 0, 0),
        Err(CellErrorV1::Invalid("runtime payload overflow")) => (5, 0, 0),
        Err(CellErrorV1::Invalid("runtime individual file bound")) => (6, 0, 0),
        Err(CellErrorV1::Invalid("runtime bounded plan")) => (7, 0, 0),
        Err(CellErrorV1::Invalid("runtime bounded segment/context")) => (8, 0, 0),
        Err(CellErrorV1::Invalid("runtime metadata cap")) => (9, 0, 0),
        Err(CellErrorV1::Invalid("runtime segment coverage")) => (10, 0, 0),
        Err(CellErrorV1::Invalid("runtime empty file")) => (11, 0, 0),
        Err(error) => panic!("unexpected frozen runtime plan error: {error}"),
    };
    let mut rfr = b"RFR1\0\0\0\0".to_vec();
    rfr.extend((files.len() as u64).to_le_bytes());
    let mut cells = Vec::new();
    for (role, file) in &rows {
        rfr.extend((file.path.len() as u64).to_be_bytes());
        rfr.extend(file.path.as_bytes());
        rfr.push(*role as u8);
        rfr.extend(file.bytes.to_be_bytes());
        rfr.extend(file.sha256);
        cells.extend((file.segments.len() as u64).to_le_bytes());
        for cell in &file.segments {
            let wire = cell.encode();
            cells.extend((wire.len() as u64).to_le_bytes());
            cells.extend(wire);
        }
    }
    let c = context_bytes(ctx);
    let mut packet = b"RFP1\0\0\0\0".to_vec();
    packet.extend((rfr.len() as u64).to_le_bytes());
    packet.extend(cap.to_le_bytes());
    packet.extend((c.len() as u64).to_le_bytes());
    packet.extend(c);
    packet.extend(rfr);
    packet.extend(cells);
    out.write_all(&status.to_le_bytes()).unwrap();
    out.write_all(&(packet.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&payload.to_le_bytes()).unwrap();
    out.write_all(&metadata.to_le_bytes()).unwrap();
    out.write_all(&packet).unwrap();
}

fn main() {
    let mut o = io::stdout().lock();
    let ctx = context();
    let mut other = ctx.clone();
    other.layout[31] ^= 1;
    let a = segment(&ctx, &[7], 16_384, 31);
    let b = segment(&ctx, &[11], 16_384, 37);
    let wrong = segment(&other, &[7], 16_384, 31);
    let big = segment(&ctx, &[16_384, 1], 16_384, 78);
    let max = segment(&ctx, &[MAX_CHUNK_BYTES], MAX_CHUNK_BYTES, 39);
    emit(&mut o, &ctx, u64::MAX, vec![]);
    for role in 0..ROLES.len() {
        emit(&mut o, &ctx, u64::MAX, vec![row("empty", role, 0, vec![])]);
    }
    let mut bad = row("empty", 1, 0, vec![]);
    bad.1.sha256[31] ^= 1;
    emit(&mut o, &ctx, u64::MAX, vec![bad]);
    emit(&mut o, &ctx, u64::MAX, vec![row("bad//name", 0, 0, vec![])]);
    emit(&mut o, &ctx, 0, vec![row("z", 0, 0, vec![]), row("a", 0, 0, vec![])]);
    let good = vec![row("A", 0, 18, vec![a.clone(), b.clone()]), row("Aa/B", 1, 0, vec![])];
    let meta = 129 + a.encode().len() as u64 + b.encode().len() as u64 + 132;
    emit(&mut o, &ctx, meta, good.clone());
    emit(&mut o, &ctx, meta - 1, good);
    emit(&mut o, &ctx, u64::MAX, vec![row("A", 1, 0, vec![]),
        row("A-lexically-between", 1, 0, vec![]), row("A/B/C", 1, 0, vec![])]);
    emit(&mut o, &ctx, u64::MAX, vec![row("A", 1, 0, vec![]), row("A/B", 1, HOST+1, vec![])]);
    emit(&mut o, &ctx, 0, vec![row("A", 1, HOST+1, vec![])]);
    emit(&mut o, &ctx, u64::MAX, vec![row("A", 1, 7, vec![a.clone()]),
        row("B", 1, u64::MAX, vec![])]);
    emit(&mut o, &ctx, u64::MAX, vec![row("A", 1, 7, vec![a.clone()]),
        row("B", 1, HOST, vec![])]);
    emit(&mut o, &ctx, 128, vec![row("A", 1, 7, vec![wrong.clone()])]);
    emit(&mut o, &ctx, 129, vec![row("A", 1, 7, vec![wrong])]);
    emit(&mut o, &ctx, 129, vec![row("A", 1, 8, vec![a.clone()])]);
    emit(&mut o, &ctx, u64::MAX, vec![row("A", 1, 8, vec![a])]);
    emit(&mut o, &ctx, u64::MAX, vec![row("A", 1, 16_385, vec![big])]);
    emit(&mut o, &ctx, u64::MAX, vec![row("A", 1, u64::from(MAX_CHUNK_BYTES), vec![max.clone()])]);
    let rows = (0..64).map(|i| row(&format!("data/{i:02}"), 10,
        4 * u64::from(MAX_CHUNK_BYTES), vec![max.clone(); 4])).collect();
    emit(&mut o, &ctx, u64::MAX, rows);
}
