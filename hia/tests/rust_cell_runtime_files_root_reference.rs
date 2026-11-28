use std::io::{self, Write};
use trnm_data_availability::cell::{
    runtime_files_root_v1, CellErrorV1, CellRuntimeFileV1, CellRuntimeRoleV1,
};

const ROLES: [CellRuntimeRoleV1; 11] = {
    use CellRuntimeRoleV1::*;
    [Interpreter, StandardLibrary, SitePackage, Native, Wheel, Distribution, Source,
        Launcher, LauncherSource, LauncherRecipe, Provenance]
};

fn emit(out: &mut impl Write, rows: &[(String, usize, u64, [u8; 32])]) {
    let files = rows.iter().map(|(path, role, bytes, sha256)| CellRuntimeFileV1 {
        path: path.clone(),
        role: ROLES[*role],
        bytes: *bytes,
        sha256: *sha256,
        segments: Vec::new(),
    }).collect::<Vec<_>>();
    let (code, digest) = match runtime_files_root_v1(&files) {
        Ok(digest) => (0u32, digest),
        Err(CellErrorV1::Invalid("runtime file count")) => (1, [0; 32]),
        Err(CellErrorV1::Invalid("runtime relative path")) => (2, [0; 32]),
        Err(CellErrorV1::Invalid("runtime sorted unique paths")) => (3, [0; 32]),
        Err(error) => panic!("unexpected original status: {error}"),
    };
    let mut frame = b"RFR1\0\0\0\0".to_vec();
    frame.extend((rows.len() as u64).to_le_bytes());
    for (path, role, bytes, sha256) in rows {
        frame.extend((path.len() as u64).to_be_bytes());
        frame.extend(path.as_bytes());
        frame.push(*role as u8);
        frame.extend(bytes.to_be_bytes());
        frame.extend(sha256);
    }
    out.write_all(&code.to_le_bytes()).unwrap();
    out.write_all(&(frame.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&digest).unwrap();
    out.write_all(&frame).unwrap();
}

fn one(path: &str) -> (String, usize, u64, [u8; 32]) {
    (path.to_owned(), 0, 0, [0; 32])
}

fn main() {
    let mut out = io::stdout().lock();
    emit(&mut out, &[]);
    emit(&mut out, &[one("A")]);
    emit(&mut out, &[one("A"), one("A/B"), one("Aa")]);
    let mut all_roles = ROLES.iter().enumerate().map(|(i, _)| (
        format!("demo/{i:02}.A_+"), i, [0, 1, 256, 1 << 63, u64::MAX][i % 5],
        std::array::from_fn(|j| (i * 31 + j) as u8),
    )).collect::<Vec<_>>();
    emit(&mut out, &all_roles);
    all_roles[3].1 = 4;
    emit(&mut out, &all_roles);
    all_roles[3].2 ^= 0x0100;
    emit(&mut out, &all_roles);
    all_roles[3].3[31] ^= 0x01;
    emit(&mut out, &all_roles);
    for path in ["", ".", "..", "x//y", "/x", "x/", "x/./y", "x/../y",
                 "x y", "x:y", "x\\y", "é", "x\0y", "x@y"] {
        emit(&mut out, &[one(path)]);
    }
    emit(&mut out, &[one("z"), one("a")]);
    emit(&mut out, &[one("a"), one("a")]);
    emit(&mut out, &[one("a/z"), one("a")]);
    emit(&mut out, &[one("z"), one("..")]);
    emit(&mut out, &[one("z"), one("a"), one("..")]);
    emit(&mut out, &[one("CON/.a/..a/x./Z+_-")]);
    emit(&mut out, &[one(&"x".repeat(1_024))]);
    emit(&mut out, &[one(&"x".repeat(1_025))]);
    let max = (0..256).map(|i| {
        (format!("{}/{i:03}", "r".repeat(1_020)), i % 11, i as u64, [i as u8; 32])
    }).collect::<Vec<_>>();
    emit(&mut out, &max);
}
