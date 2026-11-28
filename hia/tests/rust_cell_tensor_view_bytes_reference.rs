//! Genuine public resident tensor methods. All backing bytes, manifests and
//! SQLite files belong to the disposable synthetic test.
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
use trnm_data_availability::cell::*;

const N: usize = 4097;
const WIDTH: usize = 16_384;

struct RemoveOwned(PathBuf);
impl Drop for RemoveOwned {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn synthetic_container() -> Vec<u8> {
    let a = N * 4;
    let mut h = format!(
        r#"{{"a":{{"dtype":"F32","shape":[{N}],"data_offsets":[0,{a}]}},"b":{{"dtype":"F16","shape":[2],"data_offsets":[{a},{}]}},"c":{{"dtype":"BF16","shape":[],"data_offsets":[{},{}]}},"z":{{"dtype":"F32","shape":[],"data_offsets":[{},{}]}}}}"#,
        a + 4, a + 4, a + 6, a + 6, a + 10,
    );
    while h.len() % 4 != 1 {
        h.push(' ');
    }
    let data_start = 8 + h.len();
    let cross = (WIDTH - data_start) / 4;
    let specials = [
        0x8000_0000u32, // negative zero
        0x0000_0001,   // subnormal
        0x7f80_0000,   // positive infinity
        0xff80_0000,   // negative infinity
        0x7fc1_2345,   // quiet NaN payload
        0x7f81_2345,   // signaling NaN payload
        0xffc0_0042,   // signed NaN payload
    ];
    let mut data = Vec::with_capacity(a + 10);
    for j in 0..N {
        let bits = if j < specials.len() {
            specials[j]
        } else if j == cross {
            0x7fc1_a55a
        } else {
            (j as f32 * 0.25).to_bits()
        };
        data.extend(bits.to_le_bytes());
    }
    data.extend([0, 0x3c, 0, 0xc0, 0, 0x3f, 0, 0, 0, 0x80]);
    [(h.len() as u64).to_le_bytes().as_slice(), h.as_bytes(), &data].concat()
}

fn obtain(
    db: &Path,
    payload: &[u8],
    width: usize,
) -> (CellResidencyV1, CellTensorModelManifestV1, CellLoaderContextV1) {
    let config = CellCacheConfigV4 {
        max_database_bytes: 8 * 1024 * 1024,
        max_logical_bytes: 4 * 1024 * 1024,
        max_chunk_rows: 64,
        max_manifest_rows: 16,
    };
    let store = CellStoreV1::open(db, config).unwrap();
    let context = CellContextV1 {
        family: "hia-resident-tensor-byte-view-fixture-v1".into(),
        base: Sha256::digest(payload).into(),
        parent: [0x11; 32],
        tokenizer: [0x12; 32],
        layout: [0x13; 32],
        runtime: [0x14; 32],
    };
    let digest: CellDigestV1 = Sha256::digest(payload).into();
    // The committed in-crate fixture uses crate-private new(); use the exact
    // public canonical decoder and encode readback for the same owned bytes.
    let mut declaration = b"TCM1".to_vec();
    declaration.push(context.family.len() as u8);
    declaration.extend(context.family.as_bytes());
    for d in [context.base, context.parent, context.tokenizer, context.layout, context.runtime] {
        declaration.extend(d);
    }
    declaration.extend((payload.len() as u64).to_be_bytes());
    declaration.extend(digest);
    declaration.extend((width as u32).to_be_bytes());
    declaration.extend((payload.len().div_ceil(width) as u32).to_be_bytes());
    for chunk in payload.chunks(width) {
        declaration.extend((chunk.len() as u32).to_be_bytes());
        declaration.extend(Sha256::digest(chunk));
    }
    let manifest = CellManifestV1::decode(&declaration).unwrap();
    assert_eq!(manifest.encode(), declaration);
    store.put_manifest(manifest.id(), &manifest.encode()).unwrap();
    for (chunk, data) in manifest.chunks().iter().zip(payload.chunks(width)) {
        store.put_chunk(chunk, data).unwrap();
    }
    let closure = CellReleaseClosureV1::new(
        context.clone(),
        1,
        [0x15; 32],
        vec![0],
        vec![CellClosureFileV1 {
            path: "base.safetensors".into(),
            role: CellFileRoleV1::Base,
            manifest: manifest.id(),
            payload_sha256: digest,
            payload_bytes: payload.len() as u64,
            dependencies: vec![],
        }],
    )
    .unwrap();
    let root = CellModelReleaseRootV1::new(closure, vec![]).unwrap();
    let specs = [
        ("a", CellTensorDTypeV1::F32, vec![N as u64]),
        ("b", CellTensorDTypeV1::F16, vec![2]),
        ("c", CellTensorDTypeV1::Bf16, vec![]),
        ("z", CellTensorDTypeV1::F32, vec![]),
    ];
    let contract = CellTensorContractV1::new(
        root.id(),
        vec![CellTensorFileV1 {
            file_index: 0,
            tensors: specs
                .into_iter()
                .map(|(name, dtype, shape)| CellTensorSpecV1 {
                    name: name.into(),
                    dtype,
                    shape,
                })
                .collect(),
        }],
    )
    .unwrap();
    let model = CellTensorModelManifestV1::new(root, contract).unwrap();
    let expected = CellLoaderContextV1 {
        closure_id: model.root().closure().id(),
        context,
        selected_generation: 1,
        loader_profile: [0x15; 32],
        required_roles: vec![CellFileRoleV1::Base],
        max_payload_bytes: 1024 * 1024,
        max_chunks: 64,
    };
    let mut pool = CellResidencyV1::new(CellResidencyConfigV1 {
        max_resident_bytes: 1024 * 1024,
        max_resident_closures: 4,
        max_chunk_references: 64,
    })
    .unwrap();
    pool.prepare_cached(
        &store,
        model.root().closure(),
        &expected,
        Instant::now() + Duration::from_secs(10),
        &AtomicBool::new(false),
    )
    .unwrap();
    drop(store);
    (pool, model, expected)
}

fn send(w: &mut impl Write, tag: u8, bytes: &[u8]) -> io::Result<()> {
    w.write_all(&[tag])?;
    w.write_all(&(bytes.len() as u32).to_le_bytes())?;
    w.write_all(bytes)
}

fn main() -> io::Result<()> {
    let temp = std::env::temp_dir().join(format!("trnm-hia-tensor-view-{}", std::process::id()));
    fs::create_dir(&temp)?;
    let _remove = RemoveOwned(temp.clone());
    let payload = synthetic_container();
    let (two, mtwo, etwo) = obtain(&temp.join("two.sqlite"), &payload, WIDTH);
    let (one, mone, eone) = obtain(&temp.join("one.sqlite"), &payload, WIDTH * 2);
    let cancel = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(10);
    let view_two = two.admit_local_tensor_model(&mtwo, mtwo.id(), &etwo, deadline, &cancel).unwrap();
    let view_one = one.admit_local_tensor_model(&mone, mone.id(), &eone, deadline, &cancel).unwrap();
    let mut requests = Vec::new();
    io::stdin().read_to_end(&mut requests)?;
    let mut out = io::BufWriter::new(io::stdout().lock());
    out.write_all(&(payload.len() as u32).to_le_bytes())?;
    out.write_all(&payload)?;
    for bytes in requests.chunks_exact(19) {
        let [topology, which, operation] = bytes[..3].try_into().unwrap();
        let offset = u64::from_le_bytes(bytes[3..11].try_into().unwrap());
        let length = u64::from_le_bytes(bytes[11..19].try_into().unwrap());
        let owner = [&view_two, &view_one][usize::from(topology)];
        let view = owner.tensor(0, ["a", "b", "c", "z"][usize::from(which)]).unwrap();
        let result = match operation {
            0 => {
                let parts: Vec<_> = view.segments().collect();
                let mut out = (parts.len() as u32).to_le_bytes().to_vec();
                for p in &parts {
                    out.extend((p.len() as u32).to_le_bytes());
                }
                for p in parts {
                    out.extend(p);
                }
                Ok(out)
            }
            1 => {
                assert!(length <= 1024 * 1024);
                let mut out = vec![0xa5; length as usize];
                match view.copy_bytes(offset, &mut out) {
                    Ok(()) => Ok(out),
                    Err(e) => {
                        assert!(out.iter().all(|b| *b == 0xa5));
                        Err(e)
                    }
                }
            }
            2 => view.read_f32(offset).map(|v| v.to_bits().to_le_bytes().to_vec()),
            _ => unreachable!(),
        };
        match result {
            Ok(bytes) => send(&mut out, 0, &bytes)?,
            Err(CellErrorV1::Invalid(reason)) => send(&mut out, 1, reason.as_bytes())?,
            Err(_) => panic!("non-value error from genuine resident tensor API"),
        }
    }
    assert_eq!(requests.len() % 19, 0);
    out.flush()
}
