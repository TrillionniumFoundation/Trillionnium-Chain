use std::{cell::RefCell, fs, sync::atomic::Ordering, sync::Arc, time::Duration};

use sha2::{Digest, Sha256};

use super::*;
use crate::cell::*;

const CHUNK_BYTES: usize = 16_384;
const ELEMENTS: usize = 4097;
type AfterFile = Box<dyn FnOnce(u16)>;

thread_local! {
    static AFTER_FILE: RefCell<Option<AfterFile>> = const { RefCell::new(None) };
}

pub(super) fn after_file(index: u16) {
    let hook = AFTER_FILE.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(index);
    }
}

fn with_after_file<T>(hook: AfterFile, run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            let _ = AFTER_FILE.with(|slot| slot.borrow_mut().take());
        }
    }
    AFTER_FILE.with(|slot| assert!(slot.borrow_mut().replace(hook).is_none()));
    let _reset = Reset;
    run()
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 8 * 1024 * 1024,
        max_logical_bytes: 4 * 1024 * 1024,
        max_chunk_rows: 64,
        max_manifest_rows: 16,
    }
}

fn pool() -> CellResidencyV1 {
    CellResidencyV1::new(CellResidencyConfigV1 {
        max_resident_bytes: 1024 * 1024,
        max_resident_closures: 4,
        max_chunk_references: 64,
    })
    .unwrap()
}

fn container(mut header: String, data: &[u8]) -> Vec<u8> {
    // Valid header padding deliberately puts F32 data at byte offset 1 mod 4.
    // This forces one element across the real 16KiB CAS chunk boundary.
    while header.len() % 4 != 1 {
        header.push(' ');
    }
    [
        (header.len() as u64).to_le_bytes().as_slice(),
        header.as_bytes(),
        data,
    ]
    .concat()
}

fn base_bytes(wrong_shape: bool) -> Vec<u8> {
    let mut data: Vec<u8> = (0..ELEMENTS)
        .flat_map(|index| (index as f32 * 0.25).to_le_bytes())
        .collect();
    data.extend(0x3c00u16.to_le_bytes());
    data.extend(0xc000u16.to_le_bytes());
    data.extend(0x3f00u16.to_le_bytes());
    let end = ELEMENTS * 4;
    container(
        format!(
            r#"{{"a":{{"dtype":"F32","shape":[{}],"data_offsets":[0,{end}]}},"b":{{"dtype":"F16","shape":[2],"data_offsets":[{end},{}]}},"c":{{"dtype":"BF16","shape":[],"data_offsets":[{},{}]}}}}"#,
            if wrong_shape { ELEMENTS - 1 } else { ELEMENTS },
            end + 4,
            end + 4,
            end + 6,
        ),
        &data,
    )
}

struct Fixture {
    model: CellTensorModelManifestV1,
    expected: CellLoaderContextV1,
}

impl Fixture {
    fn new(store: &CellStoreV1, wrong_shape: bool, generation: u64) -> Self {
        let base = base_bytes(wrong_shape);
        let payloads = [
            container(
                r#"{"scale":{"dtype":"F32","shape":[],"data_offsets":[0,4]}}"#.into(),
                &2.0f32.to_le_bytes(),
            ),
            base,
            br#"{"vocab":{"hello":0},"version":1}"#.to_vec(),
        ];
        let context = CellContextV1 {
            family: "resident-tensor-admission-controls-v1".into(),
            base: Sha256::digest(&payloads[1]).into(),
            parent: [0x11; 32],
            tokenizer: Sha256::digest(&payloads[2]).into(),
            layout: [0x12; 32],
            runtime: [0x13; 32],
        };
        let files = [
            ("adapter.safetensors", CellFileRoleV1::Adapter),
            ("base.safetensors", CellFileRoleV1::Base),
            ("tokenizer.json", CellFileRoleV1::Tokenizer),
        ]
        .into_iter()
        .zip(&payloads)
        .map(|((path, role), bytes)| {
            let manifest = CellManifestV1::new(
                context.clone(),
                bytes.len() as u64,
                Sha256::digest(bytes).into(),
                CHUNK_BYTES as u32,
                bytes
                    .chunks(CHUNK_BYTES)
                    .map(|chunk| CellChunkV1 {
                        size: chunk.len() as u32,
                        sha256: Sha256::digest(chunk).into(),
                    })
                    .collect(),
            )
            .unwrap();
            store
                .put_manifest(manifest.id(), &manifest.encode())
                .unwrap();
            for (chunk, bytes) in manifest.chunks().iter().zip(bytes.chunks(CHUNK_BYTES)) {
                store.put_chunk(chunk, bytes).unwrap();
            }
            CellClosureFileV1 {
                path: path.into(),
                role,
                manifest: manifest.id(),
                payload_sha256: manifest.payload_sha256(),
                payload_bytes: manifest.size(),
                dependencies: vec![],
            }
        })
        .collect();
        let root = CellModelReleaseRootV1::new(
            CellReleaseClosureV1::new(
                context.clone(),
                generation,
                [0x14; 32],
                vec![0, 1, 2],
                files,
            )
            .unwrap(),
            vec![],
        )
        .unwrap();
        let expected = CellLoaderContextV1 {
            closure_id: root.closure().id(),
            context,
            selected_generation: generation,
            loader_profile: root.closure().loader_profile(),
            required_roles: vec![
                CellFileRoleV1::Base,
                CellFileRoleV1::Adapter,
                CellFileRoleV1::Tokenizer,
            ],
            max_payload_bytes: 1024 * 1024,
            max_chunks: 64,
        };
        let contract = CellTensorContractV1::new(
            root.id(),
            vec![
                CellTensorFileV1 {
                    file_index: 0,
                    tensors: vec![CellTensorSpecV1 {
                        name: "scale".into(),
                        dtype: CellTensorDTypeV1::F32,
                        shape: vec![],
                    }],
                },
                CellTensorFileV1 {
                    file_index: 1,
                    tensors: vec![
                        CellTensorSpecV1 {
                            name: "a".into(),
                            dtype: CellTensorDTypeV1::F32,
                            shape: vec![ELEMENTS as u64],
                        },
                        CellTensorSpecV1 {
                            name: "b".into(),
                            dtype: CellTensorDTypeV1::F16,
                            shape: vec![2],
                        },
                        CellTensorSpecV1 {
                            name: "c".into(),
                            dtype: CellTensorDTypeV1::Bf16,
                            shape: vec![],
                        },
                    ],
                },
            ],
        )
        .unwrap();
        Self {
            model: CellTensorModelManifestV1::new(root, contract).unwrap(),
            expected,
        }
    }

    fn prepare(&self, pool: &mut CellResidencyV1, store: &CellStoreV1) {
        pool.prepare_cached(
            store,
            self.model.root().closure(),
            &self.expected,
            deadline(),
            &AtomicBool::new(false),
        )
        .unwrap();
    }

    fn select(&self, pool: &mut CellResidencyV1) -> CellLocalSelectionV1 {
        pool.select_local(
            pool.selection(),
            &self.expected,
            deadline(),
            &AtomicBool::new(false),
        )
        .unwrap()
    }
}

#[test]
fn resident_tensors_admit_complete_real_containers_then_compute_without_disk_or_provider() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("cache.sqlite");
    let store = CellStoreV1::open(&path, config()).unwrap();
    let fixture = Fixture::new(&store, false, 1);
    let mut pool = pool();
    fixture.prepare(&mut pool, &store);
    fixture.select(&mut pool);
    let usage = pool.usage();
    drop(store);
    fs::remove_file(path).unwrap();
    let admitted = pool
        .admit_selected_tensor_model(
            &fixture.model,
            fixture.model.id(),
            &fixture.expected,
            deadline(),
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(admitted.manifest_id(), fixture.model.id());
    assert_eq!(admitted.model_root(), fixture.model.root().id());
    assert_eq!(admitted.contract_id(), fixture.model.contract().id());
    assert_eq!(admitted.closure_id(), fixture.expected.closure_id);
    assert_eq!(admitted.files().len(), 2);
    assert_eq!(admitted.files()[1].file_index(), 1);
    assert_eq!(admitted.files()[1].path(), "base.safetensors");
    assert_eq!(admitted.files()[1].readback().tensor_count, 3);
    assert_eq!(admitted.files()[1].tensors().len(), 3);
    let a = admitted.tensor(1, "a").unwrap();
    assert_eq!(a.dtype(), CellTensorDTypeV1::F32);
    assert_eq!(a.name(), "a");
    assert_eq!(a.shape(), &[ELEMENTS as u64]);
    assert_eq!(a.byte_length(), ELEMENTS as u64 * 4);
    assert_eq!(a.segments().len(), 2);
    let sum: f32 = (0..ELEMENTS as u64)
        .map(|index| a.read_f32(index).unwrap())
        .sum();
    let scale = admitted.tensor(0, "scale").unwrap().read_f32(0).unwrap();
    assert_eq!(sum * scale, ((ELEMENTS - 1) * ELEMENTS) as f32 * 0.25);
    assert_eq!(pool.usage(), usage);
}

#[test]
fn resident_tensor_views_preserve_unaligned_cross_chunk_elements_and_half_bits() {
    let temporary = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&temporary.path().join("cache"), config()).unwrap();
    let fixture = Fixture::new(&store, false, 1);
    let mut pool = pool();
    fixture.prepare(&mut pool, &store);
    let admitted = pool
        .admit_local_tensor_model(
            &fixture.model,
            fixture.model.id(),
            &fixture.expected,
            deadline(),
            &AtomicBool::new(false),
        )
        .unwrap();
    let a = admitted.tensor(1, "a").unwrap();
    let first = a.segments().next().unwrap();
    assert_ne!(first.len() % 4, 0);
    let crossing_index = first.len() as u64 / 4;
    assert_eq!(
        a.read_f32(crossing_index).unwrap(),
        crossing_index as f32 * 0.25
    );
    let actual: Vec<u8> = a.segments().flatten().copied().collect();
    let expected: Vec<u8> = (0..ELEMENTS)
        .flat_map(|index| (index as f32 * 0.25).to_le_bytes())
        .collect();
    assert_eq!(actual, expected);
    let b = admitted.tensor(1, "b").unwrap();
    let c = admitted.tensor(1, "c").unwrap();
    assert_eq!(b.dtype(), CellTensorDTypeV1::F16);
    assert_eq!(c.dtype(), CellTensorDTypeV1::Bf16);
    assert!(c.shape().is_empty());
    let mut bits = [0; 4];
    b.copy_bytes(0, &mut bits).unwrap();
    assert_eq!(bits, [0, 0x3c, 0, 0xc0]);
    assert_eq!(
        c.segments().flatten().copied().collect::<Vec<_>>(),
        [0, 0x3f]
    );
    assert!(b.read_f32(0).is_err());
    assert!(a.read_f32(ELEMENTS as u64).is_err());
    assert!(a.read_f32(u64::MAX).is_err());
    assert!(a.copy_bytes(a.byte_length() - 1, &mut bits).is_err());
    a.copy_bytes(a.byte_length(), &mut []).unwrap();
    assert!(admitted.tensor(1, "missing").is_none());
    assert!(admitted.tensor(2, "a").is_none());
}

#[test]
fn resident_tensor_admission_rejects_independent_pin_context_and_contract_transplants() {
    let temporary = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&temporary.path().join("cache"), config()).unwrap();
    let fixture = Fixture::new(&store, false, 1);
    let successor = Fixture::new(&store, false, 2);
    let mut pool = pool();
    fixture.prepare(&mut pool, &store);
    let selected = fixture.select(&mut pool);
    let usage = pool.usage();
    let cancelled = AtomicBool::new(false);
    assert!(pool
        .admit_local_tensor_model(
            &fixture.model,
            [0xee; 32],
            &fixture.expected,
            deadline(),
            &cancelled
        )
        .is_err());
    assert!(pool
        .admit_local_tensor_model(
            &successor.model,
            successor.model.id(),
            &fixture.expected,
            deadline(),
            &cancelled
        )
        .is_err());
    for field in 0..6 {
        let mut expected = fixture.expected.clone();
        match field {
            0 => expected.selected_generation += 1,
            1 => expected.loader_profile = [0xee; 32],
            2 => expected.context.runtime = [0xee; 32],
            3 => expected.required_roles.push(CellFileRoleV1::Router),
            4 => expected.max_payload_bytes = 1,
            5 => expected.max_chunks = 1,
            _ => unreachable!(),
        }
        assert!(pool
            .admit_local_tensor_model(
                &fixture.model,
                fixture.model.id(),
                &expected,
                deadline(),
                &cancelled
            )
            .is_err());
    }
    let mut specs = fixture.model.contract().files().to_vec();
    specs[1].tensors[0].shape = vec![1, ELEMENTS as u64];
    let other = CellTensorModelManifestV1::new(
        fixture.model.root().clone(),
        CellTensorContractV1::new(fixture.model.root().id(), specs).unwrap(),
    )
    .unwrap();
    assert!(pool
        .admit_local_tensor_model(
            &other,
            other.id(),
            &fixture.expected,
            deadline(),
            &cancelled
        )
        .is_err());
    assert_eq!(pool.selection(), Some(selected));
    assert_eq!(pool.usage(), usage);
}

#[test]
fn resident_correct_hash_invalid_later_tensor_file_returns_no_admission_or_selection_change() {
    let temporary = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&temporary.path().join("cache"), config()).unwrap();
    let fixture = Fixture::new(&store, true, 1);
    let mut pool = pool();
    fixture.prepare(&mut pool, &store);
    let selected = fixture.select(&mut pool);
    let usage = pool.usage();
    let passed_first = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&passed_first);
    let result = with_after_file(
        Box::new(move |index| {
            assert_eq!(index, 0);
            observed.store(true, Ordering::SeqCst);
        }),
        || {
            pool.admit_selected_tensor_model(
                &fixture.model,
                fixture.model.id(),
                &fixture.expected,
                deadline(),
                &AtomicBool::new(false),
            )
        },
    );
    assert!(passed_first.load(Ordering::SeqCst));
    assert!(matches!(
        result,
        Err(CellErrorV1::Invalid("tensor roster metadata"))
    ));
    assert_eq!(pool.selection(), Some(selected));
    assert_eq!(pool.usage(), usage);
}

#[test]
fn resident_tensor_deadline_and_mid_admission_cancellation_preserve_residency_and_selection() {
    let temporary = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&temporary.path().join("cache"), config()).unwrap();
    let fixture = Fixture::new(&store, false, 1);
    let mut pool = pool();
    fixture.prepare(&mut pool, &store);
    let selected = fixture.select(&mut pool);
    let usage = pool.usage();
    let cancelled = Arc::new(AtomicBool::new(false));
    assert!(pool
        .admit_local_tensor_model(
            &fixture.model,
            fixture.model.id(),
            &fixture.expected,
            Instant::now() - Duration::from_secs(1),
            &cancelled
        )
        .is_err());
    let observed = Arc::clone(&cancelled);
    let result = with_after_file(
        Box::new(move |index| {
            assert_eq!(index, 0);
            observed.store(true, Ordering::Release);
        }),
        || {
            pool.admit_local_tensor_model(
                &fixture.model,
                fixture.model.id(),
                &fixture.expected,
                deadline(),
                &cancelled,
            )
        },
    );
    assert!(matches!(
        result,
        Err(CellErrorV1::Invalid("resident operation cancelled"))
    ));
    assert_eq!(pool.selection(), Some(selected));
    assert_eq!(pool.usage(), usage);
    assert!(pool
        .admit_local_tensor_model(
            &fixture.model,
            fixture.model.id(),
            &fixture.expected,
            deadline(),
            &AtomicBool::new(false)
        )
        .is_ok());
}

#[test]
fn resident_tensor_cold_miss_and_wrong_selection_do_not_fetch_or_select() {
    let temporary = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&temporary.path().join("cache"), config()).unwrap();
    let fixture = Fixture::new(&store, false, 1);
    let successor = Fixture::new(&store, false, 2);
    let mut pool = pool();
    assert!(pool
        .admit_local_tensor_model(
            &fixture.model,
            fixture.model.id(),
            &fixture.expected,
            deadline(),
            &AtomicBool::new(false)
        )
        .is_err());
    assert_eq!(pool.usage(), CellResidencyUsageV1::default());
    fixture.prepare(&mut pool, &store);
    successor.prepare(&mut pool, &store);
    let selected = fixture.select(&mut pool);
    assert!(pool
        .admit_selected_tensor_model(
            &successor.model,
            successor.model.id(),
            &successor.expected,
            deadline(),
            &AtomicBool::new(false)
        )
        .is_err());
    assert!(pool
        .admit_local_tensor_model(
            &successor.model,
            successor.model.id(),
            &successor.expected,
            deadline(),
            &AtomicBool::new(false)
        )
        .is_ok());
    assert_eq!(pool.selection(), Some(selected));
}

#[test]
fn resident_payload_reader_checks_cancellation_on_read_and_seek() {
    let temporary = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&temporary.path().join("cache"), config()).unwrap();
    let fixture = Fixture::new(&store, false, 1);
    let mut pool = pool();
    fixture.prepare(&mut pool, &store);
    let resident = pool.resident(&fixture.expected).unwrap();
    let cancelled = AtomicBool::new(false);
    let mut reader = ResidentPayloadReader {
        file: &resident.files[1],
        size: resident.closure.files()[1].payload_bytes,
        position: 0,
        deadline: deadline(),
        cancelled: &cancelled,
    };
    assert_eq!(reader.read(&mut [0; 8]).unwrap(), 8);
    cancelled.store(true, Ordering::Release);
    assert!(reader.read(&mut [0; 8]).is_err());
    assert!(reader.seek(SeekFrom::Start(0)).is_err());
}
