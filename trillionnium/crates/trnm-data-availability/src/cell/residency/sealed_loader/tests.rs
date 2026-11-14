use std::{
    cell::RefCell,
    fs,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    process::{Command, Stdio},
    rc::Rc,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use rustix::io::{fcntl_getfd, FdFlags};

use super::*;
use crate::cell::*;

const CHUNK_BYTES: usize = 16_384;
const ELEMENTS: usize = 8193;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Stage {
    BeforeSeal,
    Verified,
}

type StageHook = Box<dyn FnMut(usize, Stage, &File)>;

thread_local! {
    static HOOK: RefCell<Option<StageHook>> = const { RefCell::new(None) };
}

pub(super) fn at_stage(index: usize, stage: Stage, file: &File) {
    HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(index, stage, file);
        }
    });
}

fn with_hook<T>(hook: StageHook, run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            HOOK.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    HOOK.with(|slot| assert!(slot.borrow_mut().replace(hook).is_none()));
    let _reset = Reset;
    run()
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn tensor(count: usize) -> Vec<u8> {
    let header = format!(
        r#"{{"weights":{{"dtype":"F32","shape":[{count}],"data_offsets":[0,{}]}}}}"#,
        count * 4,
    );
    let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
    bytes.extend(header.as_bytes());
    bytes.extend((0..count).flat_map(|index| (index as f32 * 0.125).to_le_bytes()));
    bytes
}

struct Fixture {
    dir: tempfile::TempDir,
    store: CellStoreV1,
    pool: CellResidencyV1,
    closure: CellReleaseClosureV1,
    expected: CellLoaderContextV1,
    payloads: Vec<Vec<u8>>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = CellStoreV1::open(
            &dir.path().join("cache.sqlite"),
            CellCacheConfigV4 {
                max_database_bytes: 8 * 1024 * 1024,
                max_logical_bytes: 1024 * 1024,
                max_chunk_rows: 64,
                max_manifest_rows: 16,
            },
        )
        .unwrap();
        let payloads = vec![
            tensor(3),
            tensor(ELEMENTS),
            br#"{"version":1,"vocab":{"hello":0}}"#.to_vec(),
        ];
        let context = CellContextV1 {
            family: "sealed-declared-loader-controls-v1".into(),
            base: Sha256::digest(&payloads[1]).into(),
            parent: [0x23; 32],
            tokenizer: Sha256::digest(&payloads[2]).into(),
            layout: [0x24; 32],
            runtime: [0x25; 32],
        };
        let files = [
            ("adapter.safetensors", CellFileRoleV1::Adapter),
            ("base/model.safetensors", CellFileRoleV1::Base),
            ("tokenizer.json", CellFileRoleV1::Tokenizer),
        ]
        .into_iter()
        .zip(&payloads)
        .enumerate()
        .map(|(index, ((path, role), bytes))| {
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
                dependencies: if index == 0 { vec![1, 2] } else { vec![] },
            }
        })
        .collect();
        let closure = CellReleaseClosureV1::new(context, 3, [0x41; 32], vec![0], files).unwrap();
        let expected = CellLoaderContextV1 {
            closure_id: closure.id(),
            context: closure.release().context().clone(),
            selected_generation: closure.selected_generation(),
            loader_profile: closure.loader_profile(),
            required_roles: vec![
                CellFileRoleV1::Base,
                CellFileRoleV1::Adapter,
                CellFileRoleV1::Tokenizer,
            ],
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
            &closure,
            &expected,
            deadline(),
            &AtomicBool::new(false),
        )
        .unwrap();
        Self {
            dir,
            store,
            pool,
            closure,
            expected,
            payloads,
        }
    }

    fn limits(&self) -> CellSealedLoaderLimitsV1 {
        CellSealedLoaderLimitsV1 {
            max_snapshot_bytes: self.payloads.iter().map(|bytes| bytes.len() as u64).sum(),
            max_files: self.payloads.len(),
        }
    }

    fn bundle(&self) -> CellSealedLoaderBundleV1<'_> {
        self.pool
            .seal_declared_loader(
                &self.expected,
                self.limits(),
                deadline(),
                &AtomicBool::new(false),
            )
            .unwrap()
    }
}

#[test]
fn complete_bundle_binds_declaration_and_real_kernel_seals() {
    let fixture = Fixture::new();
    let usage = fixture.pool.usage();
    let bundle = fixture.bundle();
    assert_eq!(bundle.closure_id(), fixture.closure.id());
    assert_eq!(bundle.closure(), &fixture.closure);
    assert_eq!(bundle.selected_generation(), 3);
    assert_eq!(bundle.loader_profile(), fixture.expected.loader_profile);
    assert_eq!(bundle.snapshot_bytes(), fixture.limits().max_snapshot_bytes);
    assert_eq!(bundle.file_count(), fixture.payloads.len());
    for (index, declared) in fixture.closure.files().iter().enumerate() {
        let mut file = bundle.file(&declared.path, declared.role).unwrap();
        assert_eq!(file.path(), declared.path);
        assert_eq!(file.role(), declared.role);
        assert_eq!(file.manifest_id(), declared.manifest);
        assert_eq!(file.payload_sha256(), declared.payload_sha256);
        assert_eq!(file.payload_bytes(), declared.payload_bytes);
        assert!(fcntl_getfd(file.as_fd())
            .unwrap()
            .contains(FdFlags::CLOEXEC));
        assert!(fcntl_get_seals(file.as_fd())
            .unwrap()
            .contains(required_seals()));
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, fixture.payloads[index]);
        let expected_content: [u8; 64] = Sha512::digest(
            [
                b"TRNM/Cell/PayloadContent/v2\0".as_slice(),
                &(bytes.len() as u64).to_be_bytes(),
                bytes.as_slice(),
            ]
            .concat(),
        )
        .into();
        assert_eq!(file.payload_sha512(), expected_content);
        assert_ne!(
            file.payload_sha512(),
            <[u8; 64]>::from(Sha512::digest(&bytes))
        );
        assert_eq!(file.read(&mut [0; 8]).unwrap(), 0);
    }
    assert_eq!(fixture.pool.usage(), usage);
    assert!(fixture.pool.selection().is_none());
}

#[test]
fn raw_native_descriptor_rejects_write_truncate_grow_and_execute_permission() {
    let fixture = Fixture::new();
    let bundle = fixture.bundle();
    let file = bundle
        .file("base/model.safetensors", CellFileRoleV1::Base)
        .unwrap();
    let mut duplicate = File::from(file.as_fd().try_clone_to_owned().unwrap());
    assert_eq!(
        duplicate.write_all(b"changed").unwrap_err().raw_os_error(),
        Some(libc::EPERM)
    );
    assert_eq!(
        duplicate.set_len(0).unwrap_err().raw_os_error(),
        Some(libc::EPERM)
    );
    assert_eq!(
        duplicate
            .set_len(file.payload_bytes() + 1)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EPERM)
    );
    assert_eq!(
        fchmod(&duplicate, Mode::RUSR | Mode::XUSR).unwrap_err(),
        rustix::io::Errno::PERM
    );
    assert_eq!(
        fcntl_add_seals(&duplicate, SealFlags::SHRINK).unwrap_err(),
        rustix::io::Errno::PERM
    );
    let mut bytes = vec![0; file.payload_bytes() as usize];
    duplicate.read_exact_at(&mut bytes, 0).unwrap();
    assert_eq!(bytes, fixture.payloads[1]);
}

#[test]
fn native_child_consumes_actual_sealed_fd_bytes() {
    let fixture = Fixture::new();
    let bundle = fixture.bundle();
    let file = bundle
        .file("base/model.safetensors", CellFileRoleV1::Base)
        .unwrap();
    // Real native process transport through an explicitly selected standard
    // descriptor. This is a finite byte-consumption control, not Hepta Ready.
    let result = Command::new("/bin/cat")
        .stdin(Stdio::from(file.as_fd().try_clone_to_owned().unwrap()))
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    assert_eq!(result.stdout, fixture.payloads[1]);
}

#[test]
fn native_tensor_parser_reads_declared_sealed_container() {
    let fixture = Fixture::new();
    let root = CellModelReleaseRootV1::new(fixture.closure.clone(), vec![]).unwrap();
    let contract = CellTensorContractV1::new(
        root.id(),
        [(0, 3), (1, ELEMENTS)]
            .into_iter()
            .map(|(index, count)| CellTensorFileV1 {
                file_index: index,
                tensors: vec![CellTensorSpecV1 {
                    name: "weights".into(),
                    dtype: CellTensorDTypeV1::F32,
                    shape: vec![count as u64],
                }],
            })
            .collect(),
    )
    .unwrap();
    let bundle = fixture.bundle();
    for index in [0, 1] {
        let declared = &fixture.closure.files()[index];
        let mut file = bundle.file(&declared.path, declared.role).unwrap();
        let readback = contract
            .verify_reader(&root, contract.id(), index as u16, &mut file, deadline())
            .unwrap();
        assert_eq!(readback.payload_bytes, declared.payload_bytes);
        assert_eq!(readback.payload_sha256, declared.payload_sha256);
        assert_eq!(readback.tensor_count, 1);
    }
}

#[test]
fn exact_declared_path_and_role_have_no_ambient_fallback() {
    let fixture = Fixture::new();
    fs::write(fixture.dir.path().join("ambient.bin"), b"undeclared").unwrap();
    let bundle = fixture.bundle();
    for path in [
        "",
        "base/model.safetensors/",
        "./base/model.safetensors",
        "/base/model.safetensors",
        "base/../base/model.safetensors",
        "BASE/model.safetensors",
        "base\\model.safetensors",
        "ambient.bin",
        "base/model.safetensors\0",
    ] {
        assert!(bundle.file(path, CellFileRoleV1::Base).is_err(), "{path:?}");
    }
    assert!(bundle
        .file("base/model.safetensors", CellFileRoleV1::Tokenizer)
        .is_err());
    assert!(bundle
        .file("tokenizer.json", CellFileRoleV1::Configuration)
        .is_err());
}

#[test]
fn independent_reader_cursors_and_failed_seek_do_not_change_other_readers() {
    let fixture = Fixture::new();
    let bundle = fixture.bundle();
    let mut a = bundle
        .file("base/model.safetensors", CellFileRoleV1::Base)
        .unwrap();
    let mut b = bundle
        .file("base/model.safetensors", CellFileRoleV1::Base)
        .unwrap();
    a.seek(SeekFrom::Start(CHUNK_BYTES as u64 - 3)).unwrap();
    let mut crossing = [0; 16];
    a.read_exact(&mut crossing).unwrap();
    assert_eq!(
        crossing,
        fixture.payloads[1][CHUNK_BYTES - 3..CHUNK_BYTES + 13]
    );
    let mut prefix = [0; 8];
    b.read_exact(&mut prefix).unwrap();
    assert_eq!(prefix, fixture.payloads[1][..8]);
    let prior = b.stream_position().unwrap();
    assert!(b.seek(SeekFrom::Current(-9)).is_err());
    assert_eq!(b.stream_position().unwrap(), prior);
    b.seek(SeekFrom::End(0)).unwrap();
    assert_eq!(b.read(&mut prefix).unwrap(), 0);
    b.seek(SeekFrom::Start(u64::MAX)).unwrap();
    assert!(b.seek(SeekFrom::Current(1)).is_err());
    assert_eq!(b.stream_position().unwrap(), u64::MAX);
}

#[test]
fn cache_replacement_cannot_change_the_handed_off_bytes() {
    let fixture = Fixture::new();
    let bundle = fixture.bundle();
    // A hostile replacement of the source pathname after admission has no
    // influence on the anonymous objects the loader actually consumes.
    let path = fixture.dir.path().join("cache.sqlite");
    fs::rename(&path, fixture.dir.path().join("original.sqlite")).unwrap();
    fs::write(path, b"replacement cache is not the admitted model").unwrap();
    let mut file = bundle
        .file("base/model.safetensors", CellFileRoleV1::Base)
        .unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, fixture.payloads[1]);
    // Keep the real original cache owner live through the replacement control.
    assert!(fixture
        .store
        .manifest(fixture.closure.files()[1].manifest)
        .is_ok());
}

#[test]
fn complete_snapshot_limits_and_owner_pins_reject_before_copying() {
    let fixture = Fixture::new();
    let visits = Rc::new(RefCell::new(0usize));
    let count = Rc::clone(&visits);
    with_hook(Box::new(move |_, _, _| *count.borrow_mut() += 1), || {
        let limits = fixture.limits();
        for wrong in [
            CellSealedLoaderLimitsV1 {
                max_snapshot_bytes: limits.max_snapshot_bytes - 1,
                ..limits
            },
            CellSealedLoaderLimitsV1 {
                max_files: limits.max_files - 1,
                ..limits
            },
            CellSealedLoaderLimitsV1 {
                max_snapshot_bytes: 0,
                ..limits
            },
            CellSealedLoaderLimitsV1 {
                max_files: MAX_CELL_CLOSURE_FILES_V1 + 1,
                ..limits
            },
        ] {
            assert!(fixture
                .pool
                .seal_declared_loader(
                    &fixture.expected,
                    wrong,
                    deadline(),
                    &AtomicBool::new(false)
                )
                .is_err());
        }
        for field in 0..4 {
            let mut wrong = fixture.expected.clone();
            match field {
                0 => wrong.closure_id[0] ^= 1,
                1 => wrong.selected_generation += 1,
                2 => wrong.loader_profile[0] ^= 1,
                _ => wrong.context.runtime[0] ^= 1,
            }
            assert!(fixture
                .pool
                .seal_declared_loader(&wrong, limits, deadline(), &AtomicBool::new(false))
                .is_err());
        }
    });
    assert_eq!(*visits.borrow(), 0);
}

#[derive(Debug)]
struct ObservedFd {
    fd: i32,
    device: u64,
    inode: u64,
}

fn observe_fd(file: &File) -> ObservedFd {
    let metadata = file.metadata().unwrap();
    ObservedFd {
        fd: file.as_raw_fd(),
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn assert_closed(fds: &[ObservedFd]) {
    assert!(!fds.is_empty());
    for observed in fds {
        // File descriptor numbers are process-wide and can already belong to
        // another parallel test after close. Reject the original live object,
        // rather than requiring the integer slot to remain unused.
        match fs::metadata(format!("/proc/self/fd/{}", observed.fd)) {
            Ok(current) => assert_ne!(
                (current.dev(), current.ino()),
                (observed.device, observed.inode),
                "original loader descriptor is still open: {}",
                observed.fd,
            ),
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::NotFound),
        }
    }
}

#[test]
#[should_panic(expected = "original loader descriptor is still open")]
fn closure_probe_rejects_a_live_original_descriptor() {
    let file = tempfile::tempfile().unwrap();
    assert_closed(&[observe_fd(&file)]);
}

#[test]
fn copied_byte_corruption_is_rejected_by_postseal_full_hash_without_partial_bundle() {
    let fixture = Fixture::new();
    let usage = fixture.pool.usage();
    let fds = Rc::new(RefCell::new(Vec::new()));
    let observed = Rc::clone(&fds);
    let outcome = with_hook(
        Box::new(move |index, stage, file| {
            if stage == Stage::BeforeSeal {
                observed.borrow_mut().push(observe_fd(file));
                if index == 1 {
                    file.write_all_at(b"!", 0).unwrap();
                }
            }
        }),
        || {
            fixture.pool.seal_declared_loader(
                &fixture.expected,
                fixture.limits(),
                deadline(),
                &AtomicBool::new(false),
            )
        },
    );
    assert!(matches!(
        outcome,
        Err(CellErrorV1::Invalid(
            "sealed loader complete payload digest"
        ))
    ));
    assert_eq!(fixture.pool.usage(), usage);
    assert!(fixture.pool.selection().is_none());
    assert_eq!(fds.borrow().len(), 2);
    assert_closed(&fds.borrow());
}

#[test]
fn cancellation_after_one_sealed_file_closes_all_unpublished_descriptors() {
    let fixture = Fixture::new();
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&cancelled);
    let fds = Rc::new(RefCell::new(Vec::new()));
    let observed = Rc::clone(&fds);
    let outcome = with_hook(
        Box::new(move |_, stage, file| {
            if stage == Stage::Verified {
                observed.borrow_mut().push(observe_fd(file));
                signal.store(true, Ordering::Release);
            }
        }),
        || {
            fixture.pool.seal_declared_loader(
                &fixture.expected,
                fixture.limits(),
                deadline(),
                &cancelled,
            )
        },
    );
    assert!(matches!(
        outcome,
        Err(CellErrorV1::Invalid("resident operation cancelled"))
    ));
    assert_eq!(fds.borrow().len(), 1);
    assert_closed(&fds.borrow());
    assert!(fixture.pool.selection().is_none());
}

#[test]
fn one_original_deadline_covers_late_member_readback() {
    let fixture = Fixture::new();
    let until = Instant::now() + Duration::from_millis(20);
    let fds = Rc::new(RefCell::new(Vec::new()));
    let observed = Rc::clone(&fds);
    let outcome = with_hook(
        Box::new(move |index, stage, file| {
            if stage == Stage::BeforeSeal {
                observed.borrow_mut().push(observe_fd(file));
            }
            if index == 1 && stage == Stage::Verified {
                std::thread::sleep(
                    until.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
                );
            }
        }),
        || {
            fixture.pool.seal_declared_loader(
                &fixture.expected,
                fixture.limits(),
                until,
                &AtomicBool::new(false),
            )
        },
    );
    assert!(matches!(
        outcome,
        Err(CellErrorV1::Invalid("resident operation deadline"))
    ));
    assert_eq!(fds.borrow().len(), 2);
    assert_closed(&fds.borrow());
}

#[test]
fn preexisting_cancel_or_expired_deadline_never_copies_a_member() {
    let fixture = Fixture::new();
    with_hook(
        Box::new(|_, _, _| panic!("preflight must reject before copying")),
        || {
            assert!(fixture
                .pool
                .seal_declared_loader(
                    &fixture.expected,
                    fixture.limits(),
                    deadline(),
                    &AtomicBool::new(true)
                )
                .is_err());
            assert!(fixture
                .pool
                .seal_declared_loader(
                    &fixture.expected,
                    fixture.limits(),
                    Instant::now() - Duration::from_secs(1),
                    &AtomicBool::new(false)
                )
                .is_err());
        },
    );
}
