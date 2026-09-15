use super::*;
use crate::{
    write_native_catchup_stream_v1, NativeCatchupStreamErrorV1, NativeCatchupStreamLimitsV1,
};
use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    ops::Range,
    time::Duration,
};

fn wire_limits() -> NativeCatchupStreamLimitsV1 {
    NativeCatchupStreamLimitsV1::new(64 * 1024 * 1024, 8 * 1024 * 1024, 64).unwrap()
}
fn transfer(f: &Fixture, base: &ApplicationHeadV0) -> Vec<u8> {
    let export = f
        .source
        .begin_finalized_snapshot_export_v1(
            POCO_THREE_CHAIN_PROOF_CLASS_V0,
            &f.proof_bytes[FINALIZED - 1],
            HeightV0::new(FINALIZED as u64),
            T0 + (FINALIZED as u64 - 1) * 1000,
            1024,
            &mut budget(),
        )
        .unwrap();
    let snapshot = f
        .source
        .pin_finalized_snapshot_export_v1(export, 64 * 1024 * 1024)
        .unwrap();
    let blocks = (base.height().get() as usize..FINALIZED).map(|i| {
        f.source.read_finalized_catchup_block_v1(
            &f.proof_bytes[i],
            HeightV0::new(i as u64 + 1),
            T0 + i as u64 * 1000,
            &mut budget(),
        )
    });
    let mut bytes = Vec::new();
    write_native_catchup_stream_v1(&mut bytes, base, &snapshot, blocks, wire_limits()).unwrap();
    bytes
}
fn receive(
    session: NativeFinalizedCatchupV1,
    bytes: &[u8],
) -> Result<RestoredNativeApplicationV1, NativeCatchupStreamErrorV1> {
    session.receive_framed_stream_v1(bytes, wire_limits(), snapshot_limits(), &mut budget())
}
fn frames(bytes: &[u8]) -> (Range<usize>, Vec<[Range<usize>; 3]>, usize) {
    let mut offset = 92;
    fn frame(bytes: &[u8], offset: &mut usize) -> Range<usize> {
        let n = u32::from_be_bytes(bytes[*offset..*offset + 4].try_into().unwrap()) as usize;
        let start = *offset + 4;
        *offset = start + n;
        start..*offset
    }
    let manifest = frame(bytes, &mut offset);
    let count = u32::from_be_bytes(bytes[88..92].try_into().unwrap());
    let blocks = (0..count)
        .map(|_| {
            [
                frame(bytes, &mut offset),
                frame(bytes, &mut offset),
                frame(bytes, &mut offset),
            ]
        })
        .collect();
    (manifest, blocks, offset)
}
fn destination(t: &TempDir) -> (std::path::PathBuf, DurableNativeApplicationV0) {
    let path = t.path().join("replica.sqlite");
    let app = open_with_config(&path, config_for_local(1));
    (path, app)
}
fn assert_recovered_next_block(f: &Fixture, restored: RestoredNativeApplicationV1) {
    assert_eq!(restored.head().height().get(), FINALIZED as u64);
    let application = restored.into_application();
    let next = f.session(application, Some(FINALIZED - 1));
    // Exact target has no suffix, but must still authenticate snapshot/trailer.
    let bytes = transfer(f, next.head());
    let restored = receive(next, &bytes).unwrap();
    assert_eq!(
        restored.head().state_root().as_bytes(),
        f.headers[FINALIZED - 1].state_root().as_bytes()
    );
    let app = restored.into_application();
    let cfg = app.config_v0();
    let preview = app
        .preview_block_v0(
            &NativeBlockPreviewRequestV0::new(
                ChainIdV0::new(cfg.chain_id_v0()).unwrap(),
                GenesisHashV0::new(cfg.genesis_hash_v0()).unwrap(),
                app.confirmed_committed_head_v0().unwrap(),
                HeightV0::new(FINALIZED as u64 + 1),
                f.headers[FINALIZED].timestamp_ms(),
                ValidatorSetIdV0::new(*cfg.validator_set_v0().id().as_bytes()).unwrap(),
                f.executed[FINALIZED].request().transactions().to_vec(),
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        preview.post_state_root().as_bytes(),
        f.headers[FINALIZED].state_root().as_bytes()
    );
}

#[test]
fn real_source_stream_replays_transactions_empty_block_and_finishes_exact_snapshot() {
    let f = Fixture::new();
    let t = TempDir::new().unwrap();
    let (_, app) = destination(&t);
    let session = f.session(app, None);
    let bytes = transfer(&f, session.head());
    assert_recovered_next_block(&f, receive(session, &bytes).unwrap());
}
#[test]
fn fragmented_reader_is_equivalent_and_never_needs_entire_transfer_buffer() {
    struct Fragmented<'a>(&'a [u8]);
    impl Read for Fragmented<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = out.len().min(7);
            self.0.read(&mut out[..n])
        }
    }
    let f = Fixture::new();
    let t = TempDir::new().unwrap();
    let (_, app) = destination(&t);
    let session = f.session(app, None);
    let bytes = transfer(&f, session.head());
    let restored = session
        .receive_framed_stream_v1(
            Fragmented(&bytes),
            wire_limits(),
            snapshot_limits(),
            &mut budget(),
        )
        .unwrap();
    assert_recovered_next_block(&f, restored);
}
#[test]
fn preamble_and_manifest_substitution_reject_before_any_execution() {
    let f = Fixture::new();
    for index in [0, 8, 16, 48, 56, 88, 96, 104, 136] {
        let t = TempDir::new().unwrap();
        let (path, app) = destination(&t);
        let session = f.session(app, None);
        let mut bytes = transfer(&f, session.head());
        bytes[index] ^= 0x80;
        assert!(receive(session, &bytes).is_err(), "substitution at {index}");
        let app = DurableNativeApplicationV0::open(&path, config_for_local(1)).unwrap();
        assert_eq!(app.confirmed_committed_head_v0().unwrap().height().get(), 0);
        assert_eq!(row_count(&path), 0);
    }
}
#[test]
fn oversized_frame_is_rejected_before_body_read_or_allocation() {
    struct NoBody {
        prefix: io::Cursor<Vec<u8>>,
    }
    impl Read for NoBody {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            assert!(
                self.prefix.position() < self.prefix.get_ref().len() as u64,
                "oversized body was read"
            );
            self.prefix.read(out)
        }
    }
    let f = Fixture::new();
    let t = TempDir::new().unwrap();
    let (path, app) = destination(&t);
    let session = f.session(app, None);
    let mut bytes = transfer(&f, session.head());
    bytes.truncate(96);
    bytes[92..96].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        session.receive_framed_stream_v1(
            NoBody {
                prefix: io::Cursor::new(bytes)
            },
            wire_limits(),
            snapshot_limits(),
            &mut budget()
        ),
        Err(NativeCatchupStreamErrorV1::Limit)
    ));
    assert_eq!(row_count(&path), 0);
}
#[test]
fn signature_work_budget_is_shared_and_rejects_before_prepared_record() {
    let f = Fixture::new();
    let t = TempDir::new().unwrap();
    let (path, app) = destination(&t);
    let session = f.session(app, None);
    let bytes = transfer(&f, session.head());
    let mut empty = Cev0AdmissionBudgetV0::new(8 * 1024 * 1024, 0);
    assert!(session
        .receive_framed_stream_v1(
            bytes.as_slice(),
            wire_limits(),
            snapshot_limits(),
            &mut empty
        )
        .is_err());
    assert_eq!(row_count(&path), 0);
}
#[test]
fn bad_later_proof_retains_only_previously_finalized_prefix() {
    let f = Fixture::new();
    let t = TempDir::new().unwrap();
    let (path, app) = destination(&t);
    let session = f.session(app, None);
    let mut bytes = transfer(&f, session.head());
    let (_, blocks, _) = frames(&bytes);
    bytes[blocks[1][2].end - 1] ^= 1;
    assert!(receive(session, &bytes).is_err());
    let app = DurableNativeApplicationV0::open(&path, config_for_local(1)).unwrap();
    assert_eq!(app.confirmed_committed_head_v0().unwrap().height().get(), 1);
    assert_eq!(row_count(&path), 1);
    let session = f.session(app, Some(0));
    let good = transfer(&f, session.head());
    assert_recovered_next_block(&f, receive(session, &good).unwrap());
}
#[test]
fn snapshot_or_terminal_failure_never_releases_owner_and_can_resume_zero_suffix() {
    let f = Fixture::new();
    for mode in 0..4 {
        let t = TempDir::new().unwrap();
        let (path, app) = destination(&t);
        let session = f.session(app, None);
        let mut bytes = transfer(&f, session.head());
        let (_, _, chunks) = frames(&bytes);
        match mode {
            0 => bytes[chunks + 4] ^= 1,
            1 => {
                bytes.pop();
            }
            2 => bytes.push(0),
            _ => {
                let n = bytes.len();
                bytes[n - 1] ^= 1;
            }
        }
        assert!(receive(session, &bytes).is_err());
        let app = DurableNativeApplicationV0::open(&path, config_for_local(1)).unwrap();
        assert_eq!(app.confirmed_committed_head_v0().unwrap().height().get(), 3);
        assert_eq!(row_count(&path), 3);
        let session = f.session(app, Some(2));
        let good = transfer(&f, session.head());
        assert_recovered_next_block(&f, receive(session, &good).unwrap());
    }
}
#[test]
fn source_local_commit_id_is_not_imported_as_receiver_authority() {
    let f = Fixture::new();
    let t = TempDir::new().unwrap();
    let (_, app) = destination(&t);
    let session = f.session(app, None);
    let mut bytes = transfer(&f, session.head());
    let (manifest, _, _) = frames(&bytes);
    let start = manifest.start + 72;
    bytes[start..start + 32].fill(0x59);
    let restored = receive(session, &bytes).unwrap();
    assert_ne!(restored.head().commit_id().as_bytes(), &[0x59; 32]);
    assert_recovered_next_block(&f, restored);
}
#[test]
fn exact_wire_budget_passes_and_too_small_limits_do_not_invent_success() {
    let f = Fixture::new();
    for short in [false, true] {
        let t = TempDir::new().unwrap();
        let (_, app) = destination(&t);
        let session = f.session(app, None);
        let bytes = transfer(&f, session.head());
        let max = bytes.len() as u64 - u64::from(short);
        let result = session.receive_framed_stream_v1(
            bytes.as_slice(),
            NativeCatchupStreamLimitsV1::new(max, 8 * 1024 * 1024, 64).unwrap(),
            snapshot_limits(),
            &mut budget(),
        );
        assert_eq!(result.is_ok(), !short);
    }
    assert!(NativeCatchupStreamLimitsV1::new(0, 1024, 1).is_err());
    assert!(NativeCatchupStreamLimitsV1::new(1024, 0, 1).is_err());
    assert!(NativeCatchupStreamLimitsV1::new(1024, 8 * 1024 * 1024 + 1, 1).is_err());
    assert!(NativeCatchupStreamLimitsV1::new(1024, 1024, 4097).is_err());
}

#[test]
fn tcp_receive_child_helper() {
    let Ok(address) = std::env::var("TRNM_STREAM_TEST_ADDRESS") else {
        return;
    };
    let path = std::path::PathBuf::from(std::env::var_os("TRNM_STREAM_TEST_PATH").unwrap());
    let f = Fixture::new();
    let app = open_with_config(&path, config_for_local(1));
    let session = f.session(app, None);
    let stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let result =
        session.receive_framed_stream_v1(stream, wire_limits(), snapshot_limits(), &mut budget());
    if std::env::var("TRNM_STREAM_TEST_EXPECT_FAILURE").as_deref() == Ok("1") {
        assert!(result.is_err());
    } else {
        assert_recovered_next_block(&f, result.unwrap());
    }
}
#[test]
fn actual_tcp_process_replays_and_recovers_disconnect_and_receiver_crash_cuts() {
    let f = Fixture::new();
    for mode in [
        "success",
        "source-disconnect",
        "after-prepare",
        "after-commit",
    ] {
        let t = TempDir::new().unwrap();
        let (path, app) = destination(&t);
        let base = app.confirmed_committed_head_v0().unwrap();
        drop(app);
        let mut bytes = transfer(&f, &base);
        let (_, blocks, _) = frames(&bytes);
        if mode == "source-disconnect" {
            bytes.truncate(blocks[0][2].end);
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "finalized_catchup_v1::tests::stream_tests::tcp_receive_child_helper",
                "--nocapture",
            ])
            .env(
                "TRNM_STREAM_TEST_ADDRESS",
                listener.local_addr().unwrap().to_string(),
            )
            .env("TRNM_STREAM_TEST_PATH", &path);
        if mode == "source-disconnect" {
            command.env("TRNM_STREAM_TEST_EXPECT_FAILURE", "1");
        }
        if mode.starts_with("after-") {
            command
                .env("TRNM_CATCHUP_TEST_CUT", mode)
                .env("TRNM_CATCHUP_TEST_PATH", &path);
        }
        let mut child = command.spawn().unwrap();
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let (mut socket, _) = loop {
            match listener.accept() {
                Ok(v) => break v,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!("child connect timeout");
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept: {e}"),
            }
        };
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let written = socket.write_all(&bytes);
        let _ = socket.shutdown(Shutdown::Write);
        drop(socket);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child exit timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        if mode.starts_with("after-") {
            assert_eq!(status.code(), Some(73));
        } else {
            written.unwrap();
            assert!(status.success());
        }
        let app = DurableNativeApplicationV0::open(&path, config_for_local(1)).unwrap();
        let height = app.confirmed_committed_head_v0().unwrap().height().get();
        let expected = match mode {
            "success" => 3,
            "after-prepare" => 0,
            _ => 1,
        };
        assert_eq!(height, expected, "{mode}");
        let current = height.checked_sub(1).map(|n| n as usize);
        let session = f.session(app, current);
        let bytes = transfer(&f, session.head());
        let restored = receive(session, &bytes).unwrap();
        assert_eq!(row_count(&path), 3);
        assert_recovered_next_block(&f, restored);
    }
}
