use std::{
    fs::File,
    io::{self, IoSliceMut},
    mem::MaybeUninit,
    os::{
        fd::AsFd,
        unix::{fs::FileExt, net::UnixStream},
    },
    sync::atomic::Ordering,
    thread,
};

use rustix::{
    fs::{fcntl_get_seals, SealFlags},
    io::{fcntl_getfd, FdFlags},
    net::{recvmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags},
    time::{clock_gettime, ClockId},
};

use super::*;

fn with_research_handoff(
    action: impl FnOnce(&CellHostHandoffV1<'_, '_, '_>, &CellHostResearchExecutionV1),
) {
    let (_dir, store, content) = captured();
    let (signer, pin) = key();
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    let current = CellPqContentExpectationV4 {
        authority: CellPqReleaseExpectationV2 {
            network: [6; 32],
            parameters: [7; 32],
            key: &pin,
            sequence: 4,
            now: 300,
        },
        loader: CellVersionLoaderContextV1 {
            commitment: content.version().commitment(),
            model: &model,
            environment: &environment,
        },
        content: content.commitment(),
    };
    let signed = CellPqContentAuthorizationV4::sign(
        CellPqContentStatementV4 {
            network: [6; 32],
            parameters: [7; 32],
            content: content.commitment(),
            signer_key_id: pin.key_id,
            signer_spki_sha512: CellPqContentStatementV4::signer_commitment(&pin.spki),
            generation: 2,
            sequence: 4,
            issued_at: 200,
            expires_at: 900,
            withdrawn: false,
        },
        &signer,
    )
    .unwrap();
    let authorization = signed
        .verify_cached_at(&content, &store, &current, &mut session(1))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let cancelled = AtomicBool::new(false);
    let mut pool = CellResidencyV1::new(CellResidencyConfigV1 {
        max_resident_bytes: 4 * 32769,
        max_resident_closures: 2,
        max_chunk_references: 12,
    })
    .unwrap();
    for (closure, expected) in [
        (content.version().model().closure(), &model),
        (content.version().environment(), &environment),
    ] {
        pool.prepare_cached(&store, closure, expected, deadline, &cancelled)
            .unwrap();
    }
    let limits = CellSealedLoaderLimitsV1 {
        max_snapshot_bytes: 2 * 32769,
        max_files: 2,
    };
    let model_bundle = pool
        .seal_declared_loader(&model, limits, deadline, &cancelled)
        .unwrap();
    let environment_bundle = pool
        .seal_declared_loader(&environment, limits, deadline, &cancelled)
        .unwrap();
    let descriptor = descriptor(&content);
    let handoff = descriptor
        .bind_authenticated(
            descriptor.commitment().unwrap(),
            &authorization,
            &current,
            (&model_bundle, &environment_bundle),
            deadline,
        )
        .unwrap();
    let execution = CellHostResearchExecutionV1 {
        schema: "trnm.cell-sealed-research-execution.v1".into(),
        operation: hex::encode(descriptor.operation),
        descriptor: hex::encode(descriptor.commitment().unwrap()),
        environment_pins: content
            .version()
            .environment()
            .files()
            .iter()
            .map(|file| (file.path.clone(), hex::encode(file.payload_sha256)))
            .collect(),
        max_snapshot_bytes: 4 * 32769,
        runtime_rss_bytes: 1024 * 1024,
        python: "/independently/pinned/research-python".into(),
        python_sha256: hex::encode([17; 32]),
        output: "/independently/owned/research-output".into(),
        threads: 1,
        material_profile: "current-contract-v1".into(),
        parent: CellHostResearchParentV1 {
            generation: descriptor.model_generation,
            operation_id: "original-parent-operation".into(),
            contract: hex::encode(descriptor.worker_context.layout),
            adapter: hex::encode([18; 32]),
            file_sha256: hex::encode(descriptor.worker_context.parent),
        },
        requests: vec![
            CellHostResearchQueryV1 {
                request_id: "first".into(),
                prompt: "First original query".into(),
            },
            CellHostResearchQueryV1 {
                request_id: "next".into(),
                prompt: "Next original query".into(),
            },
        ],
    };
    action(&handoff, &execution);
}

#[test]
fn research_fd_sender_transfers_actual_complete_sealed_pair_with_original_deadline() {
    with_research_handoff(|handoff, execution| {
        let (mut producer, mut consumer) = UnixStream::pair().unwrap();
        let cancelled = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(3);
        consumer
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let before = clock_gettime(ClockId::Monotonic);
        thread::scope(|scope| {
            let sender = scope.spawn(|| {
                handoff.send_research_fds_v1(&mut producer, execution, deadline, &cancelled)
            });
            let mut length = [0; 4];
            consumer.read_exact(&mut length).unwrap();
            let length = u32::from_be_bytes(length) as usize;
            assert!(length <= MAX_CELL_RESEARCH_FD_HEADER_V1);
            let mut raw = vec![0; length];
            consumer.read_exact(&mut raw).unwrap();
            let header: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(
                header["execution"],
                serde_json::to_value(execution).unwrap()
            );
            let wire = hex::decode(header["descriptor"].as_str().unwrap()).unwrap();
            assert_eq!(wire, handoff.descriptor().encode().unwrap());
            let end = header["deadline_monotonic_ns"].as_u64().unwrap();
            let start = before.tv_sec as u64 * 1_000_000_000 + before.tv_nsec as u64;
            assert!(end > start && end <= start + 3_000_000_000);
            let rows = header["files"].as_array().unwrap();
            assert_eq!(rows.len(), 4);
            for row in rows {
                let mut marker = [0];
                let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
                let mut control = RecvAncillaryBuffer::new(&mut space);
                let received = recvmsg(
                    &consumer,
                    &mut [IoSliceMut::new(&mut marker)],
                    &mut control,
                    RecvFlags::CMSG_CLOEXEC,
                )
                .unwrap();
                assert_eq!(received.bytes, 1);
                assert_eq!(marker, [b'F']);
                let mut files = Vec::new();
                for message in control.drain() {
                    if let RecvAncillaryMessage::ScmRights(fds) = message {
                        files.extend(fds);
                    } else {
                        panic!("unexpected ancillary record");
                    }
                }
                assert_eq!(files.len(), 1);
                let file = File::from(files.pop().unwrap());
                assert!(fcntl_getfd(file.as_fd())
                    .unwrap()
                    .contains(FdFlags::CLOEXEC));
                assert!(fcntl_get_seals(file.as_fd()).unwrap().contains(
                    SealFlags::SEAL
                        | SealFlags::WRITE
                        | SealFlags::SHRINK
                        | SealFlags::GROW
                        | SealFlags::EXEC
                ));
                let mut bytes = vec![0; row["bytes"].as_u64().unwrap() as usize];
                file.read_exact_at(&mut bytes, 0).unwrap();
                assert_eq!(
                    hex::encode(Sha256::digest(&bytes)),
                    row["sha256"].as_str().unwrap()
                );
                assert!(file.write_at(b"changed", 0).is_err());
            }
            sender.join().unwrap().unwrap();
        });
    });
}

#[test]
fn research_fd_sender_refuses_changed_pins_budget_task_parent_or_expiry_before_any_byte() {
    with_research_handoff(|handoff, execution| {
        let (mut producer, mut consumer) = UnixStream::pair().unwrap();
        consumer.set_nonblocking(true).unwrap();
        let cancelled = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(3);
        for change in 0..8 {
            let mut bad = execution.clone();
            match change {
                0 => bad.operation = hex::encode([0; 32]),
                1 => bad.descriptor = "00".repeat(64),
                2 => *bad.environment_pins.values_mut().next().unwrap() = hex::encode([0; 32]),
                3 => {
                    bad.environment_pins.pop_first();
                }
                4 => bad.max_snapshot_bytes -= 1,
                5 => bad.requests[1].request_id = bad.requests[0].request_id.clone(),
                6 => bad.parent.generation += 1,
                _ => bad.material_profile = "implicit-old-material-fallback".into(),
            }
            assert!(handoff
                .send_research_fds_v1(&mut producer, &bad, deadline, &cancelled)
                .is_err());
            assert_eq!(
                consumer.read(&mut [0]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
        cancelled.store(true, Ordering::SeqCst);
        assert!(handoff
            .send_research_fds_v1(&mut producer, execution, deadline, &cancelled)
            .is_err());
        cancelled.store(false, Ordering::SeqCst);
        assert!(handoff
            .send_research_fds_v1(&mut producer, execution, Instant::now(), &cancelled)
            .is_err());
        assert_eq!(
            consumer.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    });
}
