// Appended only to the byte-exact original payload.rs in an isolated oracle.
// All hashes, record encoding/decoding and state transitions call original code.
pub fn qualification_payload_codec_v1(
    store: &mut PayloadReplayStoreV1,
    op: u64,
    input: &[u8],
) -> (u32, Vec<u8>) {
    fn word(input: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(input[at..at + 8].try_into().unwrap())
    }
    fn digest(input: &[u8], at: usize) -> [u8; 32] {
        input[at..at + 32].try_into().unwrap()
    }
    fn namespace(input: &[u8]) -> Result<PayloadReplayNamespaceV1, PayloadReplayErrorV1> {
        PayloadReplayNamespaceV1::new(
            digest(input, 0),
            word(input, 128),
            digest(input, 32),
            digest(input, 64),
            digest(input, 96),
        )
    }
    fn direction(value: u64) -> Result<PeerLeaseDirectionV1, u32> {
        match value {
            1 => Ok(PeerLeaseDirectionV1::Outbound),
            2 => Ok(PeerLeaseDirectionV1::Inbound),
            _ => Err(100),
        }
    }
    fn category(error: PayloadReplayErrorV1) -> u32 {
        match error {
            PayloadReplayErrorV1::Truncated => 2,
            PayloadReplayErrorV1::Corrupt => 3,
            PayloadReplayErrorV1::ContextMismatch => 4,
            PayloadReplayErrorV1::Replay => 5,
            PayloadReplayErrorV1::StaleGeneration => 6,
            PayloadReplayErrorV1::SequenceGap => 7,
            PayloadReplayErrorV1::TooLarge => 8,
            PayloadReplayErrorV1::Poisoned => 9,
            PayloadReplayErrorV1::InvalidRequest(_) => 10,
            PayloadReplayErrorV1::Io(_) => 11,
            PayloadReplayErrorV1::Protocol(_) => 12,
            PayloadReplayErrorV1::CommitAmbiguous(_) => 13,
        }
    }
    fn run(store: &mut PayloadReplayStoreV1, op: u64, input: &[u8]) -> Result<Vec<u8>, u32> {
        if op == 8 {
            if input.len() < 136 {
                return Err(100);
            }
            let ns = namespace(input).map_err(category)?;
            let snapshot = parse_log(&input[136..], ns, ns.digest()).map_err(category)?;
            let mut output = Vec::new();
            output.extend_from_slice(&snapshot.record_count.to_le_bytes());
            output.extend_from_slice(&snapshot.last_hash);
            for count in [
                snapshot.states.len(),
                snapshot.seen_sessions.len(),
                snapshot.frame_receipts.len(),
                snapshot.frame_positions.len(),
            ] {
                output.extend_from_slice(&(count as u64).to_le_bytes());
            }
            return Ok(output);
        }
        let size = match op {
            1 | 2 => 136,
            3 => 448,
            4 => 72,
            5 => 380,
            6 => 116,
            7 => 56,
            _ => return Err(100),
        };
        if input.len() != size {
            return Err(match op {
                5 => 2,
                6 => 3,
                _ => 100,
            });
        }
        let mut out = Vec::new();
        match op {
            1 => out.extend_from_slice(&namespace(input).map_err(category)?.digest()),
            2 => {
                let ns = namespace(input).map_err(category)?;
                out.extend_from_slice(&encode_record(None, ns, ns.digest(), 0, [0; 32]));
            }
            3 => {
                let ns = namespace(input).map_err(category)?;
                let value = &input[136..408];
                let scope = PeerLeaseScopeV1::new(
                    digest(value, 0),
                    digest(value, 32),
                    direction(word(value, 96))?,
                    word(value, 104),
                    digest(value, 64),
                )
                .map_err(|_| 10_u32)?;
                let kind = u8::try_from(word(value, 224)).map_err(|_| 100_u32)?;
                let frame = PayloadReplayFrameV1::new(
                    scope,
                    digest(value, 112),
                    digest(value, 144),
                    digest(value, 176),
                    word(value, 208),
                    word(value, 216),
                    kind,
                    usize::try_from(word(value, 232)).map_err(|_| 8_u32)?,
                    digest(value, 240),
                )
                .map_err(category)?;
                out.extend_from_slice(&encode_record(
                    Some(&frame),
                    ns,
                    ns.digest(),
                    word(input, 408),
                    digest(input, 416),
                ));
            }
            4 => out.extend_from_slice(&encode_head(
                word(input, 0),
                digest(input, 8),
                digest(input, 40),
            )),
            5 => {
                let r = decode_record(input).map_err(category)?;
                out.extend_from_slice(&(r.operation as u64).to_le_bytes());
                out.extend_from_slice(&r.index.to_le_bytes());
                for bytes in [r.namespace_digest, r.local_id, r.remote_id] {
                    out.extend_from_slice(&bytes);
                }
                out.extend_from_slice(&(r.direction.map(|d| d as u64).unwrap_or(0)).to_le_bytes());
                out.extend_from_slice(&r.epoch.to_le_bytes());
                for bytes in [
                    r.peer_scope_id,
                    r.run_id_hash,
                    r.network_context_hash,
                    r.session_id,
                ] {
                    out.extend_from_slice(&bytes);
                }
                for word in [
                    r.generation,
                    r.sequence,
                    r.frame_kind as u64,
                    r.payload_len as u64,
                ] {
                    out.extend_from_slice(&word.to_le_bytes());
                }
                for bytes in [r.frame_fingerprint, r.predecessor, r.record_hash] {
                    out.extend_from_slice(&bytes);
                }
            }
            6 => {
                let (count, hash, ns) = decode_head(input).map_err(category)?;
                out.extend_from_slice(&count.to_le_bytes());
                out.extend_from_slice(&hash);
                out.extend_from_slice(&ns);
            }
            7 => {
                if [0, 24, 32].iter().any(|at| word(input, *at) > 1)
                    || (word(input, 0) == 0 && word(input, 24) != 0)
                {
                    return Err(100);
                }
                let key = PeerKeyV1 {
                    remote_id: [2; 32],
                    direction: PeerLeaseDirectionV1::Outbound,
                };
                let session_id = if word(input, 24) != 0 {
                    [7; 32]
                } else {
                    [8; 32]
                };
                store.states.clear();
                store.seen_sessions.clear();
                if word(input, 0) != 0 {
                    store.states.insert(
                        key,
                        ReplayStateV1 {
                            session_id: [7; 32],
                            generation: word(input, 8),
                            last_sequence: word(input, 16),
                            last_fingerprint: [9; 32],
                        },
                    );
                }
                if word(input, 32) != 0 {
                    store.seen_sessions.insert((key, session_id));
                }
                let frame = PayloadReplayFrameV1 {
                    scope: PeerLeaseScopeV1::new(
                        [1; 32],
                        [2; 32],
                        PeerLeaseDirectionV1::Outbound,
                        7,
                        [3; 32],
                    )
                    .unwrap(),
                    run_id_hash: [4; 32],
                    network_context_hash: [5; 32],
                    session_id,
                    generation: word(input, 40),
                    sequence: word(input, 48),
                    frame_kind: 1,
                    payload_len: 0,
                    frame_fingerprint: [9; 32],
                };
                store.preview_state(key, frame).map_err(category)?;
            }
            _ => unreachable!(),
        }
        Ok(out)
    }
    match run(store, op, input) {
        Ok(bytes) => (0, bytes),
        Err(code) => (code, Vec::new()),
    }
}
