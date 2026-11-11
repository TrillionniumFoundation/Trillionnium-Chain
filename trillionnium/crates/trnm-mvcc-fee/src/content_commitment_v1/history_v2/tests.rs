use super::*;
use serde_json::json;
use trnm_protocol::{
    content_commitment::{observe_bytes, ContentCommitmentError},
    crypto_profile::{CryptoProfile, ProfileBinding, ProfileScope},
};

struct Fixture {
    cfg: Config,
    initial: State,
    states: Vec<State>,
    headers: Vec<Header>,
    traces: Vec<Hash>,
    genesis: Hash,
}

impl Fixture {
    fn new(count: usize) -> Self {
        let mut cfg = Config::installed().unwrap();
        cfg.params["genesis_timestamp"] = json!(1);
        let initial = State::from([("fixture:value".into(), json!(0))]);
        let genesis = hash(
            b"genesis",
            &[
                &cfg.network,
                &cfg.parameters,
                &root_for_config(&initial, &cfg).unwrap(),
                &1_u64.to_le_bytes(),
            ],
        );
        let mut value = Self {
            cfg,
            initial,
            states: Vec::new(),
            headers: Vec::new(),
            traces: Vec::new(),
            genesis,
        };
        let mut parent = genesis;
        for index in 0..count {
            let height = index as u64 + 1;
            let state = State::from([
                ("fixture:value".into(), json!(height)),
                ("fixture:zero-liability".into(), json!({"remaining":0})),
            ]);
            let header = Header {
                network: value.cfg.network,
                parameters: value.cfg.parameters,
                parent,
                height,
                timestamp: height + 1,
                target: [255; 32],
                miner: [4; 32],
                transactions: [5; 32],
                state: root_for_config(&state, &value.cfg).unwrap(),
                receipts: [6; 32],
                work_task: [7; 32],
                nonce: height,
            };
            let trace = [index as u8 + 11; 32];
            parent = header.block_id(trace);
            value.states.push(state);
            value.headers.push(header);
            value.traces.push(trace);
        }
        value
    }

    fn blocks(&self) -> Vec<MigrationHistoryBlockV2<'_>> {
        self.headers
            .iter()
            .zip(&self.traces)
            .zip(&self.states)
            .map(|((header, trace), state)| MigrationHistoryBlockV2 {
                header,
                trace: *trace,
                state,
            })
            .collect()
    }

    fn source<'a>(
        &'a self,
        blocks: &'a [MigrationHistoryBlockV2<'a>],
    ) -> MigrationHistorySourceV2<'a> {
        MigrationHistorySourceV2 {
            configuration: &self.cfg,
            genesis: self.genesis,
            genesis_timestamp: 1,
            initial_state: &self.initial,
            checkpoint: self
                .headers
                .last()
                .map_or(self.genesis, |h| h.block_id(*self.traces.last().unwrap())),
            blocks,
        }
    }

    fn pin(&self) -> ContentClaimV1 {
        observe_migration_history_v2(&context(), &mut budget(), self.source(&self.blocks()))
            .unwrap()
            .claim()
            .clone()
    }

    fn relink(&mut self) {
        let mut parent = self.genesis;
        for ((header, trace), state) in self.headers.iter_mut().zip(&self.traces).zip(&self.states)
        {
            header.parent = parent;
            header.state = root_for_config(state, &self.cfg).unwrap();
            parent = header.block_id(*trace);
        }
    }
}

fn context() -> ContentContextV1 {
    let profile = CryptoProfile::CandidateMlDsa65V1
        .bind(ProfileBinding {
            network: [1; 32],
            parameters: [2; 32],
            genesis: [3; 32],
            protocol_version: 1,
            scope: ProfileScope::WholeSystemCandidate,
            activation_height: 0,
            retirement_height: None,
        })
        .unwrap();
    ContentContextV1::new(&profile, ContentKind::MigrationCheckpoint, [9; 64], 7).unwrap()
}

fn budget() -> ContentReadBudget {
    ContentReadBudget::new(2, MAX_MIGRATION_HISTORY_BYTES_V2 + 1).unwrap()
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> &'a [u8] {
    let start = *cursor;
    *cursor += length;
    &bytes[start..*cursor]
}

fn check_snapshot_frame(bytes: &[u8], cursor: &mut usize, state: &State, cfg: &Config) {
    let length = u64::from_be_bytes(take(bytes, cursor, 8).try_into().unwrap());
    let (mut reader, expected_length) = SnapshotReader::new(state, cfg, Vec::new()).unwrap();
    let mut expected = Vec::new();
    reader.read_to_end(&mut expected).unwrap();
    assert_eq!(length, expected_length);
    assert_eq!(take(bytes, cursor, length as usize), expected);
}

#[test]
fn full_states_and_ancestry_have_exact_streaming_coverage_and_readback() {
    let fixture = Fixture::new(3);
    let blocks = fixture.blocks();
    let source = fixture.source(&blocks);
    let expected = fixture.pin();
    let mut quota = budget();
    let readback = verify_migration_history_v2(&expected, &mut quota, source).unwrap();
    assert_eq!(readback.block_count(), 3);
    assert_eq!(readback.checkpoint(), source.checkpoint);
    assert_eq!(readback.observation().claim(), &expected);
    assert_eq!(quota.reads_reserved(), 1);
    assert_eq!(quota.bytes_reserved(), expected.content_len() + 1);

    let (segments, length) = prepare(source, &mut || Ok(())).unwrap();
    let mut progress = || Ok(());
    let mut input = HistoryReader {
        segments,
        progress: &mut progress,
    };
    let mut wire = Vec::new();
    let mut chunk = [0; 17];
    loop {
        let count = input.read(&mut chunk).unwrap();
        if count == 0 {
            break;
        }
        wire.extend_from_slice(&chunk[..count]);
    }
    assert_eq!(wire.len() as u64, length);
    // Check the fixed CMH2/HST2 grammar and every complete CST1 at its exact
    // location, independently of HistoryReader's chunk and segment boundaries.
    let mut cursor = 0;
    assert_eq!(take(&wire, &mut cursor, 4), b"CMH2");
    for expected in [
        fixture.cfg.network,
        fixture.cfg.parameters,
        fixture.genesis,
        source.checkpoint,
    ] {
        assert_eq!(take(&wire, &mut cursor, 32), expected);
    }
    assert_eq!(take(&wire, &mut cursor, 8), 1_u64.to_be_bytes());
    assert_eq!(take(&wire, &mut cursor, 8), 3_u64.to_be_bytes());
    check_snapshot_frame(&wire, &mut cursor, &fixture.initial, &fixture.cfg);
    for block in &blocks {
        assert_eq!(take(&wire, &mut cursor, 4), b"HST2");
        assert_eq!(
            take(&wire, &mut cursor, 8),
            block.header.height.to_be_bytes()
        );
        let encoded = block.header.encode();
        assert_eq!(take(&wire, &mut cursor, encoded.len()), encoded);
        assert_eq!(take(&wire, &mut cursor, 32), block.trace);
        check_snapshot_frame(&wire, &mut cursor, block.state, &fixture.cfg);
    }
    assert_eq!(cursor, wire.len());
    let observed = observe_bytes(&context(), &mut budget(), &wire).unwrap();
    expected.verify(&observed).unwrap();
    for header in &fixture.headers {
        let encoded = header.encode();
        assert!(wire
            .windows(encoded.len())
            .any(|window| window == encoded.as_slice()));
    }
    assert!(wire
        .windows(b"fixture:zero-liability".len())
        .any(|w| w == b"fixture:zero-liability"));
}

#[test]
fn genesis_only_is_explicit_and_old_locator_or_root_cannot_substitute_for_history() {
    for count in [0, 2] {
        let fixture = Fixture::new(count);
        let blocks = fixture.blocks();
        let source = fixture.source(&blocks);
        let expected = fixture.pin();
        let readback = verify_migration_history_v2(&expected, &mut budget(), source).unwrap();
        assert_eq!(readback.block_count(), count as u64);
        for old in [
            source.checkpoint,
            root_for_config(&fixture.initial, &fixture.cfg).unwrap(),
        ] {
            let wrapper = observe_bytes(&context(), &mut budget(), &old).unwrap();
            assert!(verify_migration_history_v2(wrapper.claim(), &mut budget(), source).is_err());
            assert!(ContentClaimV1::decode(&old).is_err());
        }
    }
}

#[test]
fn omitted_reordered_duplicated_and_incomplete_prefixes_are_refused() {
    let fixture = Fixture::new(3);
    let blocks = fixture.blocks();
    for malformed in [
        vec![blocks[1], blocks[2]],
        vec![blocks[0], blocks[2]],
        vec![blocks[0], blocks[1]],
        vec![blocks[0], blocks[0], blocks[2]],
        vec![blocks[2], blocks[1], blocks[0]],
        vec![],
    ] {
        assert!(observe_migration_history_v2(
            &context(),
            &mut budget(),
            fixture.source(&malformed),
        )
        .is_err());
    }
}

#[test]
fn inconsistent_ancestor_header_trace_and_source_context_are_refused() {
    for selector in 0..7 {
        let mut fixture = Fixture::new(2);
        match selector {
            0 => fixture.headers[0].parent[0] ^= 1,
            1 => fixture.headers[0].network[0] ^= 1,
            2 => fixture.headers[0].parameters[0] ^= 1,
            3 => fixture.headers[0].height = u64::MAX,
            4 => fixture.traces[0][0] ^= 1,
            5 => fixture.genesis[0] ^= 1,
            _ => fixture.cfg.params["genesis_timestamp"] = json!(2),
        }
        assert!(
            observe_migration_history_v2(
                &context(),
                &mut budget(),
                fixture.source(&fixture.blocks()),
            )
            .is_err(),
            "selector {selector}"
        );
    }
}

#[test]
fn changing_any_historical_state_while_retaining_old_roots_is_refused() {
    // Deliberately inconsistent source fixtures, not actual SHA-256 collisions.
    for index in 0..3 {
        let mut fixture = Fixture::new(3);
        fixture.states[index].insert("fixture:zero-liability".into(), json!({"remaining":1}));
        let error = observe_migration_history_v2(
            &context(),
            &mut budget(),
            fixture.source(&fixture.blocks()),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            SnapshotContentErrorV1::Input("history state root")
        ));
    }
    let mut fixture = Fixture::new(0);
    fixture.initial.insert("fixture:value".into(), json!(9));
    assert!(matches!(
        observe_migration_history_v2(&context(), &mut budget(), fixture.source(&[]),),
        Err(SnapshotContentErrorV1::Input("history genesis material"))
    ));
}

#[test]
fn self_consistent_rewritten_history_still_cannot_reuse_the_independent_pin() {
    for selector in 0..4 {
        let mut fixture = Fixture::new(3);
        let expected = fixture.pin();
        match selector {
            0 => {
                fixture.states[0].insert("fixture:new-zero".into(), json!(0));
            }
            1 => fixture.headers[0].timestamp += 10,
            2 => fixture.traces[0][0] ^= 1,
            _ => fixture.cfg.params["fixture:new-policy"] = json!(1),
        }
        fixture.relink();
        let source_blocks = fixture.blocks();
        let source = fixture.source(&source_blocks);
        assert!(observe_migration_history_v2(&context(), &mut budget(), source).is_ok());
        assert!(matches!(
            verify_migration_history_v2(&expected, &mut budget(), source),
            Err(SnapshotContentErrorV1::Commitment(
                ContentCommitmentError::Mismatch
            ))
        ));
    }
}

#[test]
fn whole_claim_context_and_digest_are_required() {
    let fixture = Fixture::new(1);
    let expected = fixture.pin();
    for offset in [4, 69, 133, 141, 149, 212] {
        let mut encoded = expected.encode();
        encoded[offset] ^= 1;
        let wrong = ContentClaimV1::decode(&encoded).unwrap();
        assert!(verify_migration_history_v2(
            &wrong,
            &mut budget(),
            fixture.source(&fixture.blocks()),
        )
        .is_err());
    }
    let mut encoded = expected.encode();
    encoded[68] = ContentKind::StateSnapshot as u8;
    let wrong = ContentClaimV1::decode(&encoded).unwrap();
    assert!(matches!(
        verify_migration_history_v2(&wrong, &mut budget(), fixture.source(&fixture.blocks()),),
        Err(SnapshotContentErrorV1::Input("history content kind"))
    ));
}

#[test]
fn cumulative_budget_is_exact_and_failure_is_not_refunded() {
    let fixture = Fixture::new(2);
    let expected = fixture.pin();
    let blocks = fixture.blocks();
    let source = fixture.source(&blocks);
    let mut exact = ContentReadBudget::new(1, expected.content_len() + 1).unwrap();
    verify_migration_history_v2(&expected, &mut exact, source).unwrap();
    let mut short = ContentReadBudget::new(2, expected.content_len()).unwrap();
    assert!(verify_migration_history_v2(&expected, &mut short, source).is_err());
    assert!(short.exhausted());
    assert!(verify_migration_history_v2(&expected, &mut short, source).is_err());
    let mut encoded = expected.encode();
    encoded[149] ^= 1;
    let wrong = ContentClaimV1::decode(&encoded).unwrap();
    let mut used = ContentReadBudget::new(1, expected.content_len() + 1).unwrap();
    assert!(verify_migration_history_v2(&wrong, &mut used, source).is_err());
    assert_eq!(used.bytes_reserved(), expected.content_len() + 1);
    assert!(verify_migration_history_v2(&expected, &mut used, source).is_err());
}

#[test]
fn cancellation_at_the_last_eof_probe_never_returns_a_complete_observation() {
    let fixture = Fixture::new(2);
    let blocks = fixture.blocks();
    let source = fixture.source(&blocks);
    let mut calls = 0;
    let baseline =
        observe_migration_history_with_progress_v2(&context(), &mut budget(), source, &mut || {
            calls += 1;
            Ok(())
        })
        .unwrap();
    let mut current = 0;
    let mut used = budget();
    let result =
        observe_migration_history_with_progress_v2(&context(), &mut used, source, &mut || {
            current += 1;
            if current == calls {
                Err(SnapshotContentErrorV1::Input("test cancelled"))
            } else {
                Ok(())
            }
        });
    assert!(matches!(
        result,
        Err(SnapshotContentErrorV1::Commitment(
            ContentCommitmentError::Io(_)
        ))
    ));
    assert_eq!(current, calls);
    assert_eq!(used.reads_reserved(), 1);
    assert_eq!(used.bytes_reserved(), baseline.claim().content_len() + 1);
}

#[test]
fn finite_block_ceiling_refuses_instead_of_silently_truncating() {
    let fixture = Fixture::new(MAX_MIGRATION_HISTORY_BLOCKS_V2 + 1);
    assert!(matches!(
        observe_migration_history_v2(&context(), &mut budget(), fixture.source(&fixture.blocks()),),
        Err(SnapshotContentErrorV1::Input("history block count"))
    ));
}

#[test]
fn complete_encoded_byte_ceiling_is_checked_before_a_large_state_root() {
    let fixture = Fixture::new(0);
    // Every row fits CST1's original 4 KiB bound, while their actual combined
    // encoding exceeds CMH2's separate 32 MiB budget. No huge single-row shortcut.
    let state: State = (0..8192)
        .map(|index| (format!("state:{index:05}"), json!("x".repeat(4090))))
        .collect();
    let mut source = fixture.source(&[]);
    source.initial_state = &state;
    let mut used = budget();
    assert!(matches!(
        observe_migration_history_v2(&context(), &mut used, source),
        Err(SnapshotContentErrorV1::Input("history content size"))
    ));
    assert_eq!(used.reads_reserved(), 0);
    assert!(matches!(
        migration_history_snapshot_size_v2(&state, &fixture.cfg),
        Err(SnapshotContentErrorV1::Input("history snapshot size"))
    ));
}
