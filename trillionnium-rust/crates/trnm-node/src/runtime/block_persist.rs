use super::*;

pub(crate) fn persist_height_wal(
    runtime: &mut RuntimeState,
    proposal_hash: &str,
    state_root_hex: Option<String>,
    committed_round: u64,
    committed: bool,
) -> Result<()> {
    let wal_entry = WalMeta {
        height: runtime.height,
        round: committed_round,
        proposal_hash: proposal_hash.to_string(),
        committed,
        state_root_hex: state_root_hex.unwrap_or_else(|| hex::encode(runtime.state.state_root())),
        prev_hash_hex: runtime.wal_entries.last().map(|e| e.content_hash_hex()),
    };
    runtime.wal_entries.push(wal_entry);
    persist_wal_meta_entries(&runtime.wal_dir, &runtime.wal_entries)?;
    persist_consensus_wal(
        &runtime.wal_dir,
        &ConsensusWal {
            next_height: runtime.height + 1,
            last_round: committed_round,
            locked_block_hash: Some(proposal_hash.to_string()),
        },
    )?;
    Ok(())
}

pub(crate) fn persist_checkpoint_if_needed(args: &Args, runtime: &mut RuntimeState) -> Result<()> {
    if args.bft_checkpoint_interval > 0 && runtime.height % args.bft_checkpoint_interval == 0 {
        let Some(wal_entry) = runtime.wal_entries.last() else {
            return Ok(());
        };
        let checkpoint = CheckpointMeta {
            height: runtime.height,
            state_root_hex: wal_entry.state_root_hex.clone(),
            wal_entry_hash_hex: wal_entry.content_hash_hex(),
        };
        if checkpoint_evidence_surface_is_canonical(&checkpoint, wal_entry) {
            let checkpoint_summary = checkpoint.evidence_summary();
            let wal_summary = wal_entry.evidence_summary();
            let da_summary = checkpoint_da_light_verifier_summary(&checkpoint, wal_entry)
                .expect("canonical checkpoint evidence must produce a DA/light-verifier summary");
            runtime.checkpoints.push(checkpoint);
            persist_checkpoint_meta(&runtime.wal_dir, &runtime.checkpoints)?;
            println!(
                "[bft-checkpoint] {} {} da_light_summary={}",
                checkpoint_summary, wal_summary, da_summary
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime_fixture(name: &str, height: u64) -> RuntimeState {
        let mut wal_dir = std::env::temp_dir();
        wal_dir.push(format!("trnm-node-checkpoint-surface-{name}-{}", std::process::id()));
        wal_dir.push(format!("{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&wal_dir).unwrap();
        RuntimeState {
            cfg: NodeConfig {
                node_id: "node-test".into(),
                rpc_addr: "127.0.0.1:0".into(),
                p2p_addr: "127.0.0.1:0".into(),
            },
            wal_dir,
            restored_lock: None,
            height,
            state: StateStore::new(),
            mempool: VecDeque::new(),
            known_task_ids: HashSet::new(),
            wal_entries: Vec::new(),
            checkpoints: Vec::new(),
            bft_jitter: BftJitterControl {
                missed_threshold: 0,
                penalty_rounds: 0,
                round_change_backoff_ms: 0,
                round_change_backoff_cap_ms: 0,
                leader_health: vec![],
            },
        }
    }

    #[test]
    fn persist_checkpoint_if_needed_skips_uncommitted_wal_surface() {
        let args = Args::parse_from(["trnm-node", "--bft-checkpoint-interval", "1"]);
        let mut runtime = runtime_fixture("skip-uncommitted", 1);
        runtime.wal_entries.push(WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "proposal-1".into(),
            committed: false,
            state_root_hex: "ab".repeat(32),
            prev_hash_hex: None,
        });

        persist_checkpoint_if_needed(&args, &mut runtime).unwrap();

        assert!(runtime.checkpoints.is_empty());
    }

    #[test]
    fn persist_checkpoint_if_needed_keeps_da_light_summary_surface_canonical() {
        let args = Args::parse_from(["trnm-node", "--bft-checkpoint-interval", "1"]);
        let mut runtime = runtime_fixture("da-light-summary", 7);
        runtime.wal_entries.push(WalMeta {
            height: 7,
            round: 3,
            proposal_hash: "proposal-7".into(),
            committed: true,
            state_root_hex: "ab".repeat(32),
            prev_hash_hex: Some("cd".repeat(32)),
        });

        persist_checkpoint_if_needed(&args, &mut runtime).unwrap();

        let checkpoint = runtime
            .checkpoints
            .last()
            .expect("canonical committed WAL entry should produce a checkpoint");
        let wal_entry = runtime
            .wal_entries
            .last()
            .expect("fixture should retain the committed WAL entry");
        let da_summary = checkpoint_da_light_verifier_summary(checkpoint, wal_entry)
            .expect("persisted checkpoint must keep a canonical DA/light-verifier summary");
        assert!(da_summary.contains("da_light_surface=checkpoint-wal-v1"));
        assert!(da_summary.contains("light_verifier_surface=checkpoint-wal-v1"));
        assert!(da_summary.contains("da_state_commitment_source=checkpoint.state_root_hex"));
        assert!(da_summary.contains("da_checkpoint_commitment_source=checkpoint.commitment_hex"));
        assert!(da_summary.contains("da_wal_content_hash_source=wal.content_hash_hex"));
        assert!(da_summary.contains("da_state_commitment="));
        assert!(da_summary.contains("da_state_commitment_kind=canonical-hex-32b"));
        assert!(da_summary.contains("da_state_commitment_matches_checkpoint_state_root=true"));
        assert!(da_summary.contains("da_checkpoint_commitment="));
        assert!(da_summary.contains("da_checkpoint_commitment_kind=canonical-hex-32b"));
        assert!(da_summary.contains("da_checkpoint_commitment_matches_checkpoint_commitment=true"));
        assert!(da_summary.contains("da_wal_content_hash="));
        assert!(da_summary.contains("da_wal_content_hash_kind=canonical-hex-32b"));
        assert!(da_summary.contains("da_wal_content_hash_matches_checkpoint_wal_entry_hash=true"));
        assert!(da_summary.contains("checkpoint_commitment="));
        assert!(da_summary.contains("checkpoint_commitment_kind=canonical-hex-32b"));
        assert!(da_summary.contains("checkpoint_height_encoding=le-u64"));
        assert!(da_summary.contains("checkpoint_height_bytes=8"));
        assert!(da_summary.contains("checkpoint_state_root_kind=canonical-hex-32b"));
        assert!(da_summary.contains("checkpoint_wal_entry_hash_kind=canonical-hex-32b"));
        assert!(da_summary.contains("wal_height_encoding=le-u64"));
        assert!(da_summary.contains("wal_height_bytes=8"));
        assert!(da_summary.contains("wal_state_root_kind=canonical-hex-32b"));
        assert!(da_summary.contains("wal_content_hash_kind=canonical-hex-32b"));
        assert!(da_summary.contains("wal_prev_hash_kind=linked"));
        assert!(da_summary.contains("wal_proposal_hash_present=true"));
        assert!(da_summary.contains("wal_proposal_hash_kind=opaque-ascii"));
        assert!(da_summary.contains(
            "wal_proposal_hash_surface_policy=ascii-trimmed-no-ws-control-max128"
        ));
        assert!(da_summary.contains("checkpoint_height_matches_wal=true"));
        assert!(da_summary.contains("checkpoint_state_root_matches_wal=true"));
        assert!(da_summary.contains("checkpoint_wal_entry_hash_matches_wal=true"));
        assert!(da_summary.contains("checkpoint_wal_binding_kind=content-hash-equality"));
        assert!(da_summary.contains("wal_linkage_kind=prev-hash-chain"));
        assert!(da_summary.contains("wal_content_hash="));
        assert!(da_summary.contains("wal_content_hash_matches_checkpoint=true"));
    }

    #[test]
    fn persist_checkpoint_if_needed_marks_genesis_prev_hash_surface_for_light_verifiers() {
        let args = Args::parse_from(["trnm-node", "--bft-checkpoint-interval", "1"]);
        let mut runtime = runtime_fixture("genesis-da-light-summary", 1);
        runtime.wal_entries.push(WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "proposal-genesis".into(),
            committed: true,
            state_root_hex: "12".repeat(32),
            prev_hash_hex: None,
        });

        persist_checkpoint_if_needed(&args, &mut runtime).unwrap();

        let checkpoint = runtime
            .checkpoints
            .last()
            .expect("genesis committed WAL entry should still produce a checkpoint");
        let wal_entry = runtime
            .wal_entries
            .last()
            .expect("fixture should retain the genesis WAL entry");
        let da_summary = checkpoint_da_light_verifier_summary(checkpoint, wal_entry)
            .expect("persisted genesis checkpoint must expose a canonical DA/light-verifier summary");
        assert!(da_summary.contains("checkpoint_height=1"));
        assert!(da_summary.contains("checkpoint_height_matches_wal=true"));
        assert!(da_summary.contains("wal_prev_hash=none"));
        assert!(da_summary.contains("wal_prev_hash_present=false"));
        assert!(da_summary.contains("wal_prev_hash_kind=genesis"));
        assert!(da_summary.contains("wal_prev_hash_bytes=0"));
        assert!(da_summary.contains("wal_prev_hash_surface_policy=canonical-hex-32b-or-none"));
        assert!(da_summary.contains("wal_linkage_kind=prev-hash-chain"));
        assert!(da_summary.contains("wal_proposal_hash=proposal-genesis"));
    }

    #[test]
    fn persist_checkpoint_if_needed_rejects_non_genesis_wal_without_prev_hash_surface() {
        let args = Args::parse_from(["trnm-node", "--bft-checkpoint-interval", "1"]);
        let mut runtime = runtime_fixture("missing-prev-hash", 2);
        runtime.wal_entries.push(WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "proposal-2".into(),
            committed: true,
            state_root_hex: "34".repeat(32),
            prev_hash_hex: None,
        });

        persist_checkpoint_if_needed(&args, &mut runtime).unwrap();

        assert!(
            runtime.checkpoints.is_empty(),
            "non-genesis committed WAL without prev_hash must fail closed so checkpoint persistence never emits a DA/light-verifier surface that omits predecessor linkage"
        );
    }

    #[test]
    fn persist_checkpoint_if_needed_rejects_blank_proposal_hash_surface() {
        let args = Args::parse_from(["trnm-node", "--bft-checkpoint-interval", "1"]);
        let mut runtime = runtime_fixture("blank-proposal-hash", 1);
        runtime.wal_entries.push(WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "".into(),
            committed: true,
            state_root_hex: "ab".repeat(32),
            prev_hash_hex: None,
        });

        persist_checkpoint_if_needed(&args, &mut runtime).unwrap();

        assert!(
            runtime.checkpoints.is_empty(),
            "blank proposal hash must fail closed so node persistence never emits a checkpoint with a non-canonical DA/light-verifier surface"
        );
    }

    #[test]
    fn persist_checkpoint_if_needed_rejects_overlong_proposal_hash_surface() {
        let args = Args::parse_from(["trnm-node", "--bft-checkpoint-interval", "1"]);
        let mut runtime = runtime_fixture("overlong-proposal-hash", 1);
        runtime.wal_entries.push(WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p".repeat(257),
            committed: true,
            state_root_hex: "ab".repeat(32),
            prev_hash_hex: None,
        });

        persist_checkpoint_if_needed(&args, &mut runtime).unwrap();

        assert!(
            runtime.checkpoints.is_empty(),
            "overlong proposal hash must fail closed so node persistence never promotes a checkpoint beyond the canonical audit/light-verifier surface bound"
        );
    }
}

pub(crate) enum StopCondition {
    MaxBlocksOnly,
    MaxBlocksOrEmpty,
}

pub(crate) fn advance_or_stop(
    args: &Args,
    runtime: &mut RuntimeState,
    stop: StopCondition,
) -> Result<bool> {
    if args.max_blocks > 0 && runtime.height >= args.max_blocks {
        println!("[node] reached max_blocks={}, exiting", args.max_blocks);
        return Ok(false);
    }
    if matches!(stop, StopCondition::MaxBlocksOrEmpty) && runtime.mempool.is_empty() {
        println!("[node] mempool empty, exiting");
        return Ok(false);
    }
    runtime.height += 1;
    thread::sleep(Duration::from_millis(args.block_ms));
    Ok(true)
}
