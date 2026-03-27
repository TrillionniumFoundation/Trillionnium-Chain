use super::*;

pub(crate) fn hash32_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn validate_node_config(cfg: NodeConfig, path: &str) -> Result<NodeConfig> {
    let node_id = cfg.node_id.trim();
    anyhow::ensure!(
        !node_id.is_empty(),
        "invalid node config {}: node_id must not be empty",
        path
    );
    anyhow::ensure!(
        !node_id.chars().any(char::is_control),
        "invalid node config {}: node_id must not contain control characters",
        path
    );
    anyhow::ensure!(
        !node_id.chars().any(char::is_whitespace),
        "invalid node config {}: node_id must not contain whitespace",
        path
    );

    let rpc_addr = cfg.rpc_addr.trim();
    anyhow::ensure!(
        !rpc_addr.is_empty(),
        "invalid node config {}: rpc_addr must not be empty",
        path
    );
    anyhow::ensure!(
        !rpc_addr.chars().any(char::is_whitespace),
        "invalid node config {}: rpc_addr must not contain whitespace",
        path
    );
    anyhow::ensure!(
        !rpc_addr.chars().any(char::is_control),
        "invalid node config {}: rpc_addr must not contain control characters",
        path
    );
    let rpc_socket: std::net::SocketAddr = rpc_addr.parse().with_context(|| {
        format!(
            "invalid node config {}: rpc_addr must be a valid socket address",
            path
        )
    })?;
    anyhow::ensure!(
        rpc_socket.port() != 0,
        "invalid node config {}: rpc_addr must not use port 0",
        path
    );
    anyhow::ensure!(
        !rpc_socket.ip().is_multicast(),
        "invalid node config {}: rpc_addr must not use a multicast address",
        path
    );
    anyhow::ensure!(
        !matches!(rpc_socket.ip(), std::net::IpAddr::V4(addr) if addr.is_broadcast()),
        "invalid node config {}: rpc_addr must not use the IPv4 broadcast address",
        path
    );

    let p2p_addr = cfg.p2p_addr.trim();
    anyhow::ensure!(
        !p2p_addr.is_empty(),
        "invalid node config {}: p2p_addr must not be empty",
        path
    );
    anyhow::ensure!(
        !p2p_addr.chars().any(char::is_whitespace),
        "invalid node config {}: p2p_addr must not contain whitespace",
        path
    );
    anyhow::ensure!(
        !p2p_addr.chars().any(char::is_control),
        "invalid node config {}: p2p_addr must not contain control characters",
        path
    );
    let p2p_socket: std::net::SocketAddr = p2p_addr.parse().with_context(|| {
        format!(
            "invalid node config {}: p2p_addr must be a valid socket address",
            path
        )
    })?;
    anyhow::ensure!(
        p2p_socket.port() != 0,
        "invalid node config {}: p2p_addr must not use port 0",
        path
    );
    anyhow::ensure!(
        !p2p_socket.ip().is_multicast(),
        "invalid node config {}: p2p_addr must not use a multicast address",
        path
    );
    anyhow::ensure!(
        !matches!(p2p_socket.ip(), std::net::IpAddr::V4(addr) if addr.is_broadcast()),
        "invalid node config {}: p2p_addr must not use the IPv4 broadcast address",
        path
    );
    anyhow::ensure!(
        rpc_socket != p2p_socket,
        "invalid node config {}: rpc_addr and p2p_addr must differ",
        path
    );

    Ok(NodeConfig {
        node_id: node_id.to_string(),
        rpc_addr: rpc_addr.to_string(),
        p2p_addr: p2p_addr.to_string(),
    })
}

fn resolve_config_path(path: &str) -> std::path::PathBuf {
    let requested = std::path::Path::new(path);
    if requested.is_absolute() {
        return requested.to_path_buf();
    }

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node");
    let workspace_relative = workspace_root.join(requested);
    if workspace_relative.exists() {
        return workspace_relative;
    }

    if requested.exists() {
        return requested.to_path_buf();
    }

    requested.to_path_buf()
}

pub(crate) fn load_config(path: &str) -> Result<NodeConfig> {
    let resolved = resolve_config_path(path);
    let raw = fs::read_to_string(&resolved).with_context(|| {
        format!(
            "read config failed: {} (resolved: {})",
            path,
            resolved.display()
        )
    })?;
    let cfg: NodeConfig = toml::from_str(&raw).with_context(|| {
        format!(
            "parse toml failed: {} (resolved: {})",
            path,
            resolved.display()
        )
    })?;
    validate_node_config(cfg, resolved.to_string_lossy().as_ref())
}

pub(crate) fn compute_commitment(
    task_id: u64,
    result_hash: &Hash32,
    reveal_salt: &[u8; 32],
    worker: &str,
) -> Hash32 {
    let payload = format!(
        "{}|{}|{}|{}",
        task_id,
        hex::encode(result_hash),
        hex::encode(reveal_salt),
        worker
    );
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hasher.finalize().into()
}

pub(crate) fn demo_worker_name(task_id: u64) -> String {
    format!("worker{}", task_id)
}

pub(crate) fn build_demo_mempool(demo_tasks: u64, _demo_keys: u64) -> VecDeque<MockTx> {
    let mut q = VecDeque::new();

    for i in 0..demo_tasks.max(1) {
        let task_id = 1001u64 + i;
        let worker = demo_worker_name(task_id);
        let result_hash = [7u8; 32];
        let reveal_salt = [task_id as u8; 32];
        let committed_hash = compute_commitment(task_id, &result_hash, &reveal_salt, &worker);

        q.push_back(MockTx::CreateTask {
            task_id,
            creator: "alice".to_string(),
            bounty: 100,
        });
        q.push_back(MockTx::AcceptTask {
            task_id,
            worker: worker.clone(),
        });
        q.push_back(MockTx::Commit {
            task_id,
            worker,
            committed_hash,
        });
        q.push_back(MockTx::Reveal {
            task_id,
            result_hash,
            reveal_salt,
        });
        q.push_back(MockTx::Challenge {
            task_id,
            challenger: "challenger".into(),
            bond: 10,
        });
        q.push_back(MockTx::Resolve {
            task_id,
            slash_worker: false,
            resolver: "governance.resolve_authority".into(),
        });
    }

    q
}

pub(crate) fn task_ref(st: &StateStore, task_id: u64) -> Result<ObjectRef> {
    st.get_ref(task_id)
        .with_context(|| format!("task_ref missing for task_id={}", task_id))
}

pub(crate) fn task_id_of(tx: &MockTx) -> u64 {
    match tx {
        MockTx::CreateTask { task_id, .. }
        | MockTx::AcceptTask { task_id, .. }
        | MockTx::Commit { task_id, .. }
        | MockTx::Reveal { task_id, .. }
        | MockTx::Challenge { task_id, .. }
        | MockTx::Resolve { task_id, .. } => *task_id,
    }
}

pub(crate) fn actor_of(st: &StateStore, tx: &MockTx) -> String {
    match tx {
        MockTx::CreateTask { creator, .. } => creator.clone(),
        MockTx::AcceptTask { worker, .. } => worker.clone(),
        MockTx::Commit { worker, .. } => worker.clone(),
        MockTx::Reveal { task_id, .. } => st
            .get_task(*task_id)
            .and_then(|t| t.worker)
            .unwrap_or_else(|| format!("worker{}", task_id)),
        MockTx::Challenge { challenger, .. } => challenger.clone(),
        MockTx::Resolve { resolver, .. } => resolver.clone(),
    }
}

pub(crate) fn verified_signer_of(st: &StateStore, tx: &MockTx) -> String {
    match tx {
        MockTx::Resolve { resolver, .. } => resolver.clone(),
        MockTx::Reveal { task_id, .. } => st
            .get_task(*task_id)
            .and_then(|t| t.worker)
            .unwrap_or_else(|| "unknown_worker".to_string()),
        _ => actor_of(st, tx),
    }
}

pub(crate) fn challenger_of(tx: &MockTx) -> Option<String> {
    match tx {
        MockTx::Challenge { challenger, .. } => Some(challenger.clone()),
        MockTx::Resolve { .. } => None,
        _ => None,
    }
}

pub(crate) fn apply_one(st: &mut StateStore, tx: MockTx, current_height: u64) -> Result<()> {
    let signer = verified_signer_of(st, &tx);
    match tx {
        MockTx::CreateTask {
            task_id,
            creator,
            bounty,
        } => {
            let _ = apply_create_task(st, task_id, creator, bounty)?;
        }
        MockTx::AcceptTask { task_id, worker } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_accept_task_at_height(st, r, worker, current_height)?;
        }
        MockTx::Commit {
            task_id,
            worker,
            committed_hash,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_commit_result_at_height(st, r, worker, committed_hash, current_height)?;
        }
        MockTx::Reveal {
            task_id,
            result_hash,
            reveal_salt,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_reveal_result_at_height(
                st,
                r,
                result_hash,
                reveal_salt,
                None,
                current_height,
            )?;
        }
        MockTx::Challenge {
            task_id,
            challenger,
            bond,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_challenge_at_height(st, r, challenger, bond, signer, current_height)?;
        }
        MockTx::Resolve {
            task_id,
            slash_worker,
            resolver,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_resolve_at_height(st, r, slash_worker, resolver, signer, current_height)?;
        }
    }
    Ok(())
}

pub(crate) fn pseudo_object_id_for_account(account: &str) -> u64 {
    let mut h = Sha256::new();
    h.update(b"balance:");
    h.update(account.as_bytes());
    let digest = h.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    // keep account-derived ids in high range to avoid overlapping natural task ids
    u64::from_le_bytes(bytes) | (1u64 << 63)
}

pub(crate) fn summarize_hot_objects(st: &StateStore, txs: &[MockTx]) -> HotObjectSummary {
    let mut labels = BTreeMap::new();
    let mut hot_tx_count = 0usize;

    for tx in txs {
        if let MockTx::Resolve { task_id, .. } = tx {
            hot_tx_count += 1;
            for label in [
                CHALLENGE_ESCROW_ACCOUNT,
                CHALLENGE_FORFEIT_TREASURY_ACCOUNT,
                WORKER_SLASH_TREASURY_ACCOUNT,
                RESOLVE_PENDING_APPROVAL_HOT_LABEL,
                RESOLVE_AUTHORITY_HOT_LABEL,
            ] {
                *labels.entry(label.to_string()).or_insert(0) += 1;
            }
            if let Some(challenger) = st.get_task(*task_id).and_then(|t| t.challenger) {
                *labels.entry(challenger).or_insert(0) += 1;
            }
        }
    }

    HotObjectSummary {
        hot_tx_count,
        labels,
    }
}

pub(crate) fn hot_object_top_label_share_ppm(summary: &HotObjectSummary) -> u128 {
    let total_refs: usize = summary.labels.values().copied().sum();
    let top_refs = summary.labels.values().copied().max().unwrap_or(0);
    ratio_ppm(top_refs as u128, total_refs as u128)
}

pub(crate) fn hot_object_tail_share_ppm(summary: &HotObjectSummary) -> u128 {
    let total_refs: usize = summary.labels.values().copied().sum();
    let top_refs = summary.labels.values().copied().max().unwrap_or(0);
    ratio_ppm(
        total_refs.saturating_sub(top_refs) as u128,
        total_refs as u128,
    )
}

pub(crate) fn missed_proposals_added_since(previous: &[u64], current: &[u64]) -> u64 {
    current
        .iter()
        .enumerate()
        .map(|(idx, current_count)| {
            current_count.saturating_sub(previous.get(idx).copied().unwrap_or(0))
        })
        .sum()
}
