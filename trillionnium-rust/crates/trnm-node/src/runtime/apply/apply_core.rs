use super::*;

fn is_ipv4_compatible_ipv6(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(_) => false,
        std::net::IpAddr::V6(addr) => {
            let segments = addr.segments();
            segments[..6].iter().all(|segment| *segment == 0)
                && !addr.is_unspecified()
                && !addr.is_loopback()
                && addr.to_ipv4_mapped().is_none()
        }
    }
}

pub(crate) fn hash32_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn is_reserved_listener_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(addr) => {
            let octets = addr.octets();
            matches!(
                octets,
                [192, 0, 2, _]
                    | [198, 51, 100, _]
                    | [203, 0, 113, _]
                    | [198, 18 | 19, _, _]
            )
        }
        std::net::IpAddr::V6(addr) => {
            let segments = addr.segments();
            segments[0] == 0x2001 && segments[1] == 0x0db8
        }
    }
}

fn looks_like_dns_hostname(value: &str) -> bool {
    if !value.contains('.') {
        return false;
    }

    value.split('.').all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn validate_node_config(cfg: NodeConfig, path: &str) -> Result<NodeConfig> {
    let node_id = cfg.node_id.trim();
    anyhow::ensure!(
        cfg.node_id == node_id,
        "invalid node config {}: node_id must not contain leading or trailing whitespace",
        path
    );
    anyhow::ensure!(
        !node_id.is_empty(),
        "invalid node config {}: node_id must not be empty",
        path
    );
    anyhow::ensure!(
        node_id.len() <= MAX_NODE_ID_LEN,
        "invalid node config {}: node_id must be at most {} bytes",
        path,
        MAX_NODE_ID_LEN
    );
    anyhow::ensure!(
        !node_id.chars().any(char::is_control),
        "invalid node config {}: node_id must not contain control characters",
        path
    );
    anyhow::ensure!(
        node_id.is_ascii(),
        "invalid node config {}: node_id must use ASCII-only characters",
        path
    );
    anyhow::ensure!(
        !contains_invisible_or_bidi_format_chars(node_id),
        "invalid node config {}: node_id must not contain invisible or bidirectional format characters",
        path
    );
    anyhow::ensure!(
        !node_id.chars().any(char::is_whitespace),
        "invalid node config {}: node_id must not contain whitespace",
        path
    );
    anyhow::ensure!(
        !node_id.contains(',') && !node_id.contains(';') && !node_id.contains('|'),
        "invalid node config {}: node_id must not contain list separators (, ; |)",
        path
    );
    anyhow::ensure!(
        !node_id.contains('/')
            && !node_id.contains('\\')
            && !node_id.contains(':')
            && !node_id.contains('[')
            && !node_id.contains(']'),
        "invalid node config {}: node_id must not contain path or host-literal separators (/ \\ : [ ])",
        path
    );
    anyhow::ensure!(
        !node_id.contains('@')
            && !node_id.contains('?')
            && !node_id.contains('#')
            && !node_id.contains('%')
            && !node_id.contains('&')
            && !node_id.contains('='),
        "invalid node config {}: node_id must not contain URI delimiters (@ ? # % & =)",
        path
    );
    anyhow::ensure!(
        node_id != "." && node_id != "..",
        "invalid node config {}: node_id must not be '.' or '..'",
        path
    );
    anyhow::ensure!(
        !node_id.eq_ignore_ascii_case("localhost")
            && !looks_like_dns_hostname(node_id)
            && node_id.parse::<std::net::IpAddr>().is_err()
            && node_id.parse::<std::net::SocketAddr>().is_err(),
        "invalid node config {}: node_id must not look like a host or socket literal",
        path
    );

    let rpc_addr = cfg.rpc_addr.trim();
    anyhow::ensure!(
        cfg.rpc_addr == rpc_addr,
        "invalid node config {}: rpc_addr must not contain leading or trailing whitespace",
        path
    );
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
    anyhow::ensure!(
        !rpc_addr.contains(',') && !rpc_addr.contains(';') && !rpc_addr.contains('|'),
        "invalid node config {}: rpc_addr must not contain list separators (, ; |)",
        path
    );
    anyhow::ensure!(
        !rpc_addr.contains("://"),
        "invalid node config {}: rpc_addr must be a raw socket address, not a URL",
        path
    );
    anyhow::ensure!(
        !rpc_addr.contains('/') && !rpc_addr.contains('\\'),
        "invalid node config {}: rpc_addr must not contain path separators (/ \\)",
        path
    );
    let rpc_socket: std::net::SocketAddr = rpc_addr.parse().with_context(|| {
        format!(
            "invalid node config {}: rpc_addr must be a valid socket address",
            path
        )
    })?;
    anyhow::ensure!(
        rpc_addr == rpc_socket.to_string(),
        "invalid node config {}: rpc_addr must use a canonical socket address literal",
        path
    );
    anyhow::ensure!(
        rpc_socket.port() != 0,
        "invalid node config {}: rpc_addr must not use port 0",
        path
    );
    anyhow::ensure!(
        rpc_socket.port() >= 1024,
        "invalid node config {}: rpc_addr must not use a privileged port below 1024",
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
    anyhow::ensure!(
        !rpc_socket.ip().is_unspecified(),
        "invalid node config {}: rpc_addr must not use an unspecified address",
        path
    );
    anyhow::ensure!(
        !rpc_socket.ip().is_unicast_link_local(),
        "invalid node config {}: rpc_addr must not use a link-local address",
        path
    );
    anyhow::ensure!(
        !is_reserved_listener_ip(rpc_socket.ip()),
        "invalid node config {}: rpc_addr must not use a documentation or benchmark-only address",
        path
    );
    anyhow::ensure!(
        !is_ipv4_compatible_ipv6(rpc_socket.ip()),
        "invalid node config {}: rpc_addr must not use an IPv4-compatible IPv6 address",
        path
    );

    let p2p_addr = cfg.p2p_addr.trim();
    anyhow::ensure!(
        cfg.p2p_addr == p2p_addr,
        "invalid node config {}: p2p_addr must not contain leading or trailing whitespace",
        path
    );
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
    anyhow::ensure!(
        !p2p_addr.contains(',') && !p2p_addr.contains(';') && !p2p_addr.contains('|'),
        "invalid node config {}: p2p_addr must not contain list separators (, ; |)",
        path
    );
    anyhow::ensure!(
        !p2p_addr.contains("://"),
        "invalid node config {}: p2p_addr must be a raw socket address, not a URL",
        path
    );
    anyhow::ensure!(
        !p2p_addr.contains('/') && !p2p_addr.contains('\\'),
        "invalid node config {}: p2p_addr must not contain path separators (/ \\)",
        path
    );
    let p2p_socket: std::net::SocketAddr = p2p_addr.parse().with_context(|| {
        format!(
            "invalid node config {}: p2p_addr must be a valid socket address",
            path
        )
    })?;
    anyhow::ensure!(
        p2p_addr == p2p_socket.to_string(),
        "invalid node config {}: p2p_addr must use a canonical socket address literal",
        path
    );
    anyhow::ensure!(
        p2p_socket.port() != 0,
        "invalid node config {}: p2p_addr must not use port 0",
        path
    );
    anyhow::ensure!(
        p2p_socket.port() >= 1024,
        "invalid node config {}: p2p_addr must not use a privileged port below 1024",
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
        !p2p_socket.ip().is_unspecified(),
        "invalid node config {}: p2p_addr must not use an unspecified address",
        path
    );
    anyhow::ensure!(
        !p2p_socket.ip().is_unicast_link_local(),
        "invalid node config {}: p2p_addr must not use a link-local address",
        path
    );
    anyhow::ensure!(
        !is_reserved_listener_ip(p2p_socket.ip()),
        "invalid node config {}: p2p_addr must not use a documentation or benchmark-only address",
        path
    );
    anyhow::ensure!(
        !is_ipv4_compatible_ipv6(p2p_socket.ip()),
        "invalid node config {}: p2p_addr must not use an IPv4-compatible IPv6 address",
        path
    );
    anyhow::ensure!(
        rpc_socket != p2p_socket,
        "invalid node config {}: rpc_addr and p2p_addr must differ",
        path
    );
    anyhow::ensure!(
        rpc_socket.is_ipv4() == p2p_socket.is_ipv4(),
        "invalid node config {}: rpc_addr and p2p_addr must use the same IP family",
        path
    );
    anyhow::ensure!(
        rpc_socket.ip() == p2p_socket.ip(),
        "invalid node config {}: rpc_addr and p2p_addr must bind the same IP",
        path
    );

    Ok(NodeConfig {
        node_id: node_id.to_string(),
        rpc_addr: rpc_addr.to_string(),
        p2p_addr: p2p_addr.to_string(),
    })
}

fn workspace_root() -> &'static std::path::Path {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node")
}

fn resolve_config_path(path: &str) -> std::path::PathBuf {
    let requested = std::path::Path::new(path);
    if requested.is_absolute() {
        return requested.to_path_buf();
    }

    let workspace_root = workspace_root();
    let workspace_anchor = workspace_root.file_name().map(std::path::Path::new);
    let workspace_anchor = workspace_anchor
        .and_then(|anchor| {
            requested.strip_prefix(anchor).ok().or_else(|| {
                requested
                    .strip_prefix(std::path::Path::new("."))
                    .ok()?
                    .strip_prefix(anchor)
                    .ok()
            })
        })
        .unwrap_or(requested);
    let workspace_relative = workspace_root.join(workspace_anchor);
    if workspace_relative.exists() {
        let canonical_workspace_root = workspace_root
            .canonicalize()
            .unwrap_or_else(|_| workspace_root.to_path_buf());
        let canonical_workspace_relative = workspace_relative
            .canonicalize()
            .unwrap_or_else(|_| workspace_relative.clone());
        if canonical_workspace_relative.starts_with(&canonical_workspace_root) {
            return workspace_relative;
        }
    }

    if requested.exists() {
        return requested.to_path_buf();
    }

    requested.to_path_buf()
}

fn ensure_relative_config_path_stays_within_allowed_roots(
    requested: &str,
    resolved: &std::path::Path,
) -> Result<()> {
    if std::path::Path::new(requested).is_absolute() || !resolved.exists() {
        return Ok(());
    }

    let canonical_resolved = resolved
        .canonicalize()
        .unwrap_or_else(|_| resolved.to_path_buf());
    let workspace_root = workspace_root()
        .canonicalize()
        .unwrap_or_else(|_| workspace_root().to_path_buf());
    let current_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let canonical_current_dir = current_dir
        .canonicalize()
        .unwrap_or_else(|_| current_dir.clone());

    anyhow::ensure!(
        canonical_resolved.starts_with(&workspace_root)
            || canonical_resolved.starts_with(&canonical_current_dir),
        "read config failed: {} resolves outside allowed roots (resolved: {})",
        requested,
        canonical_resolved.display()
    );

    Ok(())
}

fn contains_invisible_or_bidi_format_chars(value: &str) -> bool {
    value.chars().any(|ch| {
        matches!(
            ch,
            '\u{200B}'
                | '\u{200C}'
                | '\u{200D}'
                | '\u{2060}'
                | '\u{FEFF}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
        )
    })
}

fn validate_config_path_input(path: &str) -> Result<()> {
    anyhow::ensure!(!path.trim().is_empty(), "read config failed: path must not be empty");
    anyhow::ensure!(
        path == path.trim(),
        "read config failed: path must not contain leading or trailing whitespace"
    );
    anyhow::ensure!(
        !path.chars().any(char::is_control),
        "read config failed: path must not contain control characters"
    );
    anyhow::ensure!(
        !contains_invisible_or_bidi_format_chars(path),
        "read config failed: path must not contain invisible or bidirectional format characters"
    );
    anyhow::ensure!(
        !path.contains(',') && !path.contains(';') && !path.contains('|'),
        "read config failed: path must not contain list separators (, ; |)"
    );
    anyhow::ensure!(
        !path.contains("://"),
        "read config failed: path must not be a URL"
    );
    anyhow::ensure!(
        !Path::new(path)
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir)),
        "read config failed: path must not contain parent traversal (..)"
    );
    anyhow::ensure!(
        !path.split(['/', '\\']).any(|segment| segment == ".."),
        "read config failed: path must not contain parent traversal (..)"
    );

    Ok(())
}

pub(crate) fn load_config(path: &str) -> Result<NodeConfig> {
    validate_config_path_input(path)?;
    let resolved = resolve_config_path(path);
    ensure_relative_config_path_stays_within_allowed_roots(path, &resolved)?;
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

#[cfg(test)]
mod tests {
    use super::{load_config, resolve_config_path, validate_node_config, NodeConfig};

    #[test]
    fn resolve_config_path_anchors_workspace_prefixed_paths_to_workspace_root() {
        let resolved = resolve_config_path("trillionnium-rust/configs/node1.toml");
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node");
        assert_eq!(resolved, workspace_root.join("configs/node1.toml"));
        assert!(resolved.is_file(), "expected shipped node1 config to exist");
    }

    #[test]
    fn resolve_config_path_anchors_curdir_prefixed_workspace_path_to_workspace_root() {
        let resolved = resolve_config_path("./trillionnium-rust/configs/node1.toml");
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node");
        assert_eq!(resolved, workspace_root.join("configs/node1.toml"));
        assert!(resolved.is_file(), "expected shipped node1 config to exist");
    }

    #[test]
    fn resolve_config_path_anchors_curdir_prefixed_repo_root_defaults_to_workspace_configs_dir() {
        let resolved = resolve_config_path("./configs/node1.toml");
        assert!(
            resolved.ends_with(std::path::Path::new("trillionnium-rust/configs/node1.toml")),
            "resolved path should normalize curdir-prefixed repo-root bootstrap defaults: {}",
            resolved.display()
        );
    }

    #[test]
    fn load_config_accepts_legacy_repo_root_relative_default_path() {
        let cfg = load_config("configs/node1.toml")
            .expect("repo-root launches should resolve legacy default config path");
        assert_eq!(cfg.node_id, "node1");
        assert_eq!(cfg.rpc_addr, "127.0.0.1:26657");
        assert_eq!(cfg.p2p_addr, "127.0.0.1:26656");
    }

    #[test]
    fn load_config_accepts_curdir_prefixed_workspace_path_for_shipped_bootstrap_config() {
        let cfg = load_config("./trillionnium-rust/configs/node1.toml")
            .expect("curdir-prefixed workspace bootstrap config should resolve");
        assert_eq!(cfg.node_id, "node1");
        assert_eq!(cfg.rpc_addr, "127.0.0.1:26657");
        assert_eq!(cfg.p2p_addr, "127.0.0.1:26656");
    }

    #[test]
    fn load_config_accepts_curdir_prefixed_repo_root_default_path() {
        let cfg = load_config("./configs/node1.toml")
            .expect("curdir-prefixed repo-root bootstrap config should resolve");
        assert_eq!(cfg.node_id, "node1");
        assert_eq!(cfg.rpc_addr, "127.0.0.1:26657");
        assert_eq!(cfg.p2p_addr, "127.0.0.1:26656");
    }

    #[test]
    fn resolve_config_path_does_not_anchor_parent_traversal_outside_workspace_root() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node");
        let outside_path = workspace_root.join("../configs/node1.toml");
        assert!(outside_path.exists(), "expected parent traversal fixture to exist");

        let resolved = resolve_config_path("../configs/node1.toml");
        assert_eq!(resolved, std::path::PathBuf::from("../configs/node1.toml"));
    }

    #[test]
    fn load_config_rejects_relative_symlink_escape_outside_workspace_and_cwd() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let temp_root = std::env::temp_dir().join(format!(
            "trnm-node-apply-config-symlink-escape-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after unix epoch")
                .as_millis()
        ));
        let workspace_shadow = temp_root.join("workspace-shadow");
        let escape_dir = temp_root.join("escape");
        std::fs::create_dir_all(workspace_shadow.join("configs"))
            .expect("workspace shadow should be creatable");
        std::fs::create_dir_all(&escape_dir).expect("escape dir should be creatable");
        std::fs::write(
            escape_dir.join("outside.toml"),
            "node_id = \"node-escape\"\nrpc_addr = \"127.0.0.1:30001\"\np2p_addr = \"127.0.0.1:30000\"\n",
        )
        .expect("outside config should be writable");
        symlink(
            escape_dir.join("outside.toml"),
            workspace_shadow.join("configs/escaped.toml"),
        )
        .expect("escape symlink should be creatable");

        let original_cwd = std::env::current_dir().expect("capture cwd");
        std::env::set_current_dir(&workspace_shadow).expect("enter shadow cwd");
        let err = load_config("configs/escaped.toml")
            .expect_err("relative symlink escape should fail closed");
        std::env::set_current_dir(&original_cwd).expect("restore cwd");
        let _ = std::fs::remove_dir_all(&temp_root);

        assert!(
            err.to_string().contains("resolves outside allowed roots"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn load_config_rejects_blank_path_fail_closed() {
        let err = load_config("   ").expect_err("blank apply config path must fail closed");
        assert!(
            err.to_string().contains("path must not be empty"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn load_config_rejects_invisible_or_bidi_format_characters_in_path_fail_closed() {
        for path in [
            "configs/node1.toml\u{200B}",
            "configs/node1.toml\u{202E}",
            "configs/node1.toml\u{2066}",
        ] {
            let err = load_config(path)
                .expect_err("apply config path invisible/bidi format characters must fail closed");
            assert!(
                err.to_string()
                    .contains("path must not contain invisible or bidirectional format characters"),
                "unexpected error for {path:?}: {err:#}"
            );
        }
    }

    #[test]
    fn load_config_rejects_list_separator_paths_fail_closed() {
        for path in [
            "configs/node1.toml,configs/node2.toml",
            "configs/node1.toml;configs/node2.toml",
            "configs/node1.toml|configs/node2.toml",
        ] {
            let err = load_config(path)
                .expect_err("multi-config apply path separators must fail closed");
            assert!(
                err.to_string().contains("path must not contain list separators"),
                "unexpected error for {path:?}: {err:#}"
            );
        }
    }

    #[test]
    fn load_config_rejects_url_style_paths_fail_closed() {
        for path in [
            "http://example.invalid/node1.toml",
            "https://example.invalid/node1.toml",
        ] {
            let err = load_config(path).expect_err("URL-style apply config paths must fail closed");
            assert!(
                err.to_string().contains("path must not be a URL"),
                "unexpected error for {path:?}: {err:#}"
            );
        }
    }

    #[test]
    fn load_config_rejects_parent_traversal_in_path_fail_closed() {
        for path in [
            "../configs/node1.toml",
            "configs/../node1.toml",
            r"..\configs\node1.toml",
            r"configs\..\node1.toml",
        ] {
            let err = load_config(path).expect_err("apply config path parent traversal must fail closed");
            assert!(
                err.to_string()
                    .contains("path must not contain parent traversal (..)"),
                "unexpected error for {path:?}: {err:#}"
            );
        }
    }

    #[test]
    fn load_config_rejects_unknown_fields_to_keep_apply_bootstrap_config_fail_closed() {
        use std::time::{SystemTime, UNIX_EPOCH};

        for (unknown_field, field_value) in [
            ("bootstrap_peers", "[\"127.0.0.1:27656\"]"),
            ("bootstrap_peer", "\"127.0.0.1:27656\""),
            ("seed_nodes", "[\"127.0.0.1:27656\"]"),
            ("seed_node", "\"127.0.0.1:27656\""),
            ("persistent_peers", "[\"127.0.0.1:27656\"]"),
            ("persistent_peer", "\"127.0.0.1:27656\""),
        ] {
            let path = std::env::temp_dir().join(format!(
                "trnm-node-apply-config-unknown-field-{unknown_field}-{}-{}.toml",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock should be after unix epoch")
                    .as_nanos()
            ));
            std::fs::write(
                &path,
                format!(
                    "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"127.0.0.1:26656\"\n{unknown_field} = {field_value}\n"
                ),
            )
            .expect("write temp config");

            let err = load_config(path.to_str().expect("temp path utf-8"))
                .expect_err("unknown apply config fields must fail closed");
            let _ = std::fs::remove_file(&path);

            let err_surface = err.to_string();
            assert!(
                err_surface.contains("parse toml failed")
                    && err_surface.contains(&format!("unknown field `{unknown_field}`")),
                "unexpected error for {unknown_field}: {err:#}"
            );
        }
    }

    #[test]
    fn validate_node_config_rejects_operator_boundary_whitespace_fail_closed() {
        let cfg = NodeConfig {
            node_id: "  node-a  ".into(),
            rpc_addr: " 127.0.0.1:7000\n".into(),
            p2p_addr: "\t127.0.0.1:7001 ".into(),
        };

        let err = validate_node_config(cfg, "inline")
            .expect_err("boundary whitespace in apply config must fail closed");
        let err_surface = err.to_string();
        assert!(
            err_surface.contains("node_id must not contain leading or trailing whitespace"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_noncanonical_socket_literals() {
        let rpc_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:026657".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "inline",
        )
        .expect_err("noncanonical rpc_addr literals must fail closed");
        assert!(
            rpc_err
                .to_string()
                .contains("rpc_addr must use a canonical socket address literal"),
            "unexpected error: {rpc_err:#}"
        );

        let p2p_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[::1]:26657".into(),
                p2p_addr: "[0:0:0:0:0:0:0:1]:26656".into(),
            },
            "inline",
        )
        .expect_err("noncanonical p2p_addr literals must fail closed");
        assert!(
            p2p_err
                .to_string()
                .contains("p2p_addr must use a canonical socket address literal"),
            "unexpected error: {p2p_err:#}"
        );

        let rpc_ipv4_compatible_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[::7f00:1]:26657".into(),
                p2p_addr: "[2001:4860::1]:26656".into(),
            },
            "inline",
        )
        .expect_err("IPv4-compatible rpc_addr literals must fail closed");
        assert!(
            rpc_ipv4_compatible_err
                .to_string()
                .contains("rpc_addr must not use an IPv4-compatible IPv6 address"),
            "unexpected error: {rpc_ipv4_compatible_err:#}"
        );

        let p2p_ipv4_compatible_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[2001:4860::1]:26657".into(),
                p2p_addr: "[::c000:20a]:26656".into(),
            },
            "inline",
        )
        .expect_err("IPv4-compatible p2p_addr literals must fail closed");
        assert!(
            p2p_ipv4_compatible_err
                .to_string()
                .contains("p2p_addr must not use an IPv4-compatible IPv6 address"),
            "unexpected error: {p2p_ipv4_compatible_err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_privileged_listener_ports() {
        let rpc_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:443".into(),
                p2p_addr: "127.0.0.1:17001".into(),
            },
            "inline",
        )
        .expect_err("privileged rpc_addr port must fail closed");
        assert!(
            rpc_err
                .to_string()
                .contains("rpc_addr must not use a privileged port below 1024"),
            "unexpected error: {rpc_err:#}"
        );

        let p2p_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:17000".into(),
                p2p_addr: "127.0.0.1:80".into(),
            },
            "inline",
        )
        .expect_err("privileged p2p_addr port must fail closed");
        assert!(
            p2p_err
                .to_string()
                .contains("p2p_addr must not use a privileged port below 1024"),
            "unexpected error: {p2p_err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_unspecified_listener_addresses() {
        let rpc_unspecified_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "0.0.0.0:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr unspecified bind must fail closed");
        assert!(
            rpc_unspecified_err
                .to_string()
                .contains("rpc_addr must not use an unspecified address"),
            "unexpected error: {rpc_unspecified_err:#}"
        );

        let p2p_unspecified_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "[::]:7001".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr unspecified bind must fail closed");
        assert!(
            p2p_unspecified_err
                .to_string()
                .contains("p2p_addr must not use an unspecified address"),
            "unexpected error: {p2p_unspecified_err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_link_local_listener_addresses() {
        let rpc_link_local_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[fe80::1]:7000".into(),
                p2p_addr: "[2001:4860::1]:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr link-local bind must fail closed");
        assert!(
            rpc_link_local_err
                .to_string()
                .contains("rpc_addr must not use a link-local address"),
            "unexpected error: {rpc_link_local_err:#}"
        );

        let p2p_link_local_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[2001:4860::1]:7000".into(),
                p2p_addr: "[fe80::2]:7001".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr link-local bind must fail closed");
        assert!(
            p2p_link_local_err
                .to_string()
                .contains("p2p_addr must not use a link-local address"),
            "unexpected error: {p2p_link_local_err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_documentation_and_benchmark_listener_addresses() {
        let rpc_reserved_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "192.0.2.10:7000".into(),
                p2p_addr: "192.0.2.10:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr documentation bind must fail closed");
        assert!(
            rpc_reserved_err
                .to_string()
                .contains("rpc_addr must not use a documentation or benchmark-only address"),
            "unexpected error: {rpc_reserved_err:#}"
        );

        let p2p_reserved_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "198.19.0.10:7001".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr benchmark bind must fail closed");
        assert!(
            p2p_reserved_err
                .to_string()
                .contains("p2p_addr must not use a documentation or benchmark-only address"),
            "unexpected error: {p2p_reserved_err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_control_characters_in_node_id() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node\nalpha".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("control characters in node_id must fail closed");
        assert!(
            err.to_string()
                .contains("node_id must not contain control characters"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_mixed_ip_families() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "[::1]:7001".into(),
            },
            "inline",
        )
        .expect_err("mixed IPv4/IPv6 listener families must fail closed");
        assert!(
            err.to_string()
                .contains("rpc_addr and p2p_addr must use the same IP family"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_distinct_listener_ips_within_same_family() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.2:7001".into(),
            },
            "inline",
        )
        .expect_err("distinct same-family listener IPs must fail closed");
        assert!(
            err.to_string()
                .contains("rpc_addr and p2p_addr must bind the same IP"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_shared_rpc_and_p2p_addr() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:7000".into(),
            },
            "inline",
        )
        .expect_err("shared rpc/p2p listener address must fail closed");
        assert!(
            err.to_string()
                .contains("rpc_addr and p2p_addr must differ"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_list_separators_in_node_id() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node|alpha".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("list separators in node_id must fail closed");
        assert!(
            err.to_string()
                .contains("node_id must not contain list separators (, ; |)"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_path_and_host_literal_separators_in_node_id() {
        for node_id in ["node/alpha", r"node\\alpha", "node:alpha", "[::1]"] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:7000".into(),
                    p2p_addr: "127.0.0.1:7001".into(),
                },
                "inline",
            )
            .expect_err("path or host-literal separators in node_id must fail closed");
            assert!(
                err.to_string()
                    .contains("node_id must not contain path or host-literal separators (/ \\ : [ ])"),
                "unexpected error for {node_id:?}: {err:#}"
            );
        }
    }

    #[test]
    fn validate_node_config_rejects_non_ascii_node_id() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "节点-alpha".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("non-ascii node_id must fail closed");
        assert!(
            err.to_string()
                .contains("node_id must use ASCII-only characters"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn load_config_rejects_url_like_listener_addrs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("node.toml");
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \"http://127.0.0.1:7000\"\np2p_addr = \"tcp://127.0.0.1:7001\"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("URL-like listener addrs must fail closed");
        let err_surface = err.to_string();
        assert!(
            err_surface.contains("rpc_addr must be a raw socket address, not a URL")
                || err_surface.contains("p2p_addr must be a raw socket address, not a URL"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_url_like_listener_addrs() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "http://127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("URL-like rpc_addr must fail closed");
        assert!(
            err.to_string()
                .contains("rpc_addr must be a raw socket address, not a URL"),
            "unexpected error: {err:#}"
        );

        let err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "tcp://127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("URL-like p2p_addr must fail closed");
        assert!(
            err.to_string()
                .contains("p2p_addr must be a raw socket address, not a URL"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_dot_segments_in_node_id() {
        for node_id in [".", ".."] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:7000".into(),
                    p2p_addr: "127.0.0.1:7001".into(),
                },
                "inline",
            )
            .expect_err("dot-segment node_id must fail closed");
            assert!(
                err.to_string()
                    .contains("node_id must not be '.' or '..'"),
                "unexpected error for {node_id:?}: {err:#}"
            );
        }
    }

    #[test]
    fn validate_node_config_rejects_host_like_node_id_and_url_style_operator_addresses() {
        for node_id in [
            "localhost",
            "LOCALHOST",
            "127.0.0.1",
            "127.0.0.1:7000",
            "bootstrap.example.com",
            "node-2.bootstrap.internal",
        ] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:7000".into(),
                    p2p_addr: "127.0.0.1:7001".into(),
                },
                "inline",
            )
            .expect_err("host-like node_id literals must fail closed");
            assert!(
                err.to_string()
                    .contains("node_id must not look like a host or socket literal"),
                "unexpected error for {node_id:?}: {err:#}"
            );
        }

        let rpc_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "http://127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("URL-style rpc_addr must fail closed");
        assert!(
            rpc_err
                .to_string()
                .contains("rpc_addr must be a raw socket address, not a URL"),
            "unexpected error: {rpc_err:#}"
        );

        let p2p_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "tcp://127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("URL-style p2p_addr must fail closed");
        assert!(
            p2p_err
                .to_string()
                .contains("p2p_addr must be a raw socket address, not a URL"),
            "unexpected error: {p2p_err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_internal_whitespace_in_operator_addresses() {
        let rpc_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:70 00".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr internal whitespace must fail closed");
        assert!(
            rpc_err
                .to_string()
                .contains("rpc_addr must not contain whitespace"),
            "unexpected error: {rpc_err:#}"
        );

        let p2p_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:70 01".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr internal whitespace must fail closed");
        assert!(
            p2p_err
                .to_string()
                .contains("p2p_addr must not contain whitespace"),
            "unexpected error: {p2p_err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_list_separators_in_operator_addresses() {
        let rpc_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000,127.0.0.1:7002".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr list separators must fail closed");
        assert!(
            rpc_err
                .to_string()
                .contains("rpc_addr must not contain list separators (, ; |)"),
            "unexpected error: {rpc_err:#}"
        );

        let p2p_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:7001|127.0.0.1:7003".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr list separators must fail closed");
        assert!(
            p2p_err
                .to_string()
                .contains("p2p_addr must not contain list separators (, ; |)"),
            "unexpected error: {p2p_err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_path_separators_in_operator_addresses() {
        let rpc_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1/7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr path separators must fail closed");
        assert!(
            rpc_err
                .to_string()
                .contains("rpc_addr must not contain path separators"),
            "unexpected error: {rpc_err:#}"
        );

        let p2p_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1\\7001".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr path separators must fail closed");
        assert!(
            p2p_err
                .to_string()
                .contains("p2p_addr must not contain path separators"),
            "unexpected error: {p2p_err:#}"
        );
    }

}
