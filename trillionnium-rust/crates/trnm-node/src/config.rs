use anyhow::{Context, Result};
use serde::Deserialize;
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeConfig {
    pub(crate) node_id: String,
    pub(crate) rpc_addr: String,
    pub(crate) p2p_addr: String,
}

const MAX_NODE_ID_LEN: usize = 64;

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

fn is_link_local_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(addr) => addr.is_link_local(),
        std::net::IpAddr::V6(addr) => addr.is_unicast_link_local(),
    }
}

fn is_documentation_or_benchmark_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(addr) => {
            let octets = addr.octets();
            matches!(octets, [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _])
                || (octets[0] == 198 && octets[1] >= 18 && octets[1] <= 19)
        }
        std::net::IpAddr::V6(addr) => {
            let segments = addr.segments();
            segments[0] == 0x2001 && segments[1] == 0x0db8
        }
    }
}

fn is_ipv4_mapped_ipv6(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(_) => false,
        std::net::IpAddr::V6(addr) => addr.to_ipv4_mapped().is_some(),
    }
}

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

fn has_nonzero_ipv6_scope(socket: SocketAddr) -> bool {
    match socket {
        SocketAddr::V4(_) => false,
        SocketAddr::V6(addr) => addr.scope_id() != 0,
    }
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
        !node_id.contains('"') && !node_id.contains('\'') && !node_id.contains('`'),
        "invalid node config {}: node_id must not contain quoting characters (\" ' `)",
        path
    );
    anyhow::ensure!(
        !node_id.contains('[') && !node_id.contains(']'),
        "invalid node config {}: node_id must not contain bracketed host delimiters ([ ])",
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
            && node_id.parse::<std::net::IpAddr>().is_err()
            && node_id.parse::<SocketAddr>().is_err(),
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
        !contains_invisible_or_bidi_format_chars(rpc_addr),
        "invalid node config {}: rpc_addr must not contain invisible or bidirectional format characters",
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
        !contains_invisible_or_bidi_format_chars(p2p_addr),
        "invalid node config {}: p2p_addr must not contain invisible or bidirectional format characters",
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
    let rpc_socket: SocketAddr = rpc_addr.parse().with_context(|| {
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
        !is_link_local_ip(rpc_socket.ip()),
        "invalid node config {}: rpc_addr must not use a link-local address",
        path
    );
    anyhow::ensure!(
        !is_ipv4_mapped_ipv6(rpc_socket.ip()),
        "invalid node config {}: rpc_addr must not use an IPv4-mapped IPv6 address",
        path
    );
    anyhow::ensure!(
        !is_ipv4_compatible_ipv6(rpc_socket.ip()),
        "invalid node config {}: rpc_addr must not use an IPv4-compatible IPv6 address",
        path
    );
    anyhow::ensure!(
        !has_nonzero_ipv6_scope(rpc_socket),
        "invalid node config {}: rpc_addr must not use an IPv6 scope identifier",
        path
    );
    anyhow::ensure!(
        !is_documentation_or_benchmark_ip(rpc_socket.ip()),
        "invalid node config {}: rpc_addr must not use a documentation or benchmark-only address",
        path
    );
    let p2p_socket: SocketAddr = p2p_addr.parse().with_context(|| {
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
        !is_link_local_ip(p2p_socket.ip()),
        "invalid node config {}: p2p_addr must not use a link-local address",
        path
    );
    anyhow::ensure!(
        !is_ipv4_mapped_ipv6(p2p_socket.ip()),
        "invalid node config {}: p2p_addr must not use an IPv4-mapped IPv6 address",
        path
    );
    anyhow::ensure!(
        !is_ipv4_compatible_ipv6(p2p_socket.ip()),
        "invalid node config {}: p2p_addr must not use an IPv4-compatible IPv6 address",
        path
    );
    anyhow::ensure!(
        !has_nonzero_ipv6_scope(p2p_socket),
        "invalid node config {}: p2p_addr must not use an IPv6 scope identifier",
        path
    );
    anyhow::ensure!(
        !is_documentation_or_benchmark_ip(p2p_socket.ip()),
        "invalid node config {}: p2p_addr must not use a documentation or benchmark-only address",
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

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node")
}

fn resolve_config_path(path: &str) -> PathBuf {
    let requested = Path::new(path);
    if requested.is_absolute() {
        return requested.to_path_buf();
    }

    let workspace_root = workspace_root();
    let workspace_anchor = workspace_root.file_name().map(Path::new);
    let workspace_anchor = workspace_anchor
        .and_then(|anchor| {
            requested
                .strip_prefix(anchor)
                .ok()
                .or_else(|| requested.strip_prefix(Path::new(".")).ok()?.strip_prefix(anchor).ok())
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

fn ensure_config_path_stays_within_allowed_roots(requested: &str, resolved: &Path) -> Result<()> {
    if !resolved.exists() {
        return Ok(());
    }

    let canonical_resolved = resolved
        .canonicalize()
        .unwrap_or_else(|_| resolved.to_path_buf());
    let workspace_root = workspace_root()
        .canonicalize()
        .unwrap_or_else(|_| workspace_root().to_path_buf());
    let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
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
    ensure_config_path_stays_within_allowed_roots(path, &resolved)?;
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

#[cfg(test)]
mod tests {
    use super::{load_config, resolve_config_path, validate_node_config, NodeConfig};

    #[test]
    fn resolve_config_path_anchors_default_node_config_to_workspace_root() {
        let resolved = resolve_config_path("configs/node1.toml");
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node");
        assert_eq!(resolved, workspace_root.join("configs/node1.toml"));
        assert!(resolved.is_file(), "expected shipped node1 config to exist");
    }

    #[test]
    fn resolve_config_path_anchors_repo_root_workspace_path_to_workspace_root() {
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
        let cfg =
            load_config("configs/node1.toml").expect("repo-root launches should resolve legacy default config path");
        assert_eq!(cfg.node_id, "node1");
        assert_eq!(cfg.rpc_addr, "127.0.0.1:26657");
        assert_eq!(cfg.p2p_addr, "127.0.0.1:26656");
    }

    #[test]
    fn load_config_accepts_repo_root_workspace_path_for_shipped_bootstrap_config() {
        let cfg = load_config("trillionnium-rust/configs/node1.toml")
            .expect("repo-root workspace bootstrap config should resolve");
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
        let cfg =
            load_config("./configs/node1.toml").expect("curdir-prefixed repo-root bootstrap config should resolve");
        assert_eq!(cfg.node_id, "node1");
        assert_eq!(cfg.rpc_addr, "127.0.0.1:26657");
        assert_eq!(cfg.p2p_addr, "127.0.0.1:26656");
    }

    #[test]
    fn load_config_accepts_inner_curdir_markers_for_shipped_bootstrap_paths() {
        for path in ["configs/./node1.toml", "./configs/./node1.toml"] {
            let cfg = load_config(path).unwrap_or_else(|err| {
                panic!("{path} should resolve for shipped bootstrap config anchoring: {err:#}")
            });
            assert_eq!(cfg.node_id, "node1", "unexpected node_id for {path}");
            assert_eq!(cfg.rpc_addr, "127.0.0.1:26657", "unexpected rpc_addr for {path}");
            assert_eq!(cfg.p2p_addr, "127.0.0.1:26656", "unexpected p2p_addr for {path}");
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
            .expect_err("boundary whitespace in node bootstrap config must fail closed");
        let err_surface = err.to_string();
        assert!(
            err_surface.contains("node_id must not contain leading or trailing whitespace"),
            "unexpected error: {err:#}"
        );
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
    fn resolve_config_path_does_not_anchor_curdir_prefixed_workspace_parent_traversal() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node");
        let outside_path = workspace_root.join("../configs/node1.toml");
        assert!(outside_path.exists(), "expected parent traversal fixture to exist");

        let resolved = resolve_config_path("./trillionnium-rust/../configs/node1.toml");
        assert_eq!(
            resolved,
            std::path::PathBuf::from("./trillionnium-rust/../configs/node1.toml")
        );
    }

    #[test]
    fn load_config_rejects_relative_symlink_escape_outside_workspace_and_cwd() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let temp_root = std::env::temp_dir().join(format!(
            "trnm-node-config-symlink-escape-{}-{}",
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
    fn load_config_rejects_absolute_path_outside_workspace_and_cwd() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let workspace_root = super::workspace_root()
            .canonicalize()
            .expect("workspace root should canonicalize");
        let current_dir = std::env::current_dir()
            .expect("capture cwd")
            .canonicalize()
            .expect("cwd should canonicalize");
        let outside_path = std::env::temp_dir().join(format!(
            "trnm-node-config-absolute-outside-{}-{}.toml",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after unix epoch")
                .as_millis()
        ));
        std::fs::write(
            &outside_path,
            "node_id = \"node-escape\"\nrpc_addr = \"127.0.0.1:30001\"\np2p_addr = \"127.0.0.1:30000\"\n",
        )
        .expect("outside config should be writable");

        let err = load_config(outside_path.to_str().expect("utf8 path"))
            .expect_err("absolute config path outside allowed roots should fail closed");
        let canonical_outside = outside_path
            .canonicalize()
            .expect("outside path should canonicalize");
        let _ = std::fs::remove_file(&outside_path);

        assert!(
            !canonical_outside.starts_with(&workspace_root)
                && !canonical_outside.starts_with(&current_dir),
            "test fixture must stay outside allowed roots"
        );
        assert!(
            err.to_string().contains("resolves outside allowed roots"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn load_config_rejects_blank_rpc_addr_with_operator_facing_error() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-blank-rpc-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \"   \"\np2p_addr = \"127.0.0.1:7001\"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path")).expect_err("blank rpc must fail");
        assert!(
            err.to_string().contains("rpc_addr must not be empty"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_blank_path_fail_closed() {
        let err = load_config("   ").expect_err("blank config path must fail closed");
        assert!(
            err.to_string().contains("path must not be empty"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn load_config_rejects_control_characters_in_path_fail_closed() {
        let err = load_config("configs/node1.toml\n")
            .expect_err("config path control characters must fail closed");
        assert!(
            err.to_string()
                .contains("path must not contain control characters"),
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
                .expect_err("config path invisible/bidi format characters must fail closed");
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
                .expect_err("multi-config path separators must fail closed");
            assert!(
                err.to_string()
                    .contains("path must not contain list separators (, ; |)"),
                "unexpected error for {path:?}: {err:#}"
            );
        }
    }

    #[test]
    fn load_config_rejects_url_style_paths_fail_closed() {
        for path in [
            "http://127.0.0.1:26657/node1.toml",
            "https://example.invalid/node1.toml",
            "file:///tmp/node1.toml",
        ] {
            let err = load_config(path).expect_err("URL-style config paths must fail closed");
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
            "configs/..\\node1.toml",
            "configs\\../node1.toml",
        ] {
            let err = load_config(path).expect_err("config path parent traversal must fail closed");
            assert!(
                err.to_string()
                    .contains("path must not contain parent traversal (..)"),
                "unexpected error for {path:?}: {err:#}"
            );
        }
    }

    #[test]
    fn load_config_rejects_unknown_fields_to_keep_bootstrap_config_fail_closed() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-unknown-field-{}-{}.toml",
            std::process::id(),
            now_unix_ms()
        ));
        std::fs::write(
            &path,
            r#"node_id = "node1"
rpc_addr = "127.0.0.1:26657"
p2p_addr = "127.0.0.1:26656"
bootstrap_peers = ["127.0.0.1:27656"]
"#,
        )
        .expect("write temp config");

        let err = load_config(path.to_str().expect("temp path utf-8"))
            .expect_err("unknown config fields must fail closed");
        let err_surface = format!("{err:#}");
        assert!(
            err_surface.contains("parse toml failed")
                && err_surface.contains("unknown field `bootstrap_peers`"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn load_config_rejects_blank_node_id_with_operator_facing_error() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-blank-node-id-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"   \"\nrpc_addr = \"127.0.0.1:7000\"\np2p_addr = \"127.0.0.1:7001\"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("blank node_id must fail");
        assert!(
            err.to_string().contains("node_id must not be empty"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_blank_p2p_addr_with_operator_facing_error() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-blank-p2p-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:7000\"\np2p_addr = \"   \"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("blank p2p_addr must fail");
        assert!(
            err.to_string().contains("p2p_addr must not be empty"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_host_like_node_id_with_operator_facing_error() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-host-like-node-id-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"127.0.0.1\"\nrpc_addr = \"127.0.0.1:7000\"\np2p_addr = \"127.0.0.1:7001\"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("host-like node_id must fail closed");
        assert!(
            err.to_string()
                .contains("node_id must not look like a host or socket literal"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_localhost_style_node_id_with_operator_facing_error() {
        for node_id in ["localhost", "LOCALHOST"] {
            let path = std::env::temp_dir().join(format!(
                "trnm-node-config-localhost-node-id-{}-{}-{node_id}.toml",
                std::process::id(),
                std::thread::current().name().unwrap_or("unnamed")
            ));
            std::fs::write(
                &path,
                format!(
                    "node_id = \"{node_id}\"\nrpc_addr = \"127.0.0.1:7000\"\np2p_addr = \"127.0.0.1:7001\"\n"
                ),
            )
            .expect("write config");

            let err = load_config(path.to_str().expect("utf8 path"))
                .expect_err("localhost-style node_id must fail closed");
            assert!(
                err.to_string()
                    .contains("node_id must not look like a host or socket literal"),
                "unexpected error for {node_id:?}: {err:#}"
            );

            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn validate_node_config_rejects_shared_rpc_and_p2p_addr() {
        let cfg = NodeConfig {
            node_id: "node-a".into(),
            rpc_addr: "127.0.0.1:7000".into(),
            p2p_addr: "127.0.0.1:7000".into(),
        };

        let err = validate_node_config(cfg, "inline").expect_err("shared listen addr must fail");
        assert!(
            err.to_string()
                .contains("rpc_addr and p2p_addr must differ"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_mixed_ip_families() {
        let cfg = NodeConfig {
            node_id: "node-a".into(),
            rpc_addr: "127.0.0.1:7000".into(),
            p2p_addr: "[::1]:7001".into(),
        };

        let err = validate_node_config(cfg, "inline")
            .expect_err("mixed IPv4/IPv6 listener families must fail closed");
        assert!(
            err.to_string()
                .contains("rpc_addr and p2p_addr must use the same IP family"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_distinct_listener_ips_within_same_family() {
        let cfg = NodeConfig {
            node_id: "node-a".into(),
            rpc_addr: "127.0.0.1:7000".into(),
            p2p_addr: "127.0.0.2:7001".into(),
        };

        let err = validate_node_config(cfg, "inline")
            .expect_err("distinct same-family listener IPs must fail closed");
        assert!(
            err.to_string()
                .contains("rpc_addr and p2p_addr must bind the same IP"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn load_config_rejects_shared_rpc_and_p2p_addr_after_operator_trimming() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-shared-listen-addr-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \" 127.0.0.1:7000\\n\"\np2p_addr = \"\\t127.0.0.1:7000 \"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("trimmed shared listen addr must fail closed");
        assert!(
            err.to_string()
                .contains("rpc_addr and p2p_addr must differ"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_distinct_listener_ips_after_operator_trimming() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-distinct-listener-ips-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \" 127.0.0.1:7000\\n\"\np2p_addr = \"\\t127.0.0.2:7001 \"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("trimmed distinct listener IPs must fail closed");
        assert!(
            err.to_string()
                .contains("rpc_addr and p2p_addr must bind the same IP"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_mixed_ip_families_after_operator_trimming() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-mixed-ip-families-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \" 127.0.0.1:7000\\n\"\np2p_addr = \"\\t[::1]:7001 \"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("trimmed mixed-family listener addresses must fail closed");
        assert!(
            err.to_string()
                .contains("rpc_addr and p2p_addr must use the same IP family"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_unspecified_listener_after_operator_trimming() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-unspecified-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \" 0.0.0.0:7000\\n\"\np2p_addr = \"\\t127.0.0.1:7001 \"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("trimmed unspecified listener must fail closed");
        assert!(
            err.to_string()
                .contains("rpc_addr must not use an unspecified address"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_unspecified_p2p_listener_after_operator_trimming() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-unspecified-p2p-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \" 127.0.0.1:7000\\n\"\np2p_addr = \"\\t[::]:7001 \"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("trimmed unspecified p2p listener must fail closed");
        assert!(
            err.to_string()
                .contains("p2p_addr must not use an unspecified address"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_broadcast_rpc_listener_after_operator_trimming() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-broadcast-rpc-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \" 255.255.255.255:7000\\t\"\np2p_addr = \"127.0.0.1:7001\"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("trimmed broadcast rpc listener must fail closed");
        assert!(
            err.to_string()
                .contains("rpc_addr must not use the IPv4 broadcast address"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_broadcast_p2p_listener_after_operator_trimming() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-broadcast-p2p-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:7000\"\np2p_addr = \" 255.255.255.255:7001\\t\"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("trimmed broadcast p2p listener must fail closed");
        assert!(
            err.to_string()
                .contains("p2p_addr must not use the IPv4 broadcast address"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_documentation_rpc_listener_with_operator_facing_error() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-documentation-rpc-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \"192.0.2.10:7000\"\np2p_addr = \"192.0.2.10:7001\"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("documentation rpc listener must fail closed");
        assert!(
            err.to_string()
                .contains("rpc_addr must not use a documentation or benchmark-only address"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_documentation_p2p_listener_with_operator_facing_error() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-documentation-p2p-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:7000\"\np2p_addr = \"198.19.0.10:7001\"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("documentation p2p listener must fail closed");
        assert!(
            err.to_string()
                .contains("p2p_addr must not use a documentation or benchmark-only address"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_multicast_listener_after_operator_trimming() {
        let rpc_path = std::env::temp_dir().join(format!(
            "trnm-node-config-multicast-rpc-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &rpc_path,
            "node_id = \"node-a\"\nrpc_addr = \" 239.1.2.3:7000\\n\"\np2p_addr = \"\\t127.0.0.1:7001 \"\n",
        )
        .expect("write config");

        let rpc_err = load_config(rpc_path.to_str().expect("utf8 path"))
            .expect_err("trimmed multicast rpc listener must fail closed");
        assert!(
            rpc_err
                .to_string()
                .contains("rpc_addr must not use a multicast address"),
            "unexpected error: {rpc_err:#}"
        );

        let _ = std::fs::remove_file(rpc_path);

        let p2p_path = std::env::temp_dir().join(format!(
            "trnm-node-config-multicast-p2p-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &p2p_path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:7000\"\np2p_addr = \" [ff02::1]:7001\\t\"\n",
        )
        .expect("write config");

        let p2p_err = load_config(p2p_path.to_str().expect("utf8 path"))
            .expect_err("trimmed multicast p2p listener must fail closed");
        assert!(
            p2p_err
                .to_string()
                .contains("p2p_addr must not use a multicast address"),
            "unexpected error: {p2p_err:#}"
        );

        let _ = std::fs::remove_file(p2p_path);
    }

    #[test]
    fn load_config_rejects_link_local_listener_after_operator_trimming() {
        let rpc_path = std::env::temp_dir().join(format!(
            "trnm-node-config-link-local-rpc-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &rpc_path,
            "node_id = \"node-a\"\nrpc_addr = \"169.254.10.20:7000\"\np2p_addr = \"127.0.0.1:7001\"\n",
        )
        .expect("write config");

        let rpc_err = load_config(rpc_path.to_str().expect("utf8 path"))
            .expect_err("trimmed link-local rpc listener must fail closed");
        assert!(
            rpc_err
                .to_string()
                .contains("rpc_addr must not use a link-local address"),
            "unexpected error: {rpc_err:#}"
        );

        let _ = std::fs::remove_file(rpc_path);

        let p2p_path = std::env::temp_dir().join(format!(
            "trnm-node-config-link-local-p2p-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &p2p_path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:7000\"\np2p_addr = \"[fe80::1]:7001\"\n",
        )
        .expect("write config");

        let p2p_err = load_config(p2p_path.to_str().expect("utf8 path"))
            .expect_err("trimmed link-local p2p listener must fail closed");
        assert!(
            p2p_err
                .to_string()
                .contains("p2p_addr must not use a link-local address"),
            "unexpected error: {p2p_err:#}"
        );

        let _ = std::fs::remove_file(p2p_path);
    }

    #[test]
    fn validate_node_config_rejects_invalid_socket_addresses() {
        let rpc_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "not-an-addr".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("invalid rpc_addr must fail closed");
        assert!(
            rpc_err
                .to_string()
                .contains("rpc_addr must be a valid socket address"),
            "unexpected error: {rpc_err:#}"
        );

        let p2p_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1".into(),
            },
            "inline",
        )
        .expect_err("invalid p2p_addr must fail closed");
        assert!(
            p2p_err
                .to_string()
                .contains("p2p_addr must be a valid socket address"),
            "unexpected error: {p2p_err:#}"
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

        let uppercase_ipv6_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[::1]:26657".into(),
                p2p_addr: "[::FFFF:127.0.0.1]:26656".into(),
            },
            "inline",
        )
        .expect_err("uppercase IPv6 host literals must fail closed until rewritten canonically");
        assert!(
            uppercase_ipv6_err
                .to_string()
                .contains("p2p_addr must use a canonical socket address literal"),
            "unexpected error: {uppercase_ipv6_err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_port_zero_listeners() {
        let rpc_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:0".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr port zero must fail closed");
        assert!(
            rpc_err
                .to_string()
                .contains("rpc_addr must not use port 0"),
            "unexpected error: {rpc_err:#}"
        );

        let p2p_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:0".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr port zero must fail closed");
        assert!(
            p2p_err
                .to_string()
                .contains("p2p_addr must not use port 0"),
            "unexpected error: {p2p_err:#}"
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
                p2p_addr: "127.0.0.1:443".into(),
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
    fn validate_node_config_rejects_multicast_broadcast_unspecified_link_local_and_documentation_listener_addresses(
    ) {
        let rpc_multicast_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "239.1.2.3:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr multicast must fail closed");
        assert!(
            rpc_multicast_err
                .to_string()
                .contains("rpc_addr must not use a multicast address"),
            "unexpected error: {rpc_multicast_err:#}"
        );

        let p2p_multicast_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "ff02::1:7001".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr multicast must fail closed");
        assert!(
            p2p_multicast_err
                .to_string()
                .contains("p2p_addr must not use a multicast address"),
            "unexpected error: {p2p_multicast_err:#}"
        );

        let rpc_broadcast_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "255.255.255.255:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr broadcast must fail closed");
        assert!(
            rpc_broadcast_err
                .to_string()
                .contains("rpc_addr must not use the IPv4 broadcast address"),
            "unexpected error: {rpc_broadcast_err:#}"
        );

        let p2p_broadcast_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "255.255.255.255:7001".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr broadcast must fail closed");
        assert!(
            p2p_broadcast_err
                .to_string()
                .contains("p2p_addr must not use the IPv4 broadcast address"),
            "unexpected error: {p2p_broadcast_err:#}"
        );

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

        let rpc_link_local_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "169.254.10.20:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
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
                rpc_addr: "[::1]:7000".into(),
                p2p_addr: "[fe80::1]:7001".into(),
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

        let rpc_ipv4_mapped_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[::ffff:127.0.0.1]:7000".into(),
                p2p_addr: "[2001:db8::1]:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr IPv4-mapped IPv6 bind must fail closed");
        assert!(
            rpc_ipv4_mapped_err
                .to_string()
                .contains("rpc_addr must not use an IPv4-mapped IPv6 address"),
            "unexpected error: {rpc_ipv4_mapped_err:#}"
        );

        let p2p_ipv4_mapped_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[2001:db8::1]:7000".into(),
                p2p_addr: "[::ffff:127.0.0.1]:7001".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr IPv4-mapped IPv6 bind must fail closed");
        assert!(
            p2p_ipv4_mapped_err
                .to_string()
                .contains("p2p_addr must not use an IPv4-mapped IPv6 address"),
            "unexpected error: {p2p_ipv4_mapped_err:#}"
        );

        let rpc_compatible_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[::7f00:1]:7000".into(),
                p2p_addr: "[2001:4860::1]:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr IPv4-compatible IPv6 bind must fail closed");
        assert!(
            rpc_compatible_err
                .to_string()
                .contains("rpc_addr must not use an IPv4-compatible IPv6 address"),
            "unexpected error: {rpc_compatible_err:#}"
        );

        let p2p_compatible_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[2001:4860::1]:7000".into(),
                p2p_addr: "[::c000:20a]:7001".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr IPv4-compatible IPv6 bind must fail closed");
        assert!(
            p2p_compatible_err
                .to_string()
                .contains("p2p_addr must not use an IPv4-compatible IPv6 address"),
            "unexpected error: {p2p_compatible_err:#}"
        );

        let rpc_scope_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[2001:db8::10%7]:7000".into(),
                p2p_addr: "[2001:db8::10]:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr IPv6 scope identifier must fail closed");
        assert!(
            rpc_scope_err
                .to_string()
                .contains("rpc_addr must not use an IPv6 scope identifier"),
            "unexpected error: {rpc_scope_err:#}"
        );

        let p2p_scope_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[2001:db8::10]:7000".into(),
                p2p_addr: "[2001:db8::10%9]:7001".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr IPv6 scope identifier must fail closed");
        assert!(
            p2p_scope_err
                .to_string()
                .contains("p2p_addr must not use an IPv6 scope identifier"),
            "unexpected error: {p2p_scope_err:#}"
        );

        for rpc_addr in [
            "192.0.2.10:7000",
            "198.51.100.10:7000",
            "203.0.113.10:7000",
            "198.18.0.10:7000",
            "[2001:db8::10]:7000",
        ] {
            let rpc_err = validate_node_config(
                NodeConfig {
                    node_id: "node-a".into(),
                    rpc_addr: rpc_addr.into(),
                    p2p_addr: "127.0.0.1:7001".into(),
                },
                "inline",
            )
            .expect_err("rpc_addr documentation and benchmark ranges must fail closed");
            assert!(
                rpc_err
                    .to_string()
                    .contains("rpc_addr must not use a documentation or benchmark-only address"),
                "unexpected error for {rpc_addr:?}: {rpc_err:#}"
            );
        }

        for p2p_addr in [
            "192.0.2.10:7001",
            "198.51.100.10:7001",
            "203.0.113.10:7001",
            "198.19.0.10:7001",
            "[2001:db8::11]:7001",
        ] {
            let p2p_err = validate_node_config(
                NodeConfig {
                    node_id: "node-a".into(),
                    rpc_addr: "127.0.0.1:7000".into(),
                    p2p_addr: p2p_addr.into(),
                },
                "inline",
            )
            .expect_err("p2p_addr documentation and benchmark ranges must fail closed");
            assert!(
                p2p_err
                    .to_string()
                    .contains("p2p_addr must not use a documentation or benchmark-only address"),
                "unexpected error for {p2p_addr:?}: {p2p_err:#}"
            );
        }
    }

    #[test]
    fn validate_node_config_rejects_control_characters_in_node_id() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node\u{0007}1".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("node_id control characters must fail closed");
        assert!(
            err.to_string()
                .contains("node_id must not contain control characters"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_invisible_or_bidi_format_characters_in_node_id() {
        for node_id in ["node\u{200B}1", "node\u{202E}1"] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:7000".into(),
                    p2p_addr: "127.0.0.1:7001".into(),
                },
                "inline",
            )
            .expect_err("invisible/bidi node_id characters must fail closed");
            assert!(
                err.to_string()
                    .contains("node_id must not contain invisible or bidirectional format characters"),
                "unexpected error for {node_id:?}: {err:#}"
            );
        }
    }

    #[test]
    fn validate_node_config_rejects_invisible_or_bidi_format_characters_in_listener_addresses() {
        for (field, rpc_addr, p2p_addr, expected_message) in [
            (
                "rpc_addr",
                "127.0.0.1:70\u{200B}00",
                "127.0.0.1:7001",
                "rpc_addr must not contain invisible or bidirectional format characters",
            ),
            (
                "p2p_addr",
                "127.0.0.1:7000",
                "127.0.0.1:70\u{202E}01",
                "p2p_addr must not contain invisible or bidirectional format characters",
            ),
        ] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: "node-a".into(),
                    rpc_addr: rpc_addr.into(),
                    p2p_addr: p2p_addr.into(),
                },
                "inline",
            )
            .expect_err("invisible/bidi listener characters must fail closed");
            assert!(
                err.to_string().contains(expected_message),
                "unexpected error for {field}: {err:#}"
            );
        }
    }

    #[test]
    fn validate_node_config_rejects_host_and_socket_literals_in_node_id() {
        for node_id in ["localhost", "127.0.0.1", "127.0.0.1:7000", "[::1]:7000"] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:7000".into(),
                    p2p_addr: "127.0.0.1:7001".into(),
                },
                "inline",
            )
            .expect_err("host/socket-shaped node_id must fail closed");
            assert!(
                err.to_string()
                    .contains("node_id must not look like a host or socket literal"),
                "unexpected error for {node_id}: {err:#}"
            );
        }
    }

    #[test]
    fn validate_node_config_rejects_url_like_listener_addresses() {
        let rpc_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "http://127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("URL-like rpc_addr must fail closed");
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
        .expect_err("URL-like p2p_addr must fail closed");
        assert!(
            p2p_err
                .to_string()
                .contains("p2p_addr must be a raw socket address, not a URL"),
            "unexpected error: {p2p_err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_internal_whitespace_in_node_id() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("node_id whitespace must fail closed");
        assert!(
            err.to_string().contains("node_id must not contain whitespace"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_overlong_node_id() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "n".repeat(MAX_NODE_ID_LEN + 1),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("overlong node_id must fail closed");
        assert!(
            err.to_string()
                .contains("node_id must be at most 64 bytes"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_accepts_node_id_at_max_length_boundary() {
        let cfg = validate_node_config(
            NodeConfig {
                node_id: "n".repeat(MAX_NODE_ID_LEN),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect("node_id at length boundary should remain valid");
        assert_eq!(cfg.node_id.len(), MAX_NODE_ID_LEN);
    }

    #[test]
    fn validate_node_config_rejects_leading_or_trailing_whitespace_in_node_id() {
        for node_id in [" node-a", "node-a ", "\tnode-a\n"] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:7000".into(),
                    p2p_addr: "127.0.0.1:7001".into(),
                },
                "inline",
            )
            .expect_err("node_id boundary whitespace must fail closed");
            assert!(
                err.to_string()
                    .contains("node_id must not contain leading or trailing whitespace"),
                "unexpected error for {node_id:?}: {err:#}"
            );
        }
    }

    #[test]
    fn validate_node_config_rejects_list_separators_in_node_id() {
        for node_id in ["node,a", "node;a", "node|a"] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:7000".into(),
                    p2p_addr: "127.0.0.1:7001".into(),
                },
                "inline",
            )
            .expect_err("node_id list separators must fail closed");
            assert!(
                err.to_string()
                    .contains("node_id must not contain list separators (, ; |)"),
                "unexpected error for {node_id:?}: {err:#}"
            );
        }
    }

    #[test]
    fn validate_node_config_rejects_path_separators_in_node_id() {
        for node_id in ["node/alpha", r"node\\alpha", "node:alpha", "[::1]"] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:7000".into(),
                    p2p_addr: "127.0.0.1:7001".into(),
                },
                "inline",
            )
            .expect_err("node_id path or host-literal separators must fail closed");
            assert!(
                err.to_string()
                    .contains("node_id must not contain path or host-literal separators"),
                "unexpected error for {node_id:?}: {err:#}"
            );
        }
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
            .expect_err("node_id dot segments must fail closed");
            assert!(
                err.to_string()
                    .contains("node_id must not be '.' or '..'"),
                "unexpected error for {node_id:?}: {err:#}"
            );
        }
    }

    #[test]
    fn validate_node_config_rejects_uri_and_userinfo_separators_in_node_id() {
        for node_id in [
            "node@alpha",
            "node?alpha",
            "node#alpha",
            "node%zone",
            "node&peer",
            "node=peer",
        ] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:7000".into(),
                    p2p_addr: "127.0.0.1:7001".into(),
                },
                "inline",
            )
            .expect_err("node_id URI/userinfo separators must fail closed");
            assert!(
                err.to_string()
                    .contains("node_id must not contain URI delimiters (@ ? # % & =)"),
                "unexpected error for {node_id:?}: {err:#}"
            );
        }
    }

    #[test]
    fn validate_node_config_rejects_quoting_characters_in_node_id() {
        for node_id in ["node\"alpha", "node'alpha", "node`alpha"] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:7000".into(),
                    p2p_addr: "127.0.0.1:7001".into(),
                },
                "inline",
            )
            .expect_err("node_id quoting characters must fail closed");
            assert!(
                err.to_string()
                    .contains("node_id must not contain quoting characters (\" ' `)"),
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
            "::1",
            "[::1]:7000",
            "::ffff:127.0.0.1",
            "[::ffff:127.0.0.1]:7000",
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
                rpc_addr: "127.0.0.1 :7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr with internal whitespace must fail");
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
                p2p_addr: "127.0.0.1:700 1".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr with internal whitespace must fail");
        assert!(
            p2p_err
                .to_string()
                .contains("p2p_addr must not contain whitespace"),
            "unexpected error: {p2p_err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_leading_or_trailing_whitespace_in_operator_addresses() {
        let rpc_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: " 127.0.0.1:7000 ".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr boundary whitespace must fail");
        assert!(
            rpc_err
                .to_string()
                .contains("rpc_addr must not contain leading or trailing whitespace"),
            "unexpected error: {rpc_err:#}"
        );

        let p2p_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "\t127.0.0.1:7001\n".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr boundary whitespace must fail");
        assert!(
            p2p_err
                .to_string()
                .contains("p2p_addr must not contain leading or trailing whitespace"),
            "unexpected error: {p2p_err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_control_characters_in_operator_addresses() {
        let rpc_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000\u{0007}".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr with control characters must fail closed");
        assert!(
            rpc_err
                .to_string()
                .contains("rpc_addr must not contain control characters"),
            "unexpected error: {rpc_err:#}"
        );

        let p2p_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:7001\u{001b}".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr with control characters must fail closed");
        assert!(
            p2p_err
                .to_string()
                .contains("p2p_addr must not contain control characters"),
            "unexpected error: {p2p_err:#}"
        );
    }



    #[test]
    fn validate_node_config_rejects_list_separators_in_operator_addresses() {
        for rpc_addr in [
            "127.0.0.1:7000,127.0.0.1:7002",
            "127.0.0.1:7000;127.0.0.1:7002",
            "127.0.0.1:7000|127.0.0.1:7002",
        ] {
            let rpc_err = validate_node_config(
                NodeConfig {
                    node_id: "node-a".into(),
                    rpc_addr: rpc_addr.into(),
                    p2p_addr: "127.0.0.1:7001".into(),
                },
                "inline",
            )
            .expect_err("rpc_addr list separators must fail closed");
            assert!(
                rpc_err
                    .to_string()
                    .contains("rpc_addr must not contain list separators (, ; |)"),
                "unexpected error for {rpc_addr:?}: {rpc_err:#}"
            );
        }

        for p2p_addr in [
            "127.0.0.1:7001,127.0.0.1:7003",
            "127.0.0.1:7001;127.0.0.1:7003",
            "127.0.0.1:7001|127.0.0.1:7003",
        ] {
            let p2p_err = validate_node_config(
                NodeConfig {
                    node_id: "node-a".into(),
                    rpc_addr: "127.0.0.1:7000".into(),
                    p2p_addr: p2p_addr.into(),
                },
                "inline",
            )
            .expect_err("p2p_addr list separators must fail closed");
            assert!(
                p2p_err
                    .to_string()
                    .contains("p2p_addr must not contain list separators (, ; |)"),
                "unexpected error for {p2p_addr:?}: {p2p_err:#}"
            );
        }
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

    #[test]
    fn shipped_bootstrap_configs_keep_a_minimal_fail_closed_schema() {
        use std::collections::BTreeSet;

        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node");

        for config_name in ["node1.toml", "node2.toml", "node3.toml", "node4.toml"] {
            let config_path = workspace_root.join("configs").join(config_name);
            let raw = std::fs::read_to_string(&config_path).unwrap_or_else(|err| {
                panic!(
                    "{} should stay readable for shipped bootstrap schema checks: {err}",
                    config_path.display()
                )
            });
            let table: toml::Table = raw.parse().unwrap_or_else(|err| {
                panic!(
                    "{} should remain valid TOML for shipped bootstrap schema checks: {err}",
                    config_path.display()
                )
            });
            let actual_keys = table.keys().cloned().collect::<BTreeSet<_>>();
            let expected_keys = BTreeSet::from([
                String::from("node_id"),
                String::from("rpc_addr"),
                String::from("p2p_addr"),
            ]);
            assert_eq!(
                actual_keys, expected_keys,
                "{} must keep the minimal shipped bootstrap schema so peer formation fixtures stay deterministic and fail closed",
                config_path.display()
            );
        }
    }

    #[test]
    fn shipped_bootstrap_configs_keep_their_three_line_slot_bound_layout() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node");

        for (config_name, expected_node_id, expected_rpc_addr, expected_p2p_addr) in [
            ("node1.toml", "node1", "127.0.0.1:26657", "127.0.0.1:26656"),
            ("node2.toml", "node2", "127.0.0.1:27657", "127.0.0.1:27656"),
            ("node3.toml", "node3", "127.0.0.1:28657", "127.0.0.1:28656"),
            ("node4.toml", "node4", "127.0.0.1:29657", "127.0.0.1:29656"),
        ] {
            let config_path = workspace_root.join("configs").join(config_name);
            let raw = std::fs::read_to_string(&config_path).unwrap_or_else(|err| {
                panic!(
                    "{} should stay readable for shipped bootstrap line-layout checks: {err}",
                    config_path.display()
                )
            });
            let non_empty_lines = raw
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>();
            let expected_lines = vec![
                format!("node_id = \"{expected_node_id}\""),
                format!("rpc_addr = \"{expected_rpc_addr}\""),
                format!("p2p_addr = \"{expected_p2p_addr}\""),
            ];
            assert_eq!(
                non_empty_lines,
                expected_lines,
                "{} must keep the exact three-line slot-bound layout so shipped bootstrap fixtures stay deterministic for peer/bootstrap rehearsal",
                config_path.display()
            );
        }
    }

    #[test]
    fn shipped_bootstrap_configs_keep_canonical_peer_identity_and_listener_literals() {
        use std::net::SocketAddr;

        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node");

        for config_name in ["node1.toml", "node2.toml", "node3.toml", "node4.toml"] {
            let config_path = workspace_root.join("configs").join(config_name);
            let raw = std::fs::read_to_string(&config_path).unwrap_or_else(|err| {
                panic!(
                    "{} should stay readable for shipped bootstrap literal checks: {err}",
                    config_path.display()
                )
            });
            let table: toml::Table = raw.parse().unwrap_or_else(|err| {
                panic!(
                    "{} should remain valid TOML for shipped bootstrap literal checks: {err}",
                    config_path.display()
                )
            });

            let node_id = table
                .get("node_id")
                .and_then(|value| value.as_str())
                .unwrap_or_else(|| {
                    panic!(
                        "{} must keep node_id as a TOML string literal",
                        config_path.display()
                    )
                });
            assert_eq!(
                node_id,
                node_id.trim(),
                "{} node_id must not hide boundary whitespace in shipped bootstrap peer identity fixtures",
                config_path.display()
            );
            assert!(
                !node_id.chars().any(char::is_whitespace),
                "{} node_id must not contain whitespace in shipped bootstrap peer identity fixtures",
                config_path.display()
            );

            for key in ["rpc_addr", "p2p_addr"] {
                let addr = table
                    .get(key)
                    .and_then(|value| value.as_str())
                    .unwrap_or_else(|| {
                        panic!(
                            "{} {} must stay a TOML string literal",
                            config_path.display(),
                            key
                        )
                    });
                assert_eq!(
                    addr,
                    addr.trim(),
                    "{} {} must not hide boundary whitespace in shipped bootstrap listener fixtures",
                    config_path.display(),
                    key
                );
                assert!(
                    !addr.chars().any(char::is_whitespace),
                    "{} {} must not contain whitespace in shipped bootstrap listener fixtures",
                    config_path.display(),
                    key
                );
                let socket: SocketAddr = addr.parse().unwrap_or_else(|err| {
                    panic!(
                        "{} {} should remain parseable as a canonical socket literal: {err}",
                        config_path.display(),
                        key
                    )
                });
                assert_eq!(
                    addr,
                    socket.to_string(),
                    "{} {} must remain a canonical socket literal for deterministic bootstrap peer dialing",
                    config_path.display(),
                    key
                );
            }
        }
    }

    #[test]
    fn shipped_bootstrap_readme_matches_the_documented_day1_topology_and_fail_closed_model() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node");
        let readme_path = workspace_root.join("configs").join("README.md");
        let workspace_relative_readme_path = std::path::Path::new("configs/README.md");
        let curdir_repo_relative_readme_path = std::path::Path::new("./configs/README.md");
        let readme_metadata = std::fs::symlink_metadata(&readme_path).unwrap_or_else(|err| {
            panic!(
                "{} should stay stat-able for shipped bootstrap README checks: {err}",
                readme_path.display()
            )
        });
        assert!(
            readme_metadata.file_type().is_file(),
            "{} must remain a regular file for deterministic shipped bootstrap README checks",
            readme_path.display()
        );
        assert!(
            !readme_metadata.file_type().is_symlink(),
            "{} must not become a symlink that can retarget shipped bootstrap README checks",
            readme_path.display()
        );
        let workspace_relative_readme_metadata =
            std::fs::symlink_metadata(workspace_relative_readme_path).unwrap_or_else(|err| {
                panic!(
                    "{} should stay stat-able for bootstrap README path anchoring: {err}",
                    workspace_relative_readme_path.display()
                )
            });
        assert!(
            workspace_relative_readme_metadata.file_type().is_file(),
            "{} must remain a regular file for bootstrap README path anchoring",
            workspace_relative_readme_path.display()
        );
        assert!(
            !workspace_relative_readme_metadata.file_type().is_symlink(),
            "{} must not become a symlink that can retarget bootstrap README path anchoring",
            workspace_relative_readme_path.display()
        );
        let canonical_readme_path = readme_path.canonicalize().unwrap_or_else(|err| {
            panic!(
                "{} should canonicalize for shipped bootstrap README checks: {err}",
                readme_path.display()
            )
        });
        let canonical_workspace_relative_readme_path = workspace_relative_readme_path
            .canonicalize()
            .unwrap_or_else(|err| {
                panic!(
                    "{} should canonicalize for bootstrap README path anchoring: {err}",
                    workspace_relative_readme_path.display()
                )
            });
        assert_eq!(
            canonical_workspace_relative_readme_path, canonical_readme_path,
            "{} must canonicalize to the same shipped bootstrap README as {}",
            workspace_relative_readme_path.display(),
            readme_path.display()
        );
        let canonical_curdir_repo_relative_readme_path = curdir_repo_relative_readme_path
            .canonicalize()
            .unwrap_or_else(|err| {
                panic!(
                    "{} should canonicalize for curdir-prefixed bootstrap README path anchoring: {err}",
                    curdir_repo_relative_readme_path.display()
                )
            });
        assert_eq!(
            canonical_curdir_repo_relative_readme_path, canonical_readme_path,
            "{} must canonicalize to the same shipped bootstrap README as {}",
            curdir_repo_relative_readme_path.display(),
            readme_path.display()
        );
        let readme = std::fs::read_to_string(&readme_path).unwrap_or_else(|err| {
            panic!(
                "{} should stay readable for shipped bootstrap README checks: {err}",
                readme_path.display()
            )
        });
        let ipv6_loopback_mentions = readme.matches("[::1]").count();
        assert_eq!(
            ipv6_loopback_mentions, 1,
            "{} must mention `[::1]` exactly once, only in the explicit fail-closed prohibition against IPv6 loopback drift",
            readme_path.display()
        );
        assert!(
            !readme.to_ascii_lowercase().contains("localhost"),
            "{} must not silently drift bootstrap anchor guidance from canonical `127.0.0.1` tuples to `localhost` aliases",
            readme_path.display()
        );

        let expected_lines = [
            "- `node1.toml` → node id `node1`, P2P `127.0.0.1:26656`, RPC `127.0.0.1:26657`",
            "- `node2.toml` → node id `node2`, P2P `127.0.0.1:27656`, RPC `127.0.0.1:27657`",
            "- `node3.toml` → node id `node3`, P2P `127.0.0.1:28656`, RPC `127.0.0.1:28657`",
            "- `node4.toml` → node id `node4`, P2P `127.0.0.1:29656`, RPC `127.0.0.1:29657`",
        ];
        let documented_topology_lines = readme
            .lines()
            .filter(|line| line.starts_with("- `node") && line.contains("→ node id `node"))
            .collect::<Vec<_>>();
        assert_eq!(
            documented_topology_lines,
            expected_lines,
            "{} must keep exactly the four shipped Day-1 bootstrap tuples in slot order so operator topology assumptions stay deterministic",
            readme_path.display()
        );
        for expected_line in expected_lines {
            assert!(
                readme.contains(expected_line),
                "{} must document the shipped Day-1 bootstrap tuple `{expected_line}` so operator topology assumptions stay explicit",
                readme_path.display()
            );
        }

        let expected_steps_in_order = [
            "1. Start `node1` first as the initial anchor.",
            "2. Start `node2`, `node3`, and `node4` in slot order.",
            "3. If `node1` is absent, do not treat `node2`, `node3`, or `node4` as a valid replacement bootstrap anchor; restore the shipped `node1` anchor first and fail closed otherwise.",
            "4. For a join or rejoin rehearsal, bring the node back with the same config file and the same `node_id`/listener tuple. Treat any drift from the shipped tuple as invalid until reviewed.",
            "5. Do not skip a missing earlier follower slot during startup or rejoin: if `node2` is absent, keep `node3` and `node4` stopped; if `node3` is absent, keep `node4` stopped until the earlier slot regains its shipped tuple.",
            "6. Treat `configs/node1.toml` through `configs/node4.toml` as slot-bound fixtures: do not rename them, swap them between peers, or reinterpret a later slot as the bootstrap anchor during operator recovery.",
            "7. If `node4` is absent, keep `node1` through `node3` in their shipped slots; do not rename another config into the `node4` role, and if `node4` returns it must come back with `node4.toml` and its shipped tuple.",
            "8. If a config contains unknown fields, whitespace drift, host-like or path-like ids, URI-like delimiters, non-canonical socket literals, privileged ports, wildcard listeners, reserved documentation/benchmarking listener ranges, or mixed listener IP families, the config loader must fail closed.",
            "9. Do not substitute IPv6 loopback `[::1]` for the shipped IPv4 loopback `127.0.0.1` during bootstrap or rejoin; listener-family drift is invalid even if both addresses are loopback.",
        ];
        let documented_startup_model_lines = readme
            .lines()
            .filter(|line| {
                line.starts_with("1. ")
                    || line.starts_with("2. ")
                    || line.starts_with("3. ")
                    || line.starts_with("4. ")
                    || line.starts_with("5. ")
                    || line.starts_with("6. ")
                    || line.starts_with("7. ")
                    || line.starts_with("8. ")
                    || line.starts_with("9. ")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            documented_startup_model_lines,
            expected_steps_in_order,
            "{} must keep exactly the shipped bootstrap startup/join/rejoin steps so operator recovery cannot silently gain extra numbered branches or lose a fail-closed rule",
            readme_path.display()
        );
        let expected_rows_in_order = [
            "| Fresh bootstrap start | Start `node1` first, then `node2` → `node3` → `node4` in slot order | Accept only when each node keeps its shipped slot-bound config and listener tuple |",
            "| Follower join while `node1` is healthy | Start the joining follower with its original config file (`node2.toml`, `node3.toml`, or `node4.toml`) | Accept only when `node_id`, `rpc_addr`, and `p2p_addr` exactly match the shipped tuple |",
            "| Follower rejoin after restart | Bring the same follower back with the same filename and the same tuple | Accept only when the rejoining node does not drift slots, IDs, or listener addresses |",
            "| Anchor rejoin after restart | Bring `node1` back only with `node1.toml`; resume follower startup/rejoin only after the shipped anchor tuple is restored | Accept only when `node1` regains the shipped anchor tuple before later slots continue |",
            "| `node1` missing during recovery | Restore `node1` first; do not promote a later slot into the anchor role | Reject until the shipped `node1` anchor tuple is back in place |",
            "| `node2` missing during startup or rejoin | Keep `node3` and `node4` stopped until `node2` returns with `node2.toml` and its shipped tuple | Reject while a later follower tries to skip the missing `node2` slot |",
            "| `node3` missing during startup or rejoin | Keep `node4` stopped until `node3` returns with `node3.toml` and its shipped tuple | Reject while `node4` tries to skip the missing `node3` slot |",
            "| `node4` missing during startup or rejoin | Keep `node1` through `node3` in their shipped slots; if `node4` returns, bring it back only with `node4.toml` and its shipped tuple | Accept the remaining slots only while no other config is renamed or promoted into the `node4` role |",
            "| Any tuple drift or config mutation | Stop and review before startup | Reject on renamed files, swapped slots, unknown fields, whitespace drift, non-canonical socket literals, or listener-family drift |",
        ];
        let expected_table_lines = [
            "| Scenario | Expected operator action | Acceptance |",
            "| --- | --- | --- |",
            expected_rows_in_order[0],
            expected_rows_in_order[1],
            expected_rows_in_order[2],
            expected_rows_in_order[3],
            expected_rows_in_order[4],
            expected_rows_in_order[5],
            expected_rows_in_order[6],
            expected_rows_in_order[7],
            expected_rows_in_order[8],
        ];
        let documented_acceptance_table_lines = readme
            .lines()
            .filter(|line| line.starts_with("| "))
            .collect::<Vec<_>>();
        assert_eq!(
            documented_acceptance_table_lines,
            expected_table_lines,
            "{} must keep exactly the shipped bootstrap acceptance table header + separator + scenario rows so topology recovery rules cannot silently drift",
            readme_path.display()
        );
        for expected_phrase in [
            "All four nodes bind the same loopback IP (`127.0.0.1`)",
            "keep RPC exactly one port above the matching P2P listener for each slot",
            "keep a deterministic `+1000` port spacing between neighboring peers",
            "`node1` is the unique shipped bootstrap anchor because it alone owns the lowest shipped P2P port (`127.0.0.1:26656`); later slots must never reuse that listener or identity.",
            "`node1` also owns the lowest shipped RPC port (`127.0.0.1:26657`); later slots must never drift downward into an equivalent anchor-shaped RPC tuple during startup, join, or rejoin.",
            "This fixture is local-only and rehearsal-scoped.",
            "Do not treat it as proof that public-mainnet bootstrap peer management, discovery, or sync closure is complete.",
            "Start `node1` first as the initial anchor.",
            "Start `node2`, `node3`, and `node4` in slot order.",
            "do not treat `node2`, `node3`, or `node4` as a valid replacement bootstrap anchor; restore the shipped `node1` anchor first and fail closed otherwise",
            "bring the node back with the same config file and the same `node_id`/listener tuple",
            "Do not skip a missing earlier follower slot during startup or rejoin: if `node2` is absent, keep `node3` and `node4` stopped; if `node3` is absent, keep `node4` stopped until the earlier slot regains its shipped tuple.",
            "Treat `configs/node1.toml` through `configs/node4.toml` as slot-bound fixtures: do not rename them, swap them between peers, or reinterpret a later slot as the bootstrap anchor during operator recovery.",
            "If `node4` is absent, keep `node1` through `node3` in their shipped slots; do not rename another config into the `node4` role, and if `node4` returns it must come back with `node4.toml` and its shipped tuple.",
            "unknown fields, whitespace drift, host-like or path-like ids, URI-like delimiters, non-canonical socket literals, privileged ports, wildcard listeners, reserved documentation/benchmarking listener ranges, or mixed listener IP families, the config loader must fail closed",
            "Do not substitute IPv6 loopback `[::1]` for the shipped IPv4 loopback `127.0.0.1` during bootstrap or rejoin; listener-family drift is invalid even if both addresses are loopback.",
            "## Join / rejoin acceptance table",
            expected_rows_in_order[0],
            expected_rows_in_order[1],
            expected_rows_in_order[2],
            expected_rows_in_order[3],
            expected_rows_in_order[4],
            expected_rows_in_order[5],
            expected_rows_in_order[6],
            expected_rows_in_order[7],
            expected_rows_in_order[8],
            "This table is intentionally local-fixture scoped: it documents the minimum fail-closed acceptance rule for shipped bootstrap rehearsal, not a claim that public-mainnet peer discovery, sync, or dynamic topology management is complete.",
        ] {
            assert!(
                readme.contains(expected_phrase),
                "{} must keep the shipped bootstrap join/rejoin fail-closed rule `{expected_phrase}` visible to operators",
                readme_path.display()
            );
        }
        let mut previous_step_index = None;
        for expected_step in expected_steps_in_order {
            let current_step_index = readme.find(expected_step).unwrap_or_else(|| {
                panic!(
                    "{} must keep the shipped bootstrap startup/join model step `{expected_step}` visible to operators",
                    readme_path.display()
                )
            });
            if let Some(previous_step_index) = previous_step_index {
                assert!(
                    previous_step_index < current_step_index,
                    "{} must keep bootstrap startup/join model steps in anchor-first slot order so operator recovery does not silently drift",
                    readme_path.display()
                );
            }
            previous_step_index = Some(current_step_index);
        }

        let mut previous_index = None;
        for expected_row in expected_rows_in_order {
            let current_index = readme.find(expected_row).unwrap_or_else(|| {
                panic!(
                    "{} must keep the shipped bootstrap acceptance-table row `{expected_row}` visible to operators",
                    readme_path.display()
                )
            });
            if let Some(previous_index) = previous_index {
                assert!(
                    previous_index < current_index,
                    "{} must keep bootstrap/join/rejoin acceptance rows in anchor-first slot order so operator recovery does not silently drift",
                    readme_path.display()
                );
            }
            previous_index = Some(current_index);
        }

        for expected_phrase in [
            "## What this fixture is for",
            "Use these files to keep peer/bootstrap topology assumptions explicit while the public-mainnet bootstrap peer-management path is still being hardened.",
            "Do not add ad-hoc `bootstrap_peers` or `seed_nodes` fields to these shipped fixtures; the local rehearsal schema stays the minimal three-field contract until a real peer-management surface exists.",
            "The regression tests in `crates/trnm-node/src/config.rs` are the source of truth for the exact fixture invariants.",
        ] {
            assert!(
                readme.contains(expected_phrase),
                "{} must keep the shipped bootstrap scope/source-of-truth note `{expected_phrase}` visible to operators",
                readme_path.display()
            );
        }
    }
    #[test]
    fn shipped_bootstrap_readme_tuples_match_loaded_configs_exactly() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node");
        let readme_path = workspace_root.join("configs").join("README.md");
        let readme = std::fs::read_to_string(&readme_path).unwrap_or_else(|err| {
            panic!(
                "{} should stay readable for shipped bootstrap README tuple/config parity checks: {err}",
                readme_path.display()
            )
        });

        let documented_topology_lines = readme
            .lines()
            .filter(|line| line.starts_with("- `node") && line.contains("→ node id `node"))
            .collect::<Vec<_>>();

        let derived_topology_lines = [
            "configs/node1.toml",
            "configs/node2.toml",
            "configs/node3.toml",
            "configs/node4.toml",
        ]
        .into_iter()
        .map(|relative_path| {
            let path = workspace_root.join(relative_path);
            let cfg = load_config(&path).unwrap_or_else(|err| {
                panic!(
                    "{} should remain loadable for shipped bootstrap README tuple/config parity checks: {err:#}",
                    path.display()
                )
            });
            let file_name = std::path::Path::new(relative_path)
                .file_name()
                .and_then(|name| name.to_str())
                .expect("shipped bootstrap config path should end in utf-8 filename");
            format!(
                "- `{file_name}` → node id `{}`, P2P `{}`, RPC `{}`",
                cfg.node_id, cfg.p2p_addr, cfg.rpc_addr
            )
        })
        .collect::<Vec<_>>();
        let derived_topology_line_refs = derived_topology_lines
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();

        assert_eq!(
            documented_topology_lines, derived_topology_line_refs,
            "{} must keep README Day-1 tuples exactly aligned with the shipped bootstrap configs so peer topology docs cannot silently drift from fixture truth",
            readme_path.display()
        );
    }

    #[test]
    fn shipped_bootstrap_anchor_stays_unique_and_slot_zero() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node");

        let mut shipped_nodes = [
            ("configs/node1.toml", "node1", 26656_u16, 26657_u16),
            ("configs/node2.toml", "node2", 27656_u16, 27657_u16),
            ("configs/node3.toml", "node3", 28656_u16, 28657_u16),
            ("configs/node4.toml", "node4", 29656_u16, 29657_u16),
        ]
        .into_iter()
        .map(
            |(relative_path, expected_node_id, expected_p2p_port, expected_rpc_port)| {
                let path = workspace_root.join(relative_path);
                let cfg = load_config(&path).unwrap_or_else(|err| {
                    panic!(
                        "{} should remain loadable for shipped bootstrap anchor checks: {err:#}",
                        path.display()
                    )
                });
                let p2p_socket: SocketAddr = cfg.p2p_addr.parse().unwrap_or_else(|err| {
                    panic!("{} p2p_addr should parse: {err}", path.display())
                });
                let rpc_socket: SocketAddr = cfg.rpc_addr.parse().unwrap_or_else(|err| {
                    panic!("{} rpc_addr should parse: {err}", path.display())
                });
                assert_eq!(
                    cfg.node_id, expected_node_id,
                    "{} must keep the deterministic node_id for bootstrap anchor slot checks",
                    path.display()
                );
                assert_eq!(
                    p2p_socket.port(), expected_p2p_port,
                    "{} must keep the deterministic p2p port for bootstrap anchor slot checks",
                    path.display()
                );
                assert_eq!(
                    rpc_socket.port(), expected_rpc_port,
                    "{} must keep the deterministic rpc port for bootstrap anchor slot checks",
                    path.display()
                );
                (path, cfg.node_id, p2p_socket.port(), rpc_socket.port())
            },
        )
        .collect::<Vec<_>>();

        shipped_nodes.sort_by_key(|(_, _, p2p_port, rpc_port)| (*p2p_port, *rpc_port));
        let anchor = shipped_nodes
            .first()
            .expect("shipped bootstrap fixture should include node1 anchor");
        assert_eq!(
            anchor.1, "node1",
            "{} must remain the unique shipped Day-1 bootstrap anchor id",
            anchor.0.display()
        );
        assert_eq!(
            anchor.2, 26656,
            "{} must remain the unique shipped Day-1 bootstrap anchor p2p port",
            anchor.0.display()
        );
        assert_eq!(
            anchor.3, 26657,
            "{} must remain the unique shipped Day-1 bootstrap anchor rpc port",
            anchor.0.display()
        );

        for (path, node_id, p2p_port, rpc_port) in shipped_nodes.iter().skip(1) {
            assert_ne!(
                node_id, &anchor.1,
                "{} must not reuse the shipped bootstrap anchor node_id {}",
                path.display(),
                anchor.1
            );
            assert!(
                *p2p_port > anchor.2,
                "{} p2p port {} must stay above the shipped bootstrap anchor port {} so later slots cannot silently become equivalent bootstrap anchors",
                path.display(),
                p2p_port,
                anchor.2
            );
            assert!(
                *rpc_port > anchor.3,
                "{} rpc port {} must stay above the shipped bootstrap anchor rpc port {} so later slots cannot silently become equivalent bootstrap anchors",
                path.display(),
                rpc_port,
                anchor.3
            );
        }
    }

    #[test]
    fn shipped_node_configs_form_a_unique_local_bootstrap_topology() {
        use std::{collections::HashSet, net::SocketAddr};

        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node");
        let shipped_config_dir = workspace_root.join("configs");
        let shipped_config_dir_metadata = std::fs::symlink_metadata(&shipped_config_dir).unwrap_or_else(|err| {
            panic!(
                "{} should stay stat-able for shipped bootstrap topology directory checks: {err}",
                shipped_config_dir.display()
            )
        });
        assert!(
            shipped_config_dir_metadata.file_type().is_dir(),
            "{} must remain a real directory for deterministic shipped bootstrap topology discovery",
            shipped_config_dir.display()
        );
        assert!(
            !shipped_config_dir_metadata.file_type().is_symlink(),
            "{} must not become a symlink that can retarget shipped bootstrap topology discovery",
            shipped_config_dir.display()
        );
        let canonical_shipped_config_dir = shipped_config_dir.canonicalize().unwrap_or_else(|err| {
            panic!(
                "{} should canonicalize for shipped bootstrap topology checks: {err}",
                shipped_config_dir.display()
            )
        });
        let shipped_config_entry_names = std::fs::read_dir(&shipped_config_dir)
            .unwrap_or_else(|err| {
                panic!(
                    "{} should stay readable for shipped bootstrap config discovery: {err}",
                    shipped_config_dir.display()
                )
            })
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let shipped_config_entries = shipped_config_entry_names.iter().cloned().collect::<HashSet<_>>();
        let expected_shipped_config_entries = HashSet::from([
            String::from("README.md"),
            String::from("node1.toml"),
            String::from("node2.toml"),
            String::from("node3.toml"),
            String::from("node4.toml"),
        ]);
        assert_eq!(
            shipped_config_entries, expected_shipped_config_entries,
            "shipped bootstrap config dir must stay exactly README.md + node1.toml..node4.toml so peer/bootstrap topology fixtures remain deterministic and fail closed"
        );
        let mut sorted_shipped_config_entry_names = shipped_config_entry_names;
        sorted_shipped_config_entry_names.sort();
        assert_eq!(
            sorted_shipped_config_entry_names,
            vec![
                String::from("README.md"),
                String::from("node1.toml"),
                String::from("node2.toml"),
                String::from("node3.toml"),
                String::from("node4.toml"),
            ],
            "shipped bootstrap config dir entries must remain in deterministic README + node1..node4 lexical slot order so bootstrap topology discovery cannot hide slot drift behind set equality"
        );
        let shipped_node_configs = shipped_config_entries
            .iter()
            .filter(|name| name.starts_with("node") && name.ends_with(".toml"))
            .cloned()
            .collect::<HashSet<_>>();
        let expected_shipped_node_configs = HashSet::from([
            String::from("node1.toml"),
            String::from("node2.toml"),
            String::from("node3.toml"),
            String::from("node4.toml"),
        ]);
        assert_eq!(
            shipped_node_configs, expected_shipped_node_configs,
            "shipped bootstrap config set must stay exactly node1.toml..node4.toml to keep deterministic peer formation fixtures intact"
        );

        let mut node_ids = HashSet::new();
        let mut rpc_addrs = HashSet::new();
        let mut p2p_addrs = HashSet::new();
        let mut all_listener_addrs = HashSet::new();
        let mut shipped_nodes = Vec::new();
        let mut bootstrap_loopback_ips = HashSet::new();

        for (index, (config_path, workspace_relative_path, curdir_repo_relative_path)) in [
            (
                "trillionnium-rust/configs/node1.toml",
                "configs/node1.toml",
                "./configs/node1.toml",
            ),
            (
                "trillionnium-rust/configs/node2.toml",
                "configs/node2.toml",
                "./configs/node2.toml",
            ),
            (
                "trillionnium-rust/configs/node3.toml",
                "configs/node3.toml",
                "./configs/node3.toml",
            ),
            (
                "trillionnium-rust/configs/node4.toml",
                "configs/node4.toml",
                "./configs/node4.toml",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let on_disk_metadata = std::fs::symlink_metadata(config_path).unwrap_or_else(|err| {
                panic!(
                    "{config_path} should stay stat-able for shipped bootstrap topology checks: {err}"
                )
            });
            assert!(
                on_disk_metadata.file_type().is_file(),
                "{config_path} must remain a regular file for deterministic shipped bootstrap topology fixtures"
            );
            assert!(
                !on_disk_metadata.file_type().is_symlink(),
                "{config_path} must not become a symlink that can retarget shipped bootstrap topology fixtures"
            );
            let workspace_relative_metadata =
                std::fs::symlink_metadata(workspace_relative_path).unwrap_or_else(|err| {
                    panic!(
                        "{workspace_relative_path} should stay stat-able for bootstrap/rejoin path anchoring: {err}"
                    )
                });
            assert!(
                workspace_relative_metadata.file_type().is_file(),
                "{workspace_relative_path} must remain a regular file for deterministic bootstrap/rejoin path anchoring"
            );
            assert!(
                !workspace_relative_metadata.file_type().is_symlink(),
                "{workspace_relative_path} must not become a symlink that can retarget shipped bootstrap/rejoin fixtures"
            );

            let canonical_config_path = std::path::Path::new(config_path)
                .canonicalize()
                .unwrap_or_else(|err| {
                    panic!(
                        "{config_path} should canonicalize for shipped bootstrap topology checks: {err}"
                    )
                });
            assert_eq!(
                canonical_config_path.parent(),
                Some(canonical_shipped_config_dir.as_path()),
                "{config_path} must canonicalize inside {} to keep shipped bootstrap topology path anchoring deterministic",
                canonical_shipped_config_dir.display()
            );
            let canonical_workspace_relative_path = std::path::Path::new(workspace_relative_path)
                .canonicalize()
                .unwrap_or_else(|err| {
                    panic!(
                        "{workspace_relative_path} should canonicalize for bootstrap/rejoin path anchoring: {err}"
                    )
                });
            assert_eq!(
                canonical_workspace_relative_path, canonical_config_path,
                "{workspace_relative_path} must canonicalize to the same shipped bootstrap fixture as {config_path}"
            );
            let canonical_curdir_repo_relative_path = std::path::Path::new(curdir_repo_relative_path)
                .canonicalize()
                .unwrap_or_else(|err| {
                    panic!(
                        "{curdir_repo_relative_path} should canonicalize for curdir-prefixed bootstrap/rejoin path anchoring: {err}"
                    )
                });
            assert_eq!(
                canonical_curdir_repo_relative_path, canonical_config_path,
                "{curdir_repo_relative_path} must canonicalize to the same shipped bootstrap fixture as {config_path}"
            );

            let cfg = load_config(config_path)
                .unwrap_or_else(|err| panic!("{config_path} should remain loadable: {err:#}"));
            let workspace_relative_cfg = load_config(workspace_relative_path).unwrap_or_else(|err| {
                panic!(
                    "{workspace_relative_path} should remain loadable for bootstrap/rejoin path anchoring: {err:#}"
                )
            });
            let curdir_repo_relative_cfg =
                load_config(curdir_repo_relative_path).unwrap_or_else(|err| {
                    panic!(
                        "{curdir_repo_relative_path} should remain loadable for curdir-prefixed bootstrap/rejoin path anchoring: {err:#}"
                    )
                });
            assert_eq!(
                workspace_relative_cfg.node_id, cfg.node_id,
                "{workspace_relative_path} must resolve to the same shipped bootstrap node_id as {config_path}"
            );
            assert_eq!(
                workspace_relative_cfg.rpc_addr, cfg.rpc_addr,
                "{workspace_relative_path} must resolve to the same shipped bootstrap rpc_addr as {config_path}"
            );
            assert_eq!(
                workspace_relative_cfg.p2p_addr, cfg.p2p_addr,
                "{workspace_relative_path} must resolve to the same shipped bootstrap p2p_addr as {config_path}"
            );
            assert_eq!(
                curdir_repo_relative_cfg.node_id, cfg.node_id,
                "{curdir_repo_relative_path} must resolve to the same shipped bootstrap node_id as {config_path}"
            );
            assert_eq!(
                curdir_repo_relative_cfg.rpc_addr, cfg.rpc_addr,
                "{curdir_repo_relative_path} must resolve to the same shipped bootstrap rpc_addr as {config_path}"
            );
            assert_eq!(
                curdir_repo_relative_cfg.p2p_addr, cfg.p2p_addr,
                "{curdir_repo_relative_path} must resolve to the same shipped bootstrap p2p_addr as {config_path}"
            );
            let expected_node_id = format!("node{}", index + 1);
            let expected_p2p_port = 26_656 + (index as u16) * 1_000;
            let expected_rpc_port = expected_p2p_port + 1;
            let config_slot = index + 1;
            let file_stem = std::path::Path::new(config_path)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .expect("shipped bootstrap config path should end in utf-8 filename stem");
            let filename_slot = file_stem
                .strip_prefix("node")
                .and_then(|slot| slot.parse::<usize>().ok())
                .unwrap_or_else(|| panic!("{config_path} should keep a numeric `nodeN.toml` slot name"));
            let rpc_socket: SocketAddr = cfg
                .rpc_addr
                .parse()
                .unwrap_or_else(|err| panic!("{config_path} rpc_addr should parse: {err}"));
            let p2p_socket: SocketAddr = cfg
                .p2p_addr
                .parse()
                .unwrap_or_else(|err| panic!("{config_path} p2p_addr should parse: {err}"));

            assert_eq!(
                cfg.node_id, expected_node_id,
                "{config_path} must keep the deterministic shipped bootstrap node_id for slot {config_slot}"
            );
            assert_eq!(
                filename_slot, config_slot,
                "{config_path} filename slot must stay aligned with the deterministic shipped bootstrap slot order"
            );
            assert!(
                node_ids.insert(cfg.node_id.clone()),
                "{config_path} reuses node_id {}",
                cfg.node_id
            );
            assert!(
                rpc_addrs.insert(cfg.rpc_addr.clone()),
                "{config_path} reuses rpc_addr {}",
                cfg.rpc_addr
            );
            assert!(
                p2p_addrs.insert(cfg.p2p_addr.clone()),
                "{config_path} reuses p2p_addr {}",
                cfg.p2p_addr
            );
            assert!(
                all_listener_addrs.insert(cfg.rpc_addr.clone()),
                "{config_path} rpc_addr {} collides with another shipped listener address",
                cfg.rpc_addr
            );
            assert!(
                all_listener_addrs.insert(cfg.p2p_addr.clone()),
                "{config_path} p2p_addr {} collides with another shipped listener address",
                cfg.p2p_addr
            );
            assert_eq!(
                rpc_socket.ip(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                "{config_path} rpc_addr {} must stay pinned to 127.0.0.1 for the shipped local bootstrap topology",
                cfg.rpc_addr
            );
            assert!(
                !is_reserved_listener_ip(rpc_socket.ip()),
                "{config_path} rpc_addr {} must not drift into reserved documentation or benchmarking ranges for shipped bootstrap rehearsal",
                cfg.rpc_addr
            );
            assert_eq!(
                cfg.rpc_addr,
                rpc_socket.to_string(),
                "{config_path} rpc_addr {} must remain a canonical socket literal for deterministic bootstrap peer dialing",
                cfg.rpc_addr
            );
            assert_eq!(
                p2p_socket.ip(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                "{config_path} p2p_addr {} must stay pinned to 127.0.0.1 for the shipped local bootstrap topology",
                cfg.p2p_addr
            );
            assert!(
                !is_reserved_listener_ip(p2p_socket.ip()),
                "{config_path} p2p_addr {} must not drift into reserved documentation or benchmarking ranges for shipped bootstrap rehearsal",
                cfg.p2p_addr
            );
            assert_eq!(
                cfg.p2p_addr,
                p2p_socket.to_string(),
                "{config_path} p2p_addr {} must remain a canonical socket literal for deterministic bootstrap peer dialing",
                cfg.p2p_addr
            );
            assert_eq!(
                rpc_socket.is_ipv4(),
                p2p_socket.is_ipv4(),
                "{config_path} rpc_addr {} and p2p_addr {} must stay in the same IP family",
                cfg.rpc_addr,
                cfg.p2p_addr
            );
            assert_eq!(
                rpc_socket.ip(),
                p2p_socket.ip(),
                "{config_path} rpc_addr {} and p2p_addr {} must bind the same loopback IP for deterministic shipped bootstrap peer formation",
                cfg.rpc_addr,
                cfg.p2p_addr
            );
            bootstrap_loopback_ips.insert(rpc_socket.ip());
            assert_eq!(
                p2p_socket.port(),
                expected_p2p_port,
                "{config_path} p2p_addr {} must keep the deterministic shipped bootstrap port for slot {config_slot}",
                cfg.p2p_addr,
            );
            assert!(
                p2p_socket.port() >= 1024,
                "{config_path} p2p_addr {} must stay above privileged ports for shipped bootstrap rehearsal",
                cfg.p2p_addr,
            );
            assert_eq!(
                rpc_socket.port(),
                expected_rpc_port,
                "{config_path} rpc_addr {} must keep the deterministic shipped bootstrap RPC port for slot {config_slot}",
                cfg.rpc_addr,
            );
            assert!(
                rpc_socket.port() >= 1024,
                "{config_path} rpc_addr {} must stay above privileged ports for shipped bootstrap rehearsal",
                cfg.rpc_addr,
            );
            assert_eq!(
                rpc_socket.port(),
                p2p_socket.port() + 1,
                "{config_path} rpc_addr {} must stay exactly one port above p2p_addr {} for the shipped local bootstrap topology",
                cfg.rpc_addr,
                cfg.p2p_addr
            );
            shipped_nodes.push((config_path, cfg.node_id, rpc_socket, p2p_socket));
        }

        assert_eq!(
            bootstrap_loopback_ips.len(),
            1,
            "shipped local bootstrap configs must all stay on the same loopback IP for deterministic peer dialing"
        );

        for window in shipped_nodes.windows(2) {
            let [
                (prev_config_path, prev_node_id, prev_rpc_socket, prev_p2p_socket),
                (config_path, node_id, rpc_socket, p2p_socket),
            ] = window
            else {
                continue;
            };

            assert_eq!(
                p2p_socket.port() - prev_p2p_socket.port(),
                1000,
                "{config_path} p2p_addr {} must stay 1000 ports above prior shipped bootstrap peer {} ({}) to keep the local multi-node topology deterministic",
                p2p_socket,
                prev_node_id,
                prev_config_path
            );
            assert_eq!(
                rpc_socket.port() - prev_rpc_socket.port(),
                1000,
                "{config_path} rpc_addr {} must stay 1000 ports above prior shipped bootstrap peer {} ({}) to keep the local multi-node topology deterministic",
                rpc_socket,
                prev_node_id,
                prev_config_path
            );
            assert!(
                node_id > prev_node_id,
                "{config_path} node_id {} must remain lexically ordered after prior shipped bootstrap peer {} ({})",
                node_id,
                prev_node_id,
                prev_config_path
            );
        }
    }
}
