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
        !node_id.chars().any(char::is_control),
        "invalid node config {}: node_id must not contain control characters",
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
        !node_id.contains('/') && !node_id.contains('\\') && !node_id.contains(':'),
        "invalid node config {}: node_id must not contain path separators (/ \\ :)",
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

fn ensure_relative_config_path_stays_within_allowed_roots(
    requested: &str,
    resolved: &Path,
) -> Result<()> {
    if Path::new(requested).is_absolute() || !resolved.exists() {
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

pub(crate) fn load_config(path: &str) -> Result<NodeConfig> {
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
    fn load_config_accepts_curdir_prefixed_workspace_path_for_shipped_bootstrap_config() {
        let cfg = load_config("./trillionnium-rust/configs/node1.toml")
            .expect("curdir-prefixed workspace bootstrap config should resolve");
        assert_eq!(cfg.node_id, "node1");
        assert_eq!(cfg.rpc_addr, "127.0.0.1:26657");
        assert_eq!(cfg.p2p_addr, "127.0.0.1:26656");
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
    fn validate_node_config_rejects_multicast_broadcast_and_unspecified_listener_addresses() {
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
        let err = validate_node_config(
            NodeConfig {
                node_id: "node,a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("node_id list separators must fail closed");
        assert!(
            err.to_string()
                .contains("node_id must not contain list separators (, ; |)"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_path_separators_in_node_id() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node/alpha".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("node_id path separators must fail closed");
        assert!(
            err.to_string()
                .contains("node_id must not contain path separators"),
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
            .expect_err("node_id dot segments must fail closed");
            assert!(
                err.to_string()
                    .contains("node_id must not be '.' or '..'"),
                "unexpected error for {node_id:?}: {err:#}"
            );
        }
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
    fn shipped_node_configs_form_a_unique_local_bootstrap_topology() {
        use std::{collections::HashSet, net::SocketAddr};

        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node");
        let shipped_config_dir = workspace_root.join("configs");
        let shipped_node_configs = std::fs::read_dir(&shipped_config_dir)
            .unwrap_or_else(|err| {
                panic!(
                    "{} should stay readable for shipped bootstrap config discovery: {err}",
                    shipped_config_dir.display()
                )
            })
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("node") && name.ends_with(".toml"))
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

        for (index, (config_path, workspace_relative_path)) in [
            ("trillionnium-rust/configs/node1.toml", "configs/node1.toml"),
            ("trillionnium-rust/configs/node2.toml", "configs/node2.toml"),
            ("trillionnium-rust/configs/node3.toml", "configs/node3.toml"),
            ("trillionnium-rust/configs/node4.toml", "configs/node4.toml"),
        ]
        .into_iter()
        .enumerate()
        {
            let cfg = load_config(config_path)
                .unwrap_or_else(|err| panic!("{config_path} should remain loadable: {err:#}"));
            let workspace_relative_cfg = load_config(workspace_relative_path).unwrap_or_else(|err| {
                panic!(
                    "{workspace_relative_path} should remain loadable for bootstrap/rejoin path anchoring: {err:#}"
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
            let expected_node_id = format!("node{}", index + 1);
            let expected_p2p_port = 26_656 + (index as u16) * 1_000;
            let expected_rpc_port = expected_p2p_port + 1;
            let config_slot = index + 1;
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
            assert_eq!(
                rpc_socket.port(),
                expected_rpc_port,
                "{config_path} rpc_addr {} must keep the deterministic shipped bootstrap RPC port for slot {config_slot}",
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
