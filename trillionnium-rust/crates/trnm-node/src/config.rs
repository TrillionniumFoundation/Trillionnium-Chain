use anyhow::{Context, Result};
use serde::Deserialize;
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Debug, Deserialize)]
pub(crate) struct NodeConfig {
    pub(crate) node_id: String,
    pub(crate) rpc_addr: String,
    pub(crate) p2p_addr: String,
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
    let rpc_socket: SocketAddr = rpc_addr.parse().with_context(|| {
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

    Ok(NodeConfig {
        node_id: node_id.to_string(),
        rpc_addr: rpc_addr.to_string(),
        p2p_addr: p2p_addr.to_string(),
    })
}

fn resolve_config_path(path: &str) -> PathBuf {
    let requested = Path::new(path);
    if requested.is_absolute() {
        return requested.to_path_buf();
    }

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("trnm-node manifest should sit under trillionnium-rust/crates/trnm-node");
    let workspace_relative = workspace_root.join(requested);
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
    fn validate_node_config_trims_operator_addresses() {
        let cfg = NodeConfig {
            node_id: "  node-a  ".into(),
            rpc_addr: " 127.0.0.1:7000\n".into(),
            p2p_addr: "\t127.0.0.1:7001 ".into(),
        };

        let cfg = validate_node_config(cfg, "inline").expect("trimmed config should validate");
        assert_eq!(cfg.node_id, "node-a");
        assert_eq!(cfg.rpc_addr, "127.0.0.1:7000");
        assert_eq!(cfg.p2p_addr, "127.0.0.1:7001");
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
    fn shipped_node_configs_form_a_unique_local_bootstrap_topology() {
        use std::{collections::HashSet, net::SocketAddr};

        let mut node_ids = HashSet::new();
        let mut rpc_addrs = HashSet::new();
        let mut p2p_addrs = HashSet::new();
        let mut all_listener_addrs = HashSet::new();
        let mut shipped_nodes = Vec::new();

        for config_path in [
            "trillionnium-rust/configs/node1.toml",
            "trillionnium-rust/configs/node2.toml",
            "trillionnium-rust/configs/node3.toml",
            "trillionnium-rust/configs/node4.toml",
        ] {
            let cfg = load_config(config_path)
                .unwrap_or_else(|err| panic!("{config_path} should remain loadable: {err:#}"));
            let rpc_socket: SocketAddr = cfg
                .rpc_addr
                .parse()
                .unwrap_or_else(|err| panic!("{config_path} rpc_addr should parse: {err}"));
            let p2p_socket: SocketAddr = cfg
                .p2p_addr
                .parse()
                .unwrap_or_else(|err| panic!("{config_path} p2p_addr should parse: {err}"));

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
            assert!(
                rpc_socket.ip().is_loopback(),
                "{config_path} rpc_addr {} must stay on loopback for shipped local bootstrap configs",
                cfg.rpc_addr
            );
            assert!(
                p2p_socket.ip().is_loopback(),
                "{config_path} p2p_addr {} must stay on loopback for shipped local bootstrap configs",
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
                rpc_socket.port(),
                p2p_socket.port() + 1,
                "{config_path} rpc_addr {} must stay exactly one port above p2p_addr {} for the shipped local bootstrap topology",
                cfg.rpc_addr,
                cfg.p2p_addr
            );
            shipped_nodes.push((config_path, cfg.node_id, rpc_socket, p2p_socket));
        }

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
