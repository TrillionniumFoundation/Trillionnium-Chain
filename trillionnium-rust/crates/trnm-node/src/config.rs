use anyhow::{Context, Result};
use serde::Deserialize;
use std::{fs, net::SocketAddr};

#[derive(Debug, Deserialize)]
pub(crate) struct NodeConfig {
    pub(crate) node_id: String,
    pub(crate) rpc_addr: String,
    pub(crate) p2p_addr: String,
}

fn validate_listen_addr(addr: &str, field: &str, path: &str) -> Result<()> {
    let socket_addr = addr.parse::<SocketAddr>().with_context(|| {
        format!(
            "invalid node config {}: {} must be a valid socket address host:port",
            path, field
        )
    })?;
    anyhow::ensure!(
        socket_addr.port() != 0,
        "invalid node config {}: {} port must be non-zero",
        path,
        field
    );
    Ok(())
}

fn validate_node_config(cfg: NodeConfig, path: &str) -> Result<NodeConfig> {
    let node_id = cfg.node_id.trim();
    anyhow::ensure!(
        !node_id.is_empty(),
        "invalid node config {}: node_id must not be empty",
        path
    );
    anyhow::ensure!(
        !node_id.chars().any(char::is_whitespace),
        "invalid node config {}: node_id must not contain whitespace",
        path
    );
    anyhow::ensure!(
        !node_id.chars().any(char::is_control),
        "invalid node config {}: node_id must not contain control characters",
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
    validate_listen_addr(rpc_addr, "rpc_addr", path)?;
    validate_listen_addr(p2p_addr, "p2p_addr", path)?;
    anyhow::ensure!(
        rpc_addr != p2p_addr,
        "invalid node config {}: rpc_addr and p2p_addr must differ",
        path
    );

    Ok(NodeConfig {
        node_id: node_id.to_string(),
        rpc_addr: rpc_addr.to_string(),
        p2p_addr: p2p_addr.to_string(),
    })
}

pub(crate) fn load_config(path: &str) -> Result<NodeConfig> {
    let raw = fs::read_to_string(path).with_context(|| format!("read config failed: {}", path))?;
    let cfg: NodeConfig =
        toml::from_str(&raw).with_context(|| format!("parse toml failed: {}", path))?;
    validate_node_config(cfg, path)
}

#[cfg(test)]
mod tests {
    use super::{load_config, validate_node_config, NodeConfig};

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

        let err =
            load_config(path.to_str().expect("utf8 path")).expect_err("blank node_id must fail");
        assert!(
            err.to_string().contains("node_id must not be empty"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
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

        let err = load_config(path.to_str().expect("utf8 path")).expect_err("blank p2p must fail");
        assert!(
            err.to_string().contains("p2p_addr must not be empty"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_shared_rpc_and_p2p_addr_after_trimming_with_operator_facing_error() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-shared-rpc-p2p-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \" 127.0.0.1:7000\\n\"\np2p_addr = \"\\t127.0.0.1:7000 \"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("shared rpc/p2p addr must fail even after trimming");
        assert!(
            err.to_string()
                .contains("rpc_addr and p2p_addr must differ"),
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
    fn validate_node_config_rejects_shared_rpc_and_p2p_addr_after_trimming() {
        let cfg = NodeConfig {
            node_id: "node-a".into(),
            rpc_addr: " 127.0.0.1:7000\n".into(),
            p2p_addr: "\t127.0.0.1:7000 ".into(),
        };

        let err = validate_node_config(cfg, "inline")
            .expect_err("trimmed shared listen addr must still fail");
        assert!(
            err.to_string()
                .contains("rpc_addr and p2p_addr must differ"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_whitespace_in_node_id() {
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
    fn validate_node_config_rejects_invalid_rpc_socket_addr() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr without host:port must fail closed");
        assert!(
            err.to_string()
                .contains("rpc_addr must be a valid socket address host:port"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_invalid_p2p_socket_addr() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:not-a-port".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr without numeric port must fail closed");
        assert!(
            err.to_string()
                .contains("p2p_addr must be a valid socket address host:port"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_zero_rpc_port() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:0".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("rpc_addr port zero must fail closed");
        assert!(
            err.to_string().contains("rpc_addr port must be non-zero"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn load_config_rejects_zero_rpc_port_after_trimming_with_operator_facing_error() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-zero-rpc-port-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \" 127.0.0.1:0\\n\"\np2p_addr = \"127.0.0.1:7001\"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("trimmed zero rpc port must fail closed");
        assert!(
            err.to_string().contains("rpc_addr port must be non-zero"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn validate_node_config_rejects_zero_p2p_port() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:0".into(),
            },
            "inline",
        )
        .expect_err("p2p_addr port zero must fail closed");
        assert!(
            err.to_string().contains("p2p_addr port must be non-zero"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn load_config_rejects_zero_p2p_port_after_trimming_with_operator_facing_error() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-zero-p2p-port-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:7000\"\np2p_addr = \"\t127.0.0.1:0 \"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("trimmed zero p2p port must fail closed");
        assert!(
            err.to_string().contains("p2p_addr port must be non-zero"),
            "unexpected error: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }
}

