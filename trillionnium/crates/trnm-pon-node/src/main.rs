//! Ordinary native development entrypoint. Signed transactions remain external inputs.
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
use trnm_crypto_primitives::qualified_work_task::{
    derive_matrices, verify_development_admission, TaskMaterial,
};
use trnm_pon_node::{development_public, digest, ingress, Error, Node, Packet, Result, Settings};
use trnm_protocol::qualified_work_task::{SignedQualifiedWorkTask, TaskPurpose};
fn need<'a>(args: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    args.get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {key}").into())
}
fn number(args: &BTreeMap<String, String>, key: &str, default: u64) -> Result<u64> {
    args.get(key)
        .map(|s| s.parse().map_err(|_| Error::from(format!("invalid {key}"))))
        .unwrap_or(Ok(default))
}
fn read(path: &str, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("INPUT_LIMIT".into());
    }
    Ok(bytes)
}
fn read_owned_configuration(
    path: &str,
    limit: u64,
    private: bool,
    file_error: &'static str,
    length_error: &'static str,
) -> Result<Vec<u8>> {
    // Inspect the opened descriptor, not a path checked before open. O_NOFOLLOW plus
    // the descriptor metadata closes the symlink/replacement window for these inputs.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error::from(file_error))?;
    let metadata = file.metadata().map_err(|_| Error::from(file_error))?;
    let mode = metadata.permissions().mode();
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || (private && mode & 0o077 != 0)
        || (!private && mode & 0o022 != 0)
    {
        return Err(file_error.into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::from(file_error))?;
    if bytes.len() as u64 > limit {
        return Err(length_error.into());
    }
    Ok(bytes)
}

fn secret_identity(path: &str) -> Result<ingress::DevelopmentIdentity> {
    let bytes = read_owned_configuration(path, 65, true, "AUTH_SECRET_FILE", "AUTH_SECRET_LENGTH")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::from("AUTH_SECRET_ENCODING"))?;
    let secret = text.strip_suffix('\n').unwrap_or(text);
    if secret.len() != 64 || secret.contains(char::is_whitespace) {
        return Err("AUTH_SECRET_LENGTH".into());
    }
    ingress::DevelopmentIdentity::from_secret_hex(secret)
}

fn peer_roster(path: &str) -> Result<Vec<String>> {
    let bytes = read_owned_configuration(
        path,
        16_384,
        false,
        "AUTH_ROSTER_FILE",
        "AUTH_ROSTER_LENGTH",
    )?;
    let peers: Vec<String> = serde_json::from_slice(&bytes)?;
    let unique: BTreeSet<_> = peers.iter().cloned().collect();
    if peers.is_empty() || peers.len() > 64 || unique.len() != peers.len() {
        return Err("AUTH_ROSTER".into());
    }
    Ok(peers)
}

fn session_generation(args: &BTreeMap<String, String>) -> Result<u64> {
    let generation: u64 = need(args, "--session-generation")?
        .parse()
        .map_err(|_| Error::from("AUTH_GENERATION"))?;
    if generation == 0 || generation > i64::MAX as u64 {
        return Err("AUTH_GENERATION".into());
    }
    Ok(generation)
}

fn authenticated_client(
    args: &BTreeMap<String, String>,
) -> Result<Option<ingress::AuthenticatedClient>> {
    let present = [
        args.contains_key("--auth-secret"),
        args.contains_key("--server-public"),
        args.contains_key("--session-generation"),
    ];
    if present.iter().all(|value| !value) {
        return Ok(None);
    }
    if !present.iter().all(|value| *value) {
        return Err("AUTH_CLIENT_OPTIONS".into());
    }
    Ok(Some(ingress::AuthenticatedClient::new(
        secret_identity(need(args, "--auth-secret")?)?,
        need(args, "--server-public")?.to_owned(),
        session_generation(args)?,
    )?))
}

fn authenticated_server(
    args: &BTreeMap<String, String>,
) -> Result<Option<ingress::AuthenticatedServer>> {
    let present = [
        args.contains_key("--auth-secret"),
        args.contains_key("--peer-roster"),
        args.contains_key("--session-generation"),
    ];
    if present.iter().all(|value| !value) {
        return Ok(None);
    }
    if !present.iter().all(|value| *value)
        || args
            .get("--authenticated-development-network")
            .map(String::as_str)
            != Some("true")
    {
        return Err("AUTH_SERVER_OPTIONS".into());
    }
    Ok(Some(ingress::AuthenticatedServer::new(
        secret_identity(need(args, "--auth-secret")?)?,
        peer_roster(need(args, "--peer-roster")?)?,
        session_generation(args)?,
    )?))
}

fn admission_profile(args: &BTreeMap<String, String>) -> Result<bool> {
    match args.get("--admission-profile").map(String::as_str) {
        None | Some("legacy-development") => Ok(false),
        Some("connection-work-v1") => Ok(true),
        _ => Err("ADMISSION_PROFILE".into()),
    }
}

fn output(path: &str, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(
        Path::new(path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}
fn run() -> Result<Value> {
    let mut raw = std::env::args().skip(1);
    let command = raw
        .next()
        .ok_or("command: status|mine|submit|export|confirm|sync|serve|push")?;
    let mut args = BTreeMap::new();
    while let Some(key) = raw.next() {
        let value = if matches!(
            key.as_str(),
            "--development" | "--authenticated-development-network" | "--task-bootstrap"
        ) {
            "true".into()
        } else {
            raw.next().ok_or("missing argument value")?
        };
        if args.insert(key, value).is_some() {
            return Err("DUPLICATE_OPTION".into());
        }
    }
    if args.get("--development").map(String::as_str) != Some("true") {
        return Err(
            "EXPLICIT_DEVELOPMENT_REQUIRED: public test identities; no monetary value".into(),
        );
    }
    let extra = match command.as_str() {
        "status" | "recover" => "",
        "mine" | "make" => "--transactions --timestamp --output --parent --miner --task-bootstrap --task-manifest --task-model --task-input",
        "task-fixture" => "--task-model --task-input --demand-index --purpose --not-before --expires --demand-nonce --output",
        "submit" | "push" => "--packet --peer",
        "export" => "--block --output",
        "confirm" => "--transaction --block",
        "confirm-batch" => "--queries",
        "sync" => "--peer --tip --after --pages",
        "serve" => "--listen --seconds",
        _ => return Err("UNKNOWN_COMMAND".into()),
    };
    let authentication_options = match command.as_str() {
        "serve" => {
            "--authenticated-development-network --auth-secret --peer-roster --session-generation"
        }
        "push" | "sync" => "--auth-secret --server-public --session-generation",
        _ => "",
    };
    let admission_options = match command.as_str() {
        "serve" => "--admission-profile --admission-bits --admission-ttl-ms",
        "push" => "--admission-profile",
        _ => "",
    };
    let allowed = format!(
        "--development --store --genesis-time --workers --logical-now --evaluation-policy --task-profile --model-profile {authentication_options} {admission_options} {extra}"
    );
    for key in args.keys() {
        if !allowed.split_whitespace().any(|k| k == key) {
            return Err(format!("UNKNOWN_OPTION:{key}").into());
        }
    }
    if matches!(command.as_str(), "serve" | "sync" | "push") && args.contains_key("--logical-now") {
        return Err("NETWORK_USES_LOCAL_WALL_CLOCK".into());
    }
    let evaluation_policy = args
        .get("--evaluation-policy")
        .map(String::as_str)
        .unwrap_or("legacy-first-two-v3");
    if !matches!(
        evaluation_policy,
        "legacy-first-two-v3"
            | "closed-round-all-eligible-min-v1"
            | "native-public-evaluation-dev-v1"
    ) {
        return Err("EVALUATION_POLICY".into());
    }
    let settings = Settings::development_with_model_profiles(
        args.get("--genesis-time")
            .map(|s| s.parse().map_err(|_| Error::from("GENESIS_TIME")))
            .transpose()?,
        evaluation_policy,
        args.get("--task-profile")
            .map(String::as_str)
            .unwrap_or("legacy-task-v1"),
        args.get("--model-profile")
            .map(String::as_str)
            .unwrap_or("linear-expert-dev-v1"),
    )?;
    if command == "task-fixture" {
        if settings.task_profile() != "signed-task-dev-v1" {
            return Err("SIGNED_TASK_PROFILE_REQUIRED".into());
        }
        let model = read(need(&args, "--task-model")?, 16384)?;
        let input = read(need(&args, "--task-input")?, 16384)?;
        let purpose = match need(&args, "--purpose")? {
            "maintenance" => TaskPurpose::Maintenance,
            "adapter" => TaskPurpose::AdapterContraction,
            "evaluation" => TaskPurpose::EvaluationContraction,
            "inference" => TaskPurpose::InferenceContraction,
            _ => return Err("TASK_PURPOSE".into()),
        };
        let signed = settings.development_task_manifest(
            number(&args, "--demand-index", 0)?,
            purpose,
            &model,
            &input,
            number(&args, "--not-before", 1)?,
            number(&args, "--expires", 1000)?,
            number(&args, "--demand-nonce", 1)?,
        )?;
        let wire = signed
            .encode()
            .map_err(|e| Error::from(format!("TASK_MANIFEST:{e:?}")))?;
        output(need(&args, "--output")?, &wire)?;
        return Ok(
            json!({"scope":"public-key development fixture; no real-world demand or consent certificate","signed_manifest":need(&args,"--output")?,"matrix_task":hex::encode(signed.manifest.matrix_task),"production_activation":false}),
        );
    }
    if command == "push" {
        let protected = admission_profile(&args)?;
        let packet = Packet::decode(&read(need(&args, "--packet")?, 1_048_576)?)?;
        let address = need(&args, "--peer")?
            .parse()
            .map_err(|_| Error::from("PEER_ADDRESS"))?;
        let request = ingress::Request::Submit {
            packet: hex::encode(packet.encode()?),
        };
        if let Some(authentication) = authenticated_client(&args)? {
            let mut owner = Node::open(
                Path::new(need(&args, "--store")?),
                settings.clone(),
                number(&args, "--workers", 1)? as usize,
            )?;
            let response = if protected {
                ingress::call_authenticated_durable_protected(
                    &mut owner,
                    address,
                    &request,
                    &authentication,
                )?
            } else {
                ingress::call_authenticated_durable(&mut owner, address, &request, &authentication)?
            };
            return Ok(json!({
                "response":response,
                "state":owner.stats()?,
                "production_activation":false
            }));
        }
        return if protected {
            ingress::call_protected(address, &request, &settings)
        } else {
            ingress::call(address, &request)
        };
    }
    let clock = number(&args, "--logical-now", ingress::now()?)?;
    let mut node = Node::open(
        Path::new(need(&args, "--store")?),
        settings,
        number(&args, "--workers", 1)? as usize,
    )?;
    let value = match command.as_str() {
        "status" | "recover" => node.stats()?,
        "submit" => {
            let packet = Packet::decode(&read(need(&args, "--packet")?, 1_048_576)?)?;
            let id = node.admit(&packet, clock)?;
            node.activate_observed(id, clock)?;
            json!({"block":hex::encode(id),"state":node.stats()?})
        }
        "mine" | "make" => {
            let transactions = if let Some(path) = args.get("--transactions") {
                let text: Vec<String> = serde_json::from_slice(&read(path, 2_097_152)?)?;
                if text.len() > 256 {
                    return Err("TRANSACTION_LIMIT".into());
                }
                text.iter()
                    .map(|s| hex::decode(s).map_err(|_| Error::from("TRANSACTION_HEX")))
                    .collect::<Result<Vec<_>>>()?
            } else {
                Vec::new()
            };
            let timestamp = number(&args, "--timestamp", clock)?;
            let packet = {
                let parent = args
                    .get("--parent")
                    .map(|s| digest(s))
                    .transpose()?
                    .unwrap_or(node.active()?.0);
                let miner = args
                    .get("--miner")
                    .map(|s| digest(s))
                    .transpose()?
                    .unwrap_or(development_public(0)?);
                let files_present = ["--task-manifest", "--task-model", "--task-input"]
                    .map(|key| args.contains_key(key));
                let bootstrap = args.contains_key("--task-bootstrap");
                if matches!(
                    node.settings().task_profile(),
                    "signed-task-dev-v1" | "signed-task-lifecycle-dev-v2"
                ) {
                    if bootstrap && files_present.iter().any(|present| *present) {
                        return Err("TASK_OPTIONS".into());
                    }
                    let (wire, model, input) = if bootstrap {
                        let wire =
                            if node.settings().task_profile() == "signed-task-lifecycle-dev-v2" {
                                node.settings()
                                    .bootstrap_lifecycle_task()?
                                    .signed
                                    .encode()
                                    .map_err(|e| Error::from(format!("TASK_MANIFEST:{e:?}")))?
                            } else {
                                node.settings()
                                    .bootstrap_task_statement()?
                                    .encode()
                                    .map_err(|e| Error::from(format!("TASK_MANIFEST:{e:?}")))?
                            };
                        let (a, b) = trnm_pon_node::maintenance();
                        (
                            wire,
                            a.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>(),
                            b.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>(),
                        )
                    } else {
                        if !files_present.iter().all(|present| *present) {
                            return Err("TASK_MATERIAL_REQUIRED".into());
                        }
                        (
                            read(need(&args, "--task-manifest")?, 684)?,
                            read(need(&args, "--task-model")?, 16384)?,
                            read(need(&args, "--task-input")?, 16384)?,
                        )
                    };
                    let lifecycle =
                        node.settings().task_profile() == "signed-task-lifecycle-dev-v2";
                    let manifest = if lifecycle {
                        trnm_protocol::qualified_work_task::lifecycle_v2::SignedLifecycleTaskV2::decode(&wire).map_err(|e|Error::from(format!("TASK_MANIFEST:{e:?}")))?.manifest
                    } else {
                        SignedQualifiedWorkTask::decode(&wire)
                            .map_err(|e| Error::from(format!("TASK_MANIFEST:{e:?}")))?
                            .manifest
                    };
                    let (a, b) = derive_matrices(&model, &input)
                        .map_err(|e| Error::from(format!("TASK_MATERIAL:{e:?}")))?;
                    let height = node.parent_height(parent)?.checked_add(1).ok_or("HEIGHT")?;
                    let material = TaskMaterial {
                        model: &model,
                        input: &input,
                        a: &a,
                        b: &b,
                    };
                    let verification_material = TaskMaterial {
                        model: &model,
                        input: &input,
                        a: &a,
                        b: &b,
                    };
                    let admitted = if lifecycle {
                        let lease =
                            node.lifecycle_task_lease(parent, manifest.matrix_task, height)?;
                        trnm_crypto_primitives::qualified_work_task::lifecycle_v2::verify_lifecycle_admission(&wire,verification_material,&lease,height).map_err(|e|Error::from(format!("TASK_ADMISSION:{e:?}")))?
                    } else {
                        let context = node
                            .settings()
                            .qualified_task_context(manifest.demand_id, height)?;
                        verify_development_admission(&wire, verification_material, &context)
                            .map_err(|e| Error::from(format!("TASK_ADMISSION:{e:?}")))?
                    };
                    node.make_with_task(
                        parent,
                        transactions,
                        miner,
                        timestamp,
                        4096,
                        &admitted,
                        material,
                    )?
                } else {
                    if bootstrap || files_present.iter().any(|present| *present) {
                        return Err("SIGNED_TASK_PROFILE_REQUIRED".into());
                    }
                    node.make(parent, transactions, miner, timestamp, 4096)?
                }
            };
            output(need(&args, "--output")?, &packet.encode()?)?;
            if command == "mine" {
                let id = node.admit(&packet, clock)?;
                node.activate_observed(id, clock)?;
            }
            json!({"block":hex::encode(packet.id()?),"attempts":packet.header.nonce+1,"admitted":command=="mine","state":node.stats()?})
        }
        "export" => {
            let packet = node.packet(digest(need(&args, "--block")?)?)?;
            output(need(&args, "--output")?, &packet.encode()?)?;
            json!({"block":hex::encode(packet.id()?)})
        }
        "confirm" => serde_json::to_value(node.confirmation(
            digest(need(&args, "--transaction")?)?,
            digest(need(&args, "--block")?)?,
            clock,
        )?)?,
        "confirm-batch" => {
            let queries: Vec<ingress::ConfirmationQuery> =
                serde_json::from_slice(&read(need(&args, "--queries")?, 65_536)?)?;
            serde_json::to_value(
                node.confirmations(&ingress::confirmation_queries(&queries)?, clock)?,
            )?
        }
        "sync" => {
            let address = need(&args, "--peer")?
                .parse()
                .map_err(|_| Error::from("PEER_ADDRESS"))?;
            let tip = digest(need(&args, "--tip")?)?;
            let after = args
                .get("--after")
                .map(|s| digest(s))
                .transpose()?
                .unwrap_or(node.settings().genesis());
            if let Some(authentication) = authenticated_client(&args)? {
                let verified = ingress::sync_from_authenticated_durable(
                    &mut node,
                    address,
                    tip,
                    after,
                    number(&args, "--pages", 256)? as usize,
                    &authentication,
                )?;
                json!({"verified_tip":hex::encode(verified),"state":node.stats()?})
            } else {
                let verified = ingress::sync_from(
                    &mut node,
                    address,
                    tip,
                    after,
                    number(&args, "--pages", 256)? as usize,
                )?;
                json!({"verified_tip":hex::encode(verified),"state":node.stats()?})
            }
        }
        "serve" => {
            let protected = admission_profile(&args)?;
            if !protected
                && (args.contains_key("--admission-bits")
                    || args.contains_key("--admission-ttl-ms"))
            {
                return Err("ADMISSION_PROFILE_REQUIRED".into());
            }
            let admission = if protected {
                Some(ingress::AdmissionPolicy::new(
                    u8::try_from(number(&args, "--admission-bits", 16)?)
                        .map_err(|_| Error::from("ADMISSION_POLICY"))?,
                    Duration::from_millis(number(&args, "--admission-ttl-ms", 2000)?),
                )?)
            } else {
                None
            };
            let address = args
                .get("--listen")
                .map(String::as_str)
                .unwrap_or("127.0.0.1:0");
            let address: std::net::SocketAddr =
                address.parse().map_err(|_| Error::from("LISTEN_ADDRESS"))?;
            let authentication = authenticated_server(&args)?;
            if authentication.is_none() && !address.ip().is_loopback() {
                return Err("DEVELOPMENT_LOOPBACK_ONLY".into());
            }
            let listener = std::net::TcpListener::bind(address)?;
            let server_public = authentication
                .as_ref()
                .map(|value| value.public_key().to_owned());
            println!(
                "{}",
                json!({
                    "event":"listening",
                    "address":listener.local_addr()?.to_string(),
                    "state":node.stats()?,
                    "scope":if authentication.is_some(){"authenticated-development-private"}else{"native-development-loopback"},
                    "server_public":server_public,
                    "admission_profile":if protected {"connection-work-v1"} else {"legacy-development"},
                    "confidentiality":false,
                    "production_activation":false
                })
            );
            std::io::stdout().flush()?;
            let lifetime = Duration::from_secs(number(&args, "--seconds", 30)?);
            let stop = Arc::new(AtomicBool::new(false));
            let metrics = match (authentication, admission) {
                (Some(authentication), Some(policy)) => ingress::serve_authenticated_protected(
                    listener,
                    node,
                    lifetime,
                    stop,
                    authentication,
                    policy,
                )?,
                (None, Some(policy)) => {
                    ingress::serve_protected(listener, node, lifetime, stop, policy)?
                }
                (Some(authentication), None) => {
                    ingress::serve_authenticated(listener, node, lifetime, stop, authentication)?
                }
                (None, None) => ingress::serve(listener, node, lifetime, stop)?,
            };
            serde_json::to_value(metrics)?
        }
        _ => return Err("UNKNOWN_COMMAND".into()),
    };
    Ok(
        json!({"result":value,"clock_scope":if args.contains_key("--logical-now"){"logical-test"}else{"local-wall"},"production_activation":false}),
    )
}
fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn test_authentication_configuration_uses_the_opened_file_identity() {
        let temp = tempfile::tempdir().unwrap();
        let key = temp.path().join("peer.key");
        let seed = "11".repeat(32);
        std::fs::write(&key, format!("{seed}\n")).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(secret_identity(key.to_str().unwrap()).is_ok());

        let link = temp.path().join("peer-link.key");
        symlink(&key, &link).unwrap();
        assert_eq!(
            secret_identity(link.to_str().unwrap())
                .err()
                .unwrap()
                .to_string(),
            "AUTH_SECRET_FILE"
        );

        let public = temp.path().join("public.key");
        std::fs::write(&public, format!("{seed}\n")).unwrap();
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            secret_identity(public.to_str().unwrap())
                .err()
                .unwrap()
                .to_string(),
            "AUTH_SECRET_FILE"
        );

        let hard = temp.path().join("hard.key");
        std::fs::hard_link(&key, &hard).unwrap();
        assert_eq!(
            secret_identity(hard.to_str().unwrap())
                .err()
                .unwrap()
                .to_string(),
            "AUTH_SECRET_FILE"
        );

        let roster = temp.path().join("peers.json");
        let peer = ingress::DevelopmentIdentity::from_secret_hex(&"22".repeat(32)).unwrap();
        std::fs::write(
            &roster,
            serde_json::to_vec(&vec![peer.public_key().to_owned()]).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&roster, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(peer_roster(roster.to_str().unwrap()).unwrap().len(), 1);
        let writable_roster = temp.path().join("writable-peers.json");
        std::fs::write(
            &writable_roster,
            serde_json::to_vec(&vec![peer.public_key().to_owned()]).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&writable_roster, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            peer_roster(writable_roster.to_str().unwrap())
                .unwrap_err()
                .to_string(),
            "AUTH_ROSTER_FILE"
        );
        let roster_link = temp.path().join("peers-link.json");
        symlink(&roster, &roster_link).unwrap();
        assert_eq!(
            peer_roster(roster_link.to_str().unwrap())
                .unwrap_err()
                .to_string(),
            "AUTH_ROSTER_FILE"
        );
    }
}
