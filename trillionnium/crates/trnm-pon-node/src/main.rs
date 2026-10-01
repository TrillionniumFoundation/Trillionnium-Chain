//! Ordinary native development entrypoint. Signed transactions remain external inputs.
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use trnm_crypto_primitives::qualified_work_task::{
    derive_matrices, verify_development_admission, TaskMaterial,
};
use trnm_pon_node::{development_public, digest, ingress, Error, Node, Packet, Result, Settings};
use trnm_pon_node::{
    mining::{run_pool_mining, MiningConfig, MiningMaterial},
    peer_polling::{run_pinned_peer_polling, PeerPollingConfig},
    PoolLimits,
};
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
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
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
fn public_profile(args: &BTreeMap<String, String>) -> bool {
    matches!(
        args.get("--admission-profile").map(String::as_str),
        Some(ingress::public_v2::PROFILE | ingress::public_v3::PROFILE)
    )
}
fn public_pool_profile(args: &BTreeMap<String, String>) -> bool {
    args.get("--admission-profile").map(String::as_str) == Some(ingress::public_v3::PROFILE)
}
fn public_policy(args: &BTreeMap<String, String>) -> Result<ingress::public_v2::PublicPolicy> {
    ingress::public_v2::PublicPolicy::new(
        u8::try_from(number(args, "--admission-bits", 16)?)
            .map_err(|_| Error::from("PUBLIC_POLICY"))?,
        Duration::from_millis(number(args, "--admission-ttl-ms", 2000)?),
    )
}
fn public_identity(args: &BTreeMap<String, String>) -> Result<ingress::DevelopmentIdentity> {
    if args.contains_key("--peer-roster")
        || args.contains_key("--session-generation")
        || args.contains_key("--authenticated-development-network")
    {
        return Err("PUBLIC_IDENTITY_OPTIONS".into());
    }
    secret_identity(need(args, "--auth-secret")?)
}
fn public_call(
    args: &BTreeMap<String, String>,
    request: &ingress::Request,
    settings: &Settings,
) -> Result<ingress::public_v2::PublicReply> {
    if public_pool_profile(args) {
        let request = match request {
            ingress::Request::Submit { packet } => ingress::public_v3::Request::Submit {
                packet: packet.clone(),
            },
            ingress::Request::Head => ingress::public_v3::Request::Head,
            ingress::Request::History { tip, after } => ingress::public_v3::Request::History {
                tip: tip.clone(),
                after: after.clone(),
            },
            _ => return Err("PUBLIC_OPERATION".into()),
        };
        let reply = public_pool_call(args, &request, settings)?;
        return Ok(ingress::public_v2::PublicReply {
            ok: reply.ok,
            value: reply.value,
            solve_trials: reply.solve_trials,
            solve_elapsed_ns: reply.solve_elapsed_ns,
            body_bytes_sent: reply.body_bytes_sent,
            public_network_ready: reply.public_network_ready,
            identity_authority: reply.identity_authority,
        });
    }
    ingress::public_v2::call_public_protected_v2(
        need(args, "--peer")?
            .parse()
            .map_err(|_| Error::from("PEER_ADDRESS"))?,
        request,
        settings,
        need(args, "--server-public")?,
        &public_identity(args)?,
        public_policy(args)?,
    )
}

fn public_pool_call(
    args: &BTreeMap<String, String>,
    request: &ingress::public_v3::Request,
    settings: &Settings,
) -> Result<ingress::public_v3::PublicReply> {
    if !public_pool_profile(args) {
        return Err("PUBLIC_V3_REQUIRED".into());
    }
    let (reply, observations) = ingress::public_v3::call_public_protected_v3_with_metrics(
        need(args, "--peer")?.parse().map_err(|_| "PEER_ADDRESS")?,
        request,
        settings,
        need(args, "--server-public")?,
        &public_identity(args)?,
        ingress::public_v3::PublicPolicy::new(
            u8::try_from(number(args, "--admission-bits", 16)?).map_err(|_| "PUBLIC_POLICY")?,
            Duration::from_millis(number(args, "--admission-ttl-ms", 2000)?),
        )?,
    );
    if args.contains_key("--client-observations") {
        eprintln!(
            "{}",
            json!({"schema":"public-v3-cli-client-observation-v1","observations":observations,
            "scope":"local elapsed stage time including failed calls; not server CPU or cost authority",
            "public_network_ready":false})
        );
    }
    reply
}
fn pool_policy(args: &BTreeMap<String, String>) -> Result<PoolLimits> {
    Ok(serde_json::from_slice(&read_owned_configuration(
        need(args, "--pool-policy")?,
        4096,
        false,
        "POOL_POLICY_FILE",
        "POOL_POLICY_LENGTH",
    )?)?)
}
fn mining_configuration(
    args: &BTreeMap<String, String>,
    settings: &Settings,
    policy: &PoolLimits,
    default_seconds: u64,
) -> Result<MiningConfig> {
    let miner = args
        .get("--miner")
        .map(|s| digest(s))
        .transpose()?
        .unwrap_or(policy.preview_miner);
    if miner != policy.preview_miner {
        return Err("POOL_MINER".into());
    }
    let bootstrap = args.contains_key("--task-bootstrap");
    let files = ["--task-model", "--task-input"].map(|key| args.contains_key(key));
    let material = if settings.task_profile() != "legacy-task-v1" {
        if bootstrap && files.iter().any(|p| *p) {
            return Err("TASK_OPTIONS".into());
        }
        let (model, input) = if bootstrap {
            let (model, input, _, _) = settings.bootstrap_task_material()?;
            (model, input)
        } else {
            if !files.iter().all(|p| *p) {
                return Err("TASK_MATERIAL_REQUIRED".into());
            }
            (
                read(need(args, "--task-model")?, 16384)?,
                read(need(args, "--task-input")?, 16384)?,
            )
        };
        MiningMaterial::Registered { model, input }
    } else {
        if bootstrap || files.iter().any(|p| *p) {
            return Err("SIGNED_TASK_PROFILE_REQUIRED".into());
        }
        MiningMaterial::LegacyDevelopment
    };
    let config = MiningConfig {
        miner,
        material,
        max_transactions: number(args, "--max-transactions", 256)?
            .try_into()
            .map_err(|_| "MINING_LIMITS")?,
        max_transaction_bytes: number(args, "--max-transaction-bytes", 524288)?
            .try_into()
            .map_err(|_| "MINING_LIMITS")?,
        search_attempts: number(args, "--search-attempts", 4096)?,
        pace: Duration::from_millis(number(args, "--pace-ms", 10000)?),
        runtime: Duration::from_secs(number(
            args,
            "--mining-seconds",
            number(args, "--seconds", default_seconds)?,
        )?),
        max_blocks: number(args, "--blocks", 100000)?,
    };
    config.validate()?;
    Ok(config)
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
fn operator_inputs(
    args: &BTreeMap<String, String>,
) -> Result<(
    trnm_pon_node::operator_deployment::OperatorDeploymentSpec,
    Vec<u8>,
    Vec<u8>,
)> {
    use trnm_pon_node::operator_deployment::{self as actors, offline};
    if need(args, "--actor-profile")? != actors::PROFILE {
        return Err("ACTOR_PROFILE".into());
    }
    let spec = actors::OperatorDeploymentSpec::decode(&offline::read_public(
        Path::new(need(args, "--deployment-spec")?),
        actors::SPEC_BYTES as u64,
    )?)?;
    let model = offline::read_public(Path::new(need(args, "--deployment-model")?), 16384)?;
    let input = offline::read_public(Path::new(need(args, "--deployment-input")?), 16384)?;
    Ok((spec, model, input))
}
fn operator_command(command: &str, args: &BTreeMap<String, String>) -> Result<Value> {
    use trnm_pon_node::operator_deployment::{self as actors, offline};
    let (spec, model, input) = operator_inputs(args)?;
    let expected = actors::prepare(&spec, &model, &input)?;
    let value = match command {
        "genesis-prepare" => serde_json::to_value(expected)?,
        "genesis-sign" => {
            let template: actors::BootstrapTemplate = actors::decode(&offline::read_public(
                Path::new(need(args, "--deployment-template")?),
                actors::BOOTSTRAP_BYTES as u64,
            )?)?;
            serde_json::to_value(offline::sign_approval_from_file(
                &spec,
                &template,
                &model,
                &input,
                need(args, "--role")?,
                Path::new(need(args, "--signer-secret")?),
            )?)?
        }
        "genesis-finalize" => {
            let template: actors::BootstrapTemplate = actors::decode(&offline::read_public(
                Path::new(need(args, "--deployment-template")?),
                actors::BOOTSTRAP_BYTES as u64,
            )?)?;
            if template != expected {
                return Err("ACTOR_TEMPLATE".into());
            }
            let source = actors::decode(&offline::read_public(
                Path::new(need(args, "--source-approval")?),
                actors::BOOTSTRAP_BYTES as u64,
            )?)?;
            let requester = actors::decode(&offline::read_public(
                Path::new(need(args, "--requester-approval")?),
                actors::BOOTSTRAP_BYTES as u64,
            )?)?;
            let bundle = actors::assemble(&expected, &source, &requester)?;
            // Finalization independently constructs the full public state; a forged
            // template or merely well-shaped approval cannot produce a genesis.
            Settings::development_with_operator_actors(&spec, &bundle, &model, &input)?;
            serde_json::to_value(bundle)?
        }
        _ => return Err("UNKNOWN_COMMAND".into()),
    };
    if let Some(path) = args.get("--output") {
        offline::write_new_public(Path::new(path), &actors::canonical(&value)?)?;
    }
    Ok(value)
}
fn run() -> Result<Value> {
    let mut raw = std::env::args().skip(1);
    let command = raw
        .next()
        .ok_or("command: status|mine|submit|export|confirm|sync|serve|push|head|history")?;
    let mut args = BTreeMap::new();
    while let Some(key) = raw.next() {
        let value = if matches!(
            key.as_str(),
            "--development"
                | "--authenticated-development-network"
                | "--public-development-network"
                | "--task-bootstrap"
                | "--mine"
                | "--client-observations"
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
        "genesis-prepare" => "--output",
        "genesis-sign" => "--deployment-template --role --signer-secret --output",
        "genesis-finalize" => "--deployment-template --source-approval --requester-approval --output",
        "status" | "recover" | "pool-status" => "",
        "evaluation-observe" => "--candidate --ancestry-blocks",
        "evaluation-round-observe" => "--candidate --round-blocks",
        "pool-submit" => "--transactions --pool-policy",
        "pool-push" => "--peer --transactions --pool-context",
        "pool-status-remote" => "--peer",
        "mine-loop" => "--miner --pool-policy --seconds --blocks --pace-ms --search-attempts --max-transactions --max-transaction-bytes --task-bootstrap --task-model --task-input",
        "mine" | "make" => "--transactions --timestamp --output --parent --miner --task-bootstrap --task-manifest --task-model --task-input",
        "task-fixture" => "--task-model --task-input --demand-index --purpose --not-before --expires --demand-nonce --output",
        "submit" | "push" => "--packet --peer",
        "export" => "--block --output",
        "confirm" => "--transaction --block",
        "confirm-batch" => "--queries",
        "sync" => "--peer --tip --after --pages --evaluation-candidate --evaluation-round-blocks",
        "head" => "--peer",
        "history" => "--peer --tip --after",
        "serve" => "--listen --seconds --mining-seconds --pool-policy --mine --miner --blocks --pace-ms --search-attempts --max-transactions --max-transaction-bytes --task-bootstrap --task-model --task-input --peers --peer-poll-ms --peer-pages",
        _ => return Err("UNKNOWN_COMMAND".into()),
    };
    let authentication_options = match command.as_str() {
        "serve" => {
            "--authenticated-development-network --public-development-network --auth-secret --peer-roster --session-generation"
        }
        "push" | "sync" => "--auth-secret --server-public --session-generation",
        "head" | "history" | "pool-push" | "pool-status-remote" => "--auth-secret --server-public",
        _ => "",
    };
    let admission_options = match command.as_str() {
        "serve" => "--admission-profile --admission-bits --admission-ttl-ms",
        "push" | "sync" | "head" | "history" | "pool-push" | "pool-status-remote" => {
            "--admission-profile --admission-bits --admission-ttl-ms --client-observations"
        }
        _ => "",
    };
    let allowed = format!(
        "--development --store --genesis-time --workers --logical-now --evaluation-policy --task-profile --model-profile --actor-profile --deployment-spec --deployment-bootstrap --deployment-model --deployment-input {authentication_options} {admission_options} {extra}"
    );
    for key in args.keys() {
        if !allowed.split_whitespace().any(|k| k == key) {
            return Err(format!("UNKNOWN_OPTION:{key}").into());
        }
    }
    // Local evaluation query inputs reject before Node::open can create/recover a
    // store. Existing --logical-now is explicit trusted test input, never height.
    let evaluation_query = if command == "evaluation-observe" {
        let candidate = digest(need(&args, "--candidate")?)?;
        let bound = number(&args, "--ancestry-blocks", 4096)?;
        if !(1..=4096).contains(&bound) {
            return Err("EVALUATION_OBSERVATION_LIMIT".into());
        }
        Some((candidate, bound))
    } else {
        None
    };
    let evaluation_round_query = if command == "evaluation-round-observe" {
        let candidate = digest(need(&args, "--candidate")?)?;
        let bound = number(&args, "--round-blocks", 4096)?;
        if !(1..=4096).contains(&bound) {
            return Err("EVALUATION_OBSERVATION_LIMIT".into());
        }
        Some((candidate, bound))
    } else {
        None
    };
    let sync_evaluation_query = if command == "sync" {
        match args.get("--evaluation-candidate") {
            Some(candidate) => {
                let candidate = digest(candidate)?;
                let bound = number(&args, "--evaluation-round-blocks", 4096)?;
                if !(1..=4096).contains(&bound) {
                    return Err("EVALUATION_OBSERVATION_LIMIT".into());
                }
                if !public_profile(&args) {
                    return Err("EVALUATION_SYNC_PUBLIC_PROFILE".into());
                }
                Some((candidate, bound))
            }
            None => {
                if args.contains_key("--evaluation-round-blocks") {
                    return Err("EVALUATION_SYNC_CANDIDATE_REQUIRED".into());
                }
                None
            }
        }
    } else {
        None
    };
    if matches!(
        command.as_str(),
        "genesis-prepare" | "genesis-sign" | "genesis-finalize"
    ) {
        if args.keys().any(|key| {
            matches!(
                key.as_str(),
                "--store"
                    | "--genesis-time"
                    | "--workers"
                    | "--logical-now"
                    | "--evaluation-policy"
                    | "--task-profile"
                    | "--model-profile"
                    | "--deployment-bootstrap"
            )
        }) {
            return Err("ACTOR_PREPARATION_OPTIONS".into());
        }
        return operator_command(&command, &args);
    }
    if !public_profile(&args) {
        admission_profile(&args)?;
    }
    if args.contains_key("--client-observations") && !public_pool_profile(&args) {
        return Err("PUBLIC_V3_REQUIRED".into());
    }
    if matches!(
        command.as_str(),
        "serve"
            | "sync"
            | "push"
            | "head"
            | "history"
            | "mine-loop"
            | "pool-push"
            | "pool-status-remote"
    ) && args.contains_key("--logical-now")
    {
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
    let actor_options = [
        "--actor-profile",
        "--deployment-spec",
        "--deployment-bootstrap",
        "--deployment-model",
        "--deployment-input",
    ];
    let actor_present = actor_options.iter().any(|key| args.contains_key(*key));
    let settings = if actor_present {
        if !actor_options.iter().all(|key| args.contains_key(*key))
            || [
                "--genesis-time",
                "--evaluation-policy",
                "--task-profile",
                "--model-profile",
            ]
            .iter()
            .any(|key| args.contains_key(*key))
        {
            return Err("ACTOR_DEPLOYMENT_OPTIONS".into());
        }
        if command == "task-fixture" {
            return Err("ACTOR_EXPLICIT_SIGNATURE_REQUIRED".into());
        }
        if (matches!(command.as_str(), "mine" | "make" | "mine-loop")
            || command == "serve" && args.contains_key("--mine"))
            && !args.contains_key("--miner")
        {
            return Err("ACTOR_EXPLICIT_MINER_REQUIRED".into());
        }
        let (spec, model, input) = operator_inputs(&args)?;
        let bundle = trnm_pon_node::operator_deployment::decode(
            &trnm_pon_node::operator_deployment::offline::read_public(
                Path::new(need(&args, "--deployment-bootstrap")?),
                8192,
            )?,
        )?;
        Settings::development_with_operator_actors(&spec, &bundle, &model, &input)?
    } else {
        Settings::development_with_model_profiles(
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
        )?
    };
    if command == "serve" {
        let mining_options = [
            "--mining-seconds",
            "--miner",
            "--blocks",
            "--pace-ms",
            "--search-attempts",
            "--max-transactions",
            "--max-transaction-bytes",
            "--task-bootstrap",
            "--task-model",
            "--task-input",
        ];
        if !public_pool_profile(&args)
            && (args.contains_key("--pool-policy")
                || args.contains_key("--mine")
                || args.contains_key("--peers")
                || args.contains_key("--peer-poll-ms")
                || args.contains_key("--peer-pages")
                || mining_options.iter().any(|key| args.contains_key(*key)))
        {
            return Err("PUBLIC_V3_REQUIRED".into());
        }
        if !args.contains_key("--mine") && mining_options.iter().any(|key| args.contains_key(*key))
        {
            return Err("MINING_OPTIONS_REQUIRE_MINE".into());
        }
        if args.contains_key("--mining-seconds") {
            let mining_seconds = number(&args, "--mining-seconds", 30)?;
            let service_seconds = number(&args, "--seconds", 30)?;
            if !(1..=259200).contains(&mining_seconds) || mining_seconds > service_seconds {
                return Err("MINING_RUNTIME".into());
            }
        }
        if !args.contains_key("--peers")
            && (args.contains_key("--peer-poll-ms") || args.contains_key("--peer-pages"))
        {
            return Err("PEER_OPTIONS_REQUIRE_PEERS".into());
        }
    }
    // Validate the opened, bounded operator configuration before creating a store.
    // The context below binds effective overrides, rather than an unused file value.
    let polling = if command == "serve" && args.contains_key("--peers") {
        let raw = read_owned_configuration(
            need(&args, "--peers")?,
            16384,
            false,
            "PEER_CONFIG_FILE",
            "PEER_CONFIG_LIMIT",
        )?;
        let mut config: PeerPollingConfig = serde_json::from_slice(&raw)?;
        let service_ms = number(&args, "--seconds", 30)?
            .checked_mul(1000)
            .ok_or("PUBLIC_LIFETIME")?;
        config.runtime_ms = config.runtime_ms.min(service_ms);
        config.poll_interval_ms = number(&args, "--peer-poll-ms", config.poll_interval_ms)?;
        config.max_pages_per_cycle = usize::try_from(number(
            &args,
            "--peer-pages",
            config.max_pages_per_cycle as u64,
        )?)
        .map_err(|_| "PEER_CONFIG_LIMIT")?;
        config.validate(&settings)?;
        if config.bits
            != u8::try_from(number(&args, "--admission-bits", 16)?).map_err(|_| "PUBLIC_POLICY")?
            || config.lifetime_ms != number(&args, "--admission-ttl-ms", 2000)?
        {
            return Err("PEER_CONFIG_CONTEXT".into());
        }
        Some(config)
    } else {
        None
    };
    if matches!(command.as_str(), "pool-push" | "pool-status-remote") {
        let request = if command == "pool-status-remote" {
            ingress::public_v3::Request::PoolStatus
        } else {
            ingress::public_v3::Request::PoolSubmitBundle {
                pool_context: need(&args, "--pool-context")?.to_owned(),
                transactions: serde_json::from_slice(&read(
                    need(&args, "--transactions")?,
                    65536,
                )?)?,
            }
        };
        return Ok(serde_json::to_value(public_pool_call(
            &args, &request, &settings,
        )?)?);
    }
    if !public_profile(&args)
        && (args.contains_key("--public-development-network")
            || (command != "serve"
                && (args.contains_key("--admission-bits")
                    || args.contains_key("--admission-ttl-ms"))))
    {
        return Err("PUBLIC_PROFILE_REQUIRED".into());
    }
    if matches!(command.as_str(), "head" | "history") {
        if !public_profile(&args) {
            return Err("PUBLIC_PROFILE_REQUIRED".into());
        }
        let request = if command == "head" {
            ingress::Request::Head
        } else {
            ingress::Request::History {
                tip: need(&args, "--tip")?.into(),
                after: args
                    .get("--after")
                    .cloned()
                    .unwrap_or(hex::encode(settings.genesis())),
            }
        };
        return Ok(serde_json::to_value(public_call(
            &args, &request, &settings,
        )?)?);
    }
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
        let packet = Packet::decode(&read(need(&args, "--packet")?, 1_048_576)?)?;
        let address = need(&args, "--peer")?
            .parse()
            .map_err(|_| Error::from("PEER_ADDRESS"))?;
        let request = ingress::Request::Submit {
            packet: hex::encode(packet.encode()?),
        };
        if public_profile(&args) {
            return Ok(serde_json::to_value(public_call(
                &args, &request, &settings,
            )?)?);
        }
        let protected = admission_profile(&args)?;
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
        "evaluation-observe" => {
            let (candidate, bound) = evaluation_query.ok_or("EVALUATION_OBSERVATION_LIMIT")?;
            serde_json::to_value(node.evaluation_observation(candidate, clock, bound)?)?
        }
        "evaluation-round-observe" => {
            let (candidate, bound) =
                evaluation_round_query.ok_or("EVALUATION_OBSERVATION_LIMIT")?;
            serde_json::to_value(node.evaluation_round_observation(candidate, clock, bound)?)?
        }
        "pool-status" => serde_json::to_value(node.pool_status()?)?,
        "pool-submit" => {
            let policy: PoolLimits = serde_json::from_slice(&read_owned_configuration(
                need(&args, "--pool-policy")?,
                4096,
                false,
                "POOL_POLICY_FILE",
                "POOL_POLICY_LENGTH",
            )?)?;
            node.enable_local_mempool(policy)?;
            let hexes: Vec<String> =
                serde_json::from_slice(&read(need(&args, "--transactions")?, 65536)?)?;
            if !(1..=16).contains(&hexes.len()) {
                return Err("POOL_GROUP_LIMIT".into());
            }
            let raws = hexes
                .iter()
                .map(|s| {
                    if !(318..=4096).contains(&s.len()) {
                        return Err("TRANSACTION_LIMIT".into());
                    }
                    let raw = hex::decode(s).map_err(|_| Error::from("TRANSACTION_HEX"))?;
                    if hex::encode(&raw) != *s {
                        return Err("TRANSACTION_HEX".into());
                    }
                    Ok(raw)
                })
                .collect::<Result<Vec<_>>>()?;
            serde_json::to_value(node.pool_submit_bundle(raws)?)?
        }
        "mine-loop" => {
            let policy = pool_policy(&args)?;
            let config = mining_configuration(&args, node.settings(), &policy, 60)?;
            node.enable_local_mempool(policy)?;
            let report = run_pool_mining(
                Arc::new(Mutex::new(node)),
                config,
                Arc::new(AtomicBool::new(false)),
                |event| {
                    println!("{}", serde_json::to_string(event)?);
                    std::io::stdout().flush()?;
                    Ok(())
                },
            )?;
            return Ok(
                json!({"result":report,"clock_scope":"local-wall","public_network_ready":false,"production_activation":false}),
            );
        }
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
                    "signed-task-dev-v1"
                        | "signed-task-lifecycle-dev-v2"
                        | "signed-task-lifecycle-dev-v3"
                        | "signed-task-lifecycle-dev-v4"
                ) {
                    if bootstrap && files_present.iter().any(|present| *present) {
                        return Err("TASK_OPTIONS".into());
                    }
                    let (wire, model, input) = if bootstrap {
                        let wire = if matches!(
                            node.settings().task_profile(),
                            "signed-task-lifecycle-dev-v2"
                                | "signed-task-lifecycle-dev-v3"
                                | "signed-task-lifecycle-dev-v4"
                        ) {
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
                        let (model, input, _, _) = node.settings().bootstrap_task_material()?;
                        (wire, model, input)
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
                    let lifecycle = matches!(
                        node.settings().task_profile(),
                        "signed-task-lifecycle-dev-v2"
                            | "signed-task-lifecycle-dev-v3"
                            | "signed-task-lifecycle-dev-v4"
                    );
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
            if public_profile(&args) {
                let pages = number(&args, "--pages", 256)?;
                if !(1..=4096).contains(&pages) {
                    return Err("SYNC_BUDGET".into());
                }
                let mut cursor = after;
                let mut complete = cursor == tip;
                let mut trials = 0u64;
                for _ in 0..pages {
                    if complete {
                        break;
                    }
                    let reply = public_call(
                        &args,
                        &ingress::Request::History {
                            tip: hex::encode(tip),
                            after: hex::encode(cursor),
                        },
                        node.settings(),
                    )?;
                    trials = trials
                        .checked_add(reply.solve_trials)
                        .ok_or("PUBLIC_TRIALS")?;
                    if !reply.ok {
                        return Err(format!("PUBLIC_REMOTE_REFUSED:{}", reply.value).into());
                    }
                    let page: ingress::Page = serde_json::from_value(reply.value)?;
                    complete = page.complete;
                    cursor = ingress::receive_page(&mut node, page, tip, cursor, ingress::now()?)?;
                }
                if !complete {
                    return Err(format!(
                        "INCOMPLETE_HISTORY:page_budget:after={}",
                        hex::encode(cursor)
                    )
                    .into());
                }
                // A signed remote page is only transport evidence; receive_page owns
                // complete native verification and activation of the fixed tip.
                let mut result = json!({"verified_tip":hex::encode(cursor),"state":node.stats()?,"transport_solve_trials":trials,"public_network_ready":false});
                if let Some((candidate, bound)) = sync_evaluation_query {
                    // The same exclusive local owner has completed native sync.
                    // A refused query cannot undo those committed sync facts.
                    let (active_tip, generation) = node.active()?;
                    let observed_now = ingress::now()?;
                    let observation = node
                        .evaluation_round_observation(candidate, observed_now, bound)
                        .map_err(|error| Error::from(format!(
                            "SYNC_COMPLETED_EVALUATION_OBSERVATION_REFUSED:verified_tip={}:active_tip={}:generation={generation}:{error}",
                            hex::encode(cursor), hex::encode(active_tip),
                        )))?;
                    result["evaluation_observation"] = serde_json::to_value(observation)?;
                    result["evaluation_observation_scope"] = json!({
                        "schema":"native-sync-evaluation-observation-v1",
                        "same_exclusive_local_owner":true,
                        "complete_native_sync":true,
                        "unsigned_local_observation":true,
                        "transport_phase_authority":false,
                        "public_ready":false,
                    });
                }
                result
            } else if let Some(authentication) = authenticated_client(&args)? {
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
            if public_profile(&args) {
                if args.get("--public-development-network").map(String::as_str) != Some("true")
                    || args.contains_key("--server-public")
                {
                    return Err("EXPLICIT_PUBLIC_DEVELOPMENT_REQUIRED".into());
                }
                let identity = public_identity(&args)?;
                let server_public = identity.public_key().to_owned();
                let lifetime = Duration::from_secs(number(&args, "--seconds", 30)?);
                if public_pool_profile(&args) {
                    if lifetime == Duration::ZERO || lifetime > Duration::from_secs(259200) {
                        return Err("PUBLIC_LIFETIME".into());
                    }
                    let pool = pool_policy(&args)?;
                    let mining = if args.contains_key("--mine") {
                        Some(mining_configuration(&args, node.settings(), &pool, 30)?)
                    } else {
                        None
                    };
                    let policy = ingress::public_v3::PublicPolicy::new(
                        u8::try_from(number(&args, "--admission-bits", 16)?)
                            .map_err(|_| "PUBLIC_POLICY")?,
                        Duration::from_millis(number(&args, "--admission-ttl-ms", 2000)?),
                    )?;
                    let polling_identity = identity.clone();
                    let polling_context = polling
                        .as_ref()
                        .map(PeerPollingConfig::context)
                        .transpose()?
                        .map(hex::encode);
                    let server = ingress::public_v3::PublicServer::new(identity, policy)?;
                    let pool_context = node.enable_local_mempool(pool)?;
                    let listener = std::net::TcpListener::bind(
                        args.get("--listen")
                            .map(String::as_str)
                            .unwrap_or("127.0.0.1:0"),
                    )?;
                    println!(
                        "{}",
                        json!({"event":"listening","address":listener.local_addr()?.to_string(),
                        "state":node.stats()?,"server_public":server_public,"scope":"public-development-unqualified",
                        "admission_profile":ingress::public_v3::PROFILE,"admission_profile_digest":hex::encode(policy.id()),
                        "pool_context":hex::encode(pool_context),"mining_enabled":mining.is_some(),
                        "peer_polling_enabled":polling.is_some(),"peer_polling_context":polling_context,
                        "confidentiality":false,"identity_authority":false,"public_network_ready":false,"production_activation":false})
                    );
                    std::io::stdout().flush()?;
                    let owner = Arc::new(Mutex::new(node));
                    let stop = Arc::new(AtomicBool::new(false));
                    let (service, mining_result, polling_result) = std::thread::scope(|scope| {
                        let miner = mining.map(|config| {
                            let owner = owner.clone();
                            let stop = stop.clone();
                            scope.spawn(move || {
                                let result =
                                    run_pool_mining(owner, config, stop.clone(), |event| {
                                        println!("{}", serde_json::to_string(event)?);
                                        std::io::stdout().flush()?;
                                        Ok(())
                                    });
                                // A finite successful miner limit leaves ingress
                                // serving retained blocks for peer catch-up. An
                                // operational failure stops the shared runtime.
                                if result.is_err() {
                                    stop.store(true, Ordering::Release);
                                }
                                result
                            })
                        });
                        let poller = polling.map(|config| {
                            let owner = owner.clone();
                            let stop = stop.clone();
                            scope.spawn(move || {
                                let result = run_pinned_peer_polling(
                                    owner,
                                    config,
                                    polling_identity,
                                    stop.clone(),
                                    |event| {
                                        println!("{}", serde_json::to_string(event)?);
                                        std::io::stdout().flush()?;
                                        Ok(())
                                    },
                                );
                                if result.is_err() {
                                    stop.store(true, Ordering::Release);
                                }
                                result
                            })
                        });
                        let service = ingress::public_v3::serve_public_protected_v3(
                            listener,
                            owner,
                            lifetime,
                            stop.clone(),
                            server,
                        );
                        stop.store(true, Ordering::Release);
                        let mining_result = miner.map(|handle| {
                            handle
                                .join()
                                .map_err(|_| Error::from("MINING_THREAD"))
                                .and_then(|result| result)
                        });
                        let polling_result = poller.map(|handle| {
                            handle
                                .join()
                                .map_err(|_| Error::from("PEER_POLL_THREAD"))
                                .and_then(|result| result)
                        });
                        (service, mining_result, polling_result)
                    });
                    // All scoped workers have stopped before returning any error.
                    let metrics = service?;
                    let mining_report = mining_result.transpose()?;
                    let polling_report = polling_result.transpose()?;
                    return Ok(
                        json!({"result":metrics,"mining":mining_report,"peer_polling":polling_report,"public_network_ready":false,"production_activation":false}),
                    );
                }
                let listener = std::net::TcpListener::bind(
                    args.get("--listen")
                        .map(String::as_str)
                        .unwrap_or("127.0.0.1:0"),
                )?;
                let policy = public_policy(&args)?;
                println!(
                    "{}",
                    json!({"event":"listening","address":listener.local_addr()?.to_string(),
                    "state":node.stats()?,"server_public":server_public,"scope":"public-development-unqualified",
                    "admission_profile":ingress::public_v2::PROFILE,"admission_profile_digest":hex::encode(policy.id()),
                    "confidentiality":false,"identity_authority":false,"public_network_ready":false,"production_activation":false})
                );
                std::io::stdout().flush()?;
                let metrics = ingress::public_v2::serve_public_protected_v2(
                    listener,
                    node,
                    lifetime,
                    Arc::new(AtomicBool::new(false)),
                    ingress::public_v2::PublicServer::new(identity, policy)?,
                )?;
                return Ok(
                    json!({"result":metrics,"public_network_ready":false,"production_activation":false}),
                );
            }
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
        Ok(value) => {
            let refused = value.get("ok") == Some(&Value::Bool(false));
            println!("{value}");
            // Preserve the authenticated denial as structured stdout while making
            // the command unsuccessful for shell callers and campaign supervisors.
            if refused {
                std::process::exit(2);
            }
        }
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
