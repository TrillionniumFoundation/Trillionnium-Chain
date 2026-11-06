//! Explicit configured-peer cell cache pilot. This executable cannot publish a
//! Chain release, change CURRENT, or authorize model execution.

mod cell_closure;
mod cell_model;
mod cell_pq;

use std::{
    collections::BTreeMap,
    error::Error,
    io::Write,
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    sync::atomic::AtomicBool,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use trnm_data_availability::cell::{
    digest_hex, fetch_cell_persistent_rarest_first_to_file, fetch_cell_persistent_to_file,
    fetch_cell_rarest_first_to_file, fetch_cell_to_file, fetch_release_to_file,
    fetch_release_with_options_to_file, parse_digest, read_pinned_release, serve_cells,
    serve_cells_bounded, serve_cells_bounded_with_availability,
    serve_cells_bounded_with_availability_and_ready, serve_cells_bounded_with_ready,
    serve_cells_persistent, serve_cells_persistent_rarest_first,
    serve_cells_persistent_rarest_first_with_ready, serve_cells_persistent_with_ready,
    CellCacheConfigV4, CellContextV1, CellErrorV1, CellFetchTransportV2, CellPeerLimitsV1,
    CellPersistentPeerLimitsV2, CellPersistentServeLimitsV2, CellReleaseFetchLimitsV1,
    CellReleaseFetchOptionsV2, CellReleaseLimitsV1, CellReleaseManifestV1, CellServeLimitsV1,
    CellStoreV1, MAX_CELL_BYTES,
};

use trnm_data_availability::cell::pq::{
    CellPqKeyPinV2, CellPqReleaseAuthorizationV2, CellPqReleaseExpectationV2,
    CellPqReleaseStatementV2, CELL_PQ_PROFILE_V2, CELL_PQ_RELEASE_BYTES_V2,
};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const USAGE: &str = "trnm-cell: finite configured-peer content cache (no model authority)
Writers (pack,fetch,verify,prepare-release,fetch-release,fetch-closure,verify-release) also require --cache-max-bytes N --cache-max-chunks N --cache-max-manifests N --cache-max-db-bytes N. Persisted TCL4/schema4 caps must match on every reopen; the main DB image cap derives separate WAL/SHM file-length caps; held readers can refuse writes before mutation. No allocated-block reservation or journal/TEMP/output/global-disk quota is claimed.
pack --store DB --input FILE --family FAMILY --base HEX --parent HEX --tokenizer HEX --layout HEX --runtime HEX [--chunk-bytes 1048576]
serve --store DB --bind IP:PORT --seconds N [--request-ms 2000] [--max-connections 8192] [--bounded-workers 1..4 --max-served-bytes N --availability true|false]
  --transport single-request-v1 (default), persistent-v2 or persistent-rarest-v3. Persistent profiles require bounded workers, --max-served-bytes N, --max-requests N and --max-requests-per-connection N; the V1 availability flag must be false. V3 includes bounded inventory on its own TCQ3/TCS3 connections.
  --announce-ready true is opt-in and requires bounded workers. The separate ready event follows full reader setup; listener publication alone does not establish readiness. Startup does not renew the service deadline.
fetch --store DB --manifest HEX --peers IP:PORT,IP:PORT --output ABSENT_FILE --max-bytes N (--seconds N | --overall-ms N) [--parallelism 2] [--request-ms 2000] [--max-connections 32768] [--max-response-bytes N] [--scheduling ordered|rarest-first-v1]
  --transport single-request-v1 (default), persistent-v2 (ordered scheduling) or persistent-rarest-v3 (explicit rarest-first-v1 scheduling). Persistent profiles require explicit --max-requests N and --max-requests-per-connection N. Inventory and payload frames share those budgets; one fixed deadline applies to each connection and frames do not renew it.
  Response-byte default: 2 * max-bytes + 2097152 + 9 * max-connections; 0 is cache-only.
verify --store DB --manifest HEX
manifest --store DB --manifest HEX --output ABSENT_FILE
prepare-release --store DB --manifests HEX,HEX --output ABSENT_TCR1 --max-bytes N --max-chunks N (--seconds N | --overall-ms N)
  Verify all locally declared members and prepare their canonical TCR1 root; no selection authority.
fetch-release --store DB --release-file OWNER_TCR1 --release HEX --peers IP:PORT,IP:PORT --output ABSENT_MARKER --max-bytes N --max-chunks N (--seconds N | --overall-ms N) --max-response-bytes N [--parallelism 2] [--request-ms 2000] [--max-connections 32768]
  One aggregate reservation covers all declared members. Output is the exact TCR1 completion marker, not weights or use authority.
  All release/closure/model/tensor fetch commands accept the same explicit --transport and --scheduling profiles as fetch. Persistent frame, connection and byte budgets span every member, including manifest preflight.
verify-release --store DB --release-file OWNER_TCR1 --release HEX --max-bytes N --max-chunks N (--seconds N | --overall-ms N)
prepare-model-root --closure-file OWNER_TCD1 --closure HEX --parent-root-files FILE,FILE --output ABSENT_TMR1
  An empty --parent-root-files value explicitly declares an origin. Nonempty parents are decoded and checked for identity/family/older generation.
fetch-model-root --model-root-file OWNER_TMR1 --model-root HEX (all fetch-closure options except --closure-file)
  Root and original closure pins are independent owner inputs. Publishes exact TMR1 only after complete closure verification; no CURRENT or FinalUse authority.
prepare-tensor-model --model-root-file OWNER_TMR1 --model-root HEX --tensor-contract-file OWNER_TMT1 --tensor-contract HEX --output ABSENT_TMA1
fetch-tensor-model --tensor-model-file OWNER_TMA1 --tensor-model HEX (all fetch-closure options except --closure-file)
  Publishes exact TMA1 only after full byte and strict dense safetensors metadata verification. All Base/Adapter members require an exact tensor roster. No CURRENT, FinalUse or expert ABI authority.
fetch-closure --authentication-profile PROFILE --store DB --closure-file OWNER_TCD1 --closure HEX --loader-generation N --loader-profile HEX --required-roles base,tokenizer --family FAMILY --base HEX --parent HEX --tokenizer HEX --layout HEX --runtime HEX --peers IP:PORT,IP:PORT --output ABSENT_TCD1 --max-bytes N --max-chunks N (--seconds N | --overall-ms N) --max-response-bytes N [--parallelism 2] [--request-ms 2000] [--max-connections 32768]
  Explicit content-cache-v1 or cell-pq-v2; owner closure id/context/profile/generation are independent inputs. PQ authenticates the embedded TCR1 only. The TCD1 id must be pinned by the original owner separately. No Hepta install/use authority.
  PQ fetch-release/verify-release: --authentication-profile cell-pq-v2 --pq-authorization CPR2 --pq-signer-spki DER --pq-signer-key-id HEX --pq-generation N --pq-sequence N --pq-network HEX --pq-parameters HEX --pq-key-not-before UNIX --pq-key-expires UNIX [--pq-key-revoked-at UNIX]
  Host key pins/lifetimes and current sequence are independent of peer data. Authentication precedes cache open/dial; its expiry clamps the original aggregate deadline.
pq-key-public --pq-seed-file PRIVATE_RAW32 --output ABSENT_DER
sign-release --authentication-profile cell-pq-v2 --release-file OWNER_TCR1 --release HEX --output ABSENT_CPR2 --pq-seed-file PRIVATE_RAW32 --pq-signer-key-id HEX --pq-network HEX --pq-parameters HEX --pq-generation N --pq-sequence N --pq-issued UNIX --pq-expires UNIX [--pq-withdrawn true|false]";

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let values = std::env::args_os()
        .skip(1)
        .map(|v| {
            v.into_string()
                .map_err(|_| CellErrorV1::Invalid("UTF-8 arguments"))
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if values.is_empty() || values == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    let command = values[0].as_str();
    let mut args = Args::new(&values[1..])?;
    match command {
        "pq-key-public" => pq_key_public(&mut args),
        "sign-release" => sign_release(&mut args),
        "pack" => pack(&mut args),
        "serve" => serve(&mut args),
        "fetch" => fetch(&mut args),
        "verify" => verify(&mut args),
        "manifest" => manifest(&mut args),
        "prepare-release" => prepare_release(&mut args),
        "fetch-release" => fetch_release(&mut args),
        "fetch-closure" => cell_closure::fetch(&mut args),
        "prepare-model-root" => cell_model::prepare(&mut args),
        "fetch-model-root" => cell_closure::fetch_model(&mut args),
        "prepare-tensor-model" => cell_model::prepare_tensor(&mut args),
        "fetch-tensor-model" => cell_closure::fetch_tensor_model(&mut args),
        "verify-release" => verify_release(&mut args),
        _ => Err(CellErrorV1::Invalid("unknown command; use --help").into()),
    }
}

fn pack(args: &mut Args) -> Result<()> {
    let store = PathBuf::from(args.take("--store")?);
    let cache_config = args.cache_config()?;
    let input = PathBuf::from(args.take("--input")?);
    let context = CellContextV1 {
        family: args.take("--family")?,
        base: parse_digest(&args.take("--base")?)?,
        parent: parse_digest(&args.take("--parent")?)?,
        tokenizer: parse_digest(&args.take("--tokenizer")?)?,
        layout: parse_digest(&args.take("--layout")?)?,
        runtime: parse_digest(&args.take("--runtime")?)?,
    };
    let chunk_bytes = args.optional("--chunk-bytes", "1048576").parse()?;
    args.finish()?;
    let manifest =
        CellStoreV1::open(&store, cache_config)?.pack_file(&input, context, chunk_bytes)?;
    println!("{{\"schema\":\"trnm.cell.pack.v1\",\"manifest\":\"{}\",\"payload_sha256\":\"{}\",\"bytes\":{},\"chunks\":{}}}",
        digest_hex(manifest.id()), digest_hex(manifest.payload_sha256()), manifest.size(), manifest.chunks().len());
    Ok(())
}

fn serve(args: &mut Args) -> Result<()> {
    let store = PathBuf::from(args.take("--store")?);
    let bind: SocketAddr = args.take("--bind")?.parse()?;
    let seconds = args.take("--seconds")?.parse()?;
    let request_ms = args.optional("--request-ms", "2000").parse()?;
    let max_connections = args.optional("--max-connections", "8192").parse()?;
    let explicit_workers = args.0.contains_key("--bounded-workers");
    let workers = args.optional("--bounded-workers", "0").parse::<usize>()?;
    let availability = args.optional("--availability", "false").parse::<bool>()?;
    let announce_ready = args.optional("--announce-ready", "false").parse::<bool>()?;
    let transport = args.optional("--transport", "single-request-v1");
    let persistent_requests = match transport.as_str() {
        "single-request-v1" => None,
        "persistent-v2" | "persistent-rarest-v3" => Some((
            args.take("--max-requests")?.parse::<u64>()?,
            args.take("--max-requests-per-connection")?.parse::<u64>()?,
        )),
        _ => return Err(CellErrorV1::Invalid("serving transport profile").into()),
    };
    if explicit_workers && !(1..=4).contains(&workers) {
        return Err(CellErrorV1::Invalid("serving worker budget").into());
    }
    if availability && workers == 0 {
        return Err(CellErrorV1::Invalid("availability requires bounded serving").into());
    }
    if announce_ready && workers == 0 {
        return Err(CellErrorV1::Invalid("ready observation requires bounded serving").into());
    }
    if persistent_requests.is_some() && (workers == 0 || availability) {
        return Err(CellErrorV1::Invalid(
            "persistent serving requires bounded workers without the V1 availability flag",
        )
        .into());
    }
    let served_bytes = if workers == 0 {
        None
    } else {
        Some(args.take("--max-served-bytes")?.parse()?)
    };
    args.finish()?;
    if let Some(max_response_bytes) = served_bytes {
        let serving = CellServeLimitsV1 {
            request_timeout: Duration::from_millis(request_ms),
            overall_timeout: Duration::from_secs(seconds),
            max_workers: workers,
            max_connections,
            max_response_bytes,
        };
        if let Some((max_requests, max_requests_per_connection)) = persistent_requests {
            let limits = CellPersistentServeLimitsV2 {
                serving,
                max_requests,
                max_requests_per_connection,
            };
            limits.validate()?;
            let listener = TcpListener::bind(bind)?;
            println!(
                "{{\"schema\":\"trnm.cell.listen.v1\",\"address\":\"{}\"}}",
                listener.local_addr()?
            );
            std::io::stdout().flush()?;
            let ready = || publish_service_ready(&listener);
            let rarest = transport == "persistent-rarest-v3";
            let report = if announce_ready {
                let serve = if rarest {
                    serve_cells_persistent_rarest_first_with_ready
                } else {
                    serve_cells_persistent_with_ready
                };
                serve(&listener, &store, &AtomicBool::new(false), limits, &ready)?
            } else {
                let serve = if rarest {
                    serve_cells_persistent_rarest_first
                } else {
                    serve_cells_persistent
                };
                serve(&listener, &store, &AtomicBool::new(false), limits)?
            };
            let schema = if rarest {
                "trnm.cell.serve.persistent.rarest.v3"
            } else {
                "trnm.cell.serve.persistent.v2"
            };
            println!("{{\"schema\":\"{schema}\",\"request_attempts\":{},\"connections\":{},\"overloaded\":{},\"completed\":{},\"peak_active_workers\":{},\"sent_response_bytes\":{}}}",
                report.request_attempts, report.serving.accepted_connections,
                report.serving.overloaded_connections, report.serving.completed_requests,
                report.serving.peak_active_workers, report.serving.sent_response_bytes);
            return Ok(());
        }
        let listener = TcpListener::bind(bind)?;
        println!(
            "{{\"schema\":\"trnm.cell.listen.v1\",\"address\":\"{}\"}}",
            listener.local_addr()?
        );
        std::io::stdout().flush()?;
        let report = if announce_ready {
            let serve = if availability {
                serve_cells_bounded_with_availability_and_ready
            } else {
                serve_cells_bounded_with_ready
            };
            serve(&listener, &store, &AtomicBool::new(false), serving, &|| {
                publish_service_ready(&listener)
            })?
        } else {
            let serve = if availability {
                serve_cells_bounded_with_availability
            } else {
                serve_cells_bounded
            };
            serve(&listener, &store, &AtomicBool::new(false), serving)?
        };
        println!("{{\"schema\":\"trnm.cell.serve.bounded.v1\",\"connections\":{},\"overloaded\":{},\"completed\":{},\"peak_active_workers\":{},\"sent_response_bytes\":{}}}",
            report.accepted_connections, report.overloaded_connections, report.completed_requests, report.peak_active_workers, report.sent_response_bytes);
        return Ok(());
    }
    let store = CellStoreV1::open_read_only(&store)?;
    let listener = TcpListener::bind(bind)?;
    println!(
        "{{\"schema\":\"trnm.cell.listen.v1\",\"address\":\"{}\"}}",
        listener.local_addr()?
    );
    std::io::stdout().flush()?;
    let accepted = serve_cells(
        &listener,
        &store,
        &AtomicBool::new(false),
        CellPeerLimitsV1 {
            request_timeout: Duration::from_millis(request_ms),
            overall_timeout: Duration::from_secs(seconds),
            max_cell_bytes: MAX_CELL_BYTES,
            parallelism: 1,
            max_connections,
            max_response_bytes: 0,
        },
    )?;
    println!("{{\"schema\":\"trnm.cell.serve.v1\",\"connections\":{accepted}}}");
    Ok(())
}

fn publish_service_ready(listener: &TcpListener) -> trnm_data_availability::cell::CellResultV1<()> {
    let mut output = std::io::stdout().lock();
    writeln!(
        output,
        "{{\"schema\":\"trnm.cell.ready.v1\",\"address\":\"{}\"}}",
        listener.local_addr()?
    )?;
    output.flush()?;
    Ok(())
}

fn fetch(args: &mut Args) -> Result<()> {
    let store = PathBuf::from(args.take("--store")?);
    let cache_config = args.cache_config()?;
    let pinned = parse_digest(&args.take("--manifest")?)?;
    let peer_text = args.take("--peers")?;
    let peers = peer_text
        .split(',')
        .filter(|v| !v.is_empty())
        .map(str::parse)
        .collect::<std::result::Result<Vec<SocketAddr>, _>>()?;
    let output = PathBuf::from(args.take("--output")?);
    let max_cell_bytes = args.take("--max-bytes")?.parse()?;
    let overall_timeout = args.fetch_timeout()?;
    let request_ms = args.optional("--request-ms", "2000").parse()?;
    let parallelism = args.optional("--parallelism", "2").parse()?;
    let max_connections = args.optional("--max-connections", "32768").parse()?;
    let default_response_bytes =
        CellPeerLimitsV1::default_response_byte_budget(max_cell_bytes, max_connections)?;
    let max_response_bytes = args
        .optional("--max-response-bytes", &default_response_bytes.to_string())
        .parse()?;
    let schedule = args.optional("--scheduling", "ordered");
    let fetch = match schedule.as_str() {
        "ordered" => fetch_cell_to_file,
        "rarest-first-v1" => fetch_cell_rarest_first_to_file,
        _ => return Err(CellErrorV1::Invalid("fetch scheduling profile").into()),
    };
    let transport = args.optional("--transport", "single-request-v1");
    let persistent_requests = match transport.as_str() {
        "single-request-v1" => None,
        "persistent-v2" if schedule == "ordered" => Some((
            args.take("--max-requests")?.parse::<u64>()?,
            args.take("--max-requests-per-connection")?.parse::<u64>()?,
        )),
        "persistent-rarest-v3" if schedule == "rarest-first-v1" => Some((
            args.take("--max-requests")?.parse::<u64>()?,
            args.take("--max-requests-per-connection")?.parse::<u64>()?,
        )),
        "persistent-v2" => {
            return Err(
                CellErrorV1::Invalid("persistent transport requires ordered scheduling").into(),
            )
        }
        "persistent-rarest-v3" => {
            return Err(
                CellErrorV1::Invalid("persistent V3 requires rarest-first-v1 scheduling").into(),
            )
        }
        _ => return Err(CellErrorV1::Invalid("fetch transport profile").into()),
    };
    args.finish()?;
    let peer = CellPeerLimitsV1 {
        request_timeout: Duration::from_millis(request_ms),
        overall_timeout,
        max_cell_bytes,
        parallelism,
        max_connections,
        max_response_bytes,
    };
    if let Some((max_requests, max_requests_per_connection)) = persistent_requests {
        let limits = CellPersistentPeerLimitsV2 {
            peer,
            max_requests,
            max_requests_per_connection,
        };
        limits.validate()?;
        let store = CellStoreV1::open(&store, cache_config)?;
        let rarest = transport == "persistent-rarest-v3";
        let fetch = if rarest {
            fetch_cell_persistent_rarest_first_to_file
        } else {
            fetch_cell_persistent_to_file
        };
        let (_, report) = fetch(&store, pinned, &peers, limits, &output)?;
        let fetch = report.fetch;
        let schema = if rarest {
            "trnm.cell.fetch.persistent.rarest.v3"
        } else {
            "trnm.cell.fetch.persistent.v2"
        };
        println!("{{\"schema\":\"{schema}\",\"manifest\":\"{}\",\"payload_sha256\":\"{}\",\"bytes\":{},\"cached_chunks\":{},\"downloaded_chunks\":{},\"downloaded_bytes\":{},\"received_response_bytes\":{},\"max_response_bytes\":{},\"connection_attempts\":{},\"request_attempts\":{},\"rejected_responses\":{},\"suppliers\":{}}}",
            digest_hex(pinned), digest_hex(fetch.payload_sha256), fetch.payload_bytes,
            fetch.cached_chunks, fetch.downloaded_chunks, fetch.downloaded_bytes,
            fetch.received_response_bytes, max_response_bytes, fetch.connection_attempts,
            report.request_attempts, fetch.rejected_responses, fetch.supplying_peers.len());
        return Ok(());
    }
    let store = CellStoreV1::open(&store, cache_config)?;
    let (_, report) = fetch(&store, pinned, &peers, peer, &output)?;
    println!("{{\"schema\":\"trnm.cell.fetch.v1\",\"manifest\":\"{}\",\"payload_sha256\":\"{}\",\"bytes\":{},\"cached_chunks\":{},\"downloaded_chunks\":{},\"downloaded_bytes\":{},\"received_response_bytes\":{},\"max_response_bytes\":{},\"connection_attempts\":{},\"rejected_responses\":{},\"suppliers\":{}}}",
        digest_hex(pinned), digest_hex(report.payload_sha256), report.payload_bytes, report.cached_chunks,
        report.downloaded_chunks, report.downloaded_bytes, report.received_response_bytes,
        max_response_bytes, report.connection_attempts, report.rejected_responses, report.supplying_peers.len());
    Ok(())
}

fn verify(args: &mut Args) -> Result<()> {
    let store = PathBuf::from(args.take("--store")?);
    let cache_config = args.cache_config()?;
    let pinned = parse_digest(&args.take("--manifest")?)?;
    args.finish()?;
    let store = CellStoreV1::open(&store, cache_config)?;
    let manifest = store.manifest(pinned)?.ok_or(CellErrorV1::Unavailable)?;
    store.verify_complete(&manifest)?;
    println!("{{\"schema\":\"trnm.cell.verify.v1\",\"manifest\":\"{}\",\"payload_sha256\":\"{}\",\"bytes\":{}}}",
        digest_hex(pinned), digest_hex(manifest.payload_sha256()), manifest.size());
    Ok(())
}

fn manifest(args: &mut Args) -> Result<()> {
    let store = PathBuf::from(args.take("--store")?);
    let pinned = parse_digest(&args.take("--manifest")?)?;
    let output = PathBuf::from(args.take("--output")?);
    args.finish()?;
    let manifest = CellStoreV1::open_read_only(&store)?
        .manifest(pinned)?
        .ok_or(CellErrorV1::Unavailable)?;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)?;
    file.write_all(&manifest.encode())?;
    file.sync_all()?;
    Ok(())
}

fn release_limits(args: &mut Args) -> Result<(CellReleaseLimitsV1, Duration)> {
    let max_payload_bytes = args.take("--max-bytes")?.parse()?;
    let max_chunks = args.take("--max-chunks")?.parse()?;
    let duration = args.fetch_timeout()?;
    if !(Duration::from_millis(10)..=Duration::from_secs(86_400)).contains(&duration)
        || max_payload_bytes == 0
        || max_chunks == 0
    {
        return Err(CellErrorV1::Invalid("release resource budget").into());
    }
    let deadline = Instant::now()
        .checked_add(duration)
        .ok_or(CellErrorV1::Invalid("release deadline"))?;
    Ok((
        CellReleaseLimitsV1 {
            max_payload_bytes,
            max_chunks,
            deadline,
        },
        duration,
    ))
}

/// Prepare one caller-declared local set through the same aggregate verifier and
/// create-only publication path as acquisition. No bytes are fetched from peers.
fn prepare_release(args: &mut Args) -> Result<()> {
    let store = PathBuf::from(args.take("--store")?);
    let cache_config = args.cache_config()?;
    let member_text = args.take("--manifests")?;
    if member_text.len() > 1_048_576 {
        return Err(CellErrorV1::Invalid("release member argument size").into());
    }
    let members = member_text
        .split(',')
        .map(parse_digest)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let first = *members
        .first()
        .ok_or(CellErrorV1::Invalid("release cell count"))?;
    let output = PathBuf::from(args.take("--output")?);
    let (release_limits, overall_timeout) = release_limits(args)?;
    args.finish()?;
    let store = CellStoreV1::open(&store, cache_config)?;
    let context = store
        .manifest(first)?
        .ok_or(CellErrorV1::Invalid("release member manifest unavailable"))?
        .context()
        .clone();
    let release = CellReleaseManifestV1::new(context, members)?;
    let report = fetch_release_to_file(
        &store,
        &release,
        release.id(),
        &[],
        CellReleaseFetchLimitsV1 {
            peer: CellPeerLimitsV1 {
                request_timeout: overall_timeout.min(Duration::from_secs(2)),
                overall_timeout,
                max_cell_bytes: release_limits.max_payload_bytes.min(MAX_CELL_BYTES),
                parallelism: 1,
                max_connections: 1,
                max_response_bytes: 0,
            },
            release: release_limits,
        },
        &output,
    )?;
    println!(
        "{{\"schema\":\"trnm.cell.release.prepare.v1\",\"release\":\"{}\",\"cells\":{},\"payload_bytes\":{},\"chunks\":{}}}",
        digest_hex(report.release_id), report.cells, report.payload_bytes, report.chunks
    );
    Ok(())
}

fn fetch_release(args: &mut Args) -> Result<()> {
    let authentication = ReleaseAuthentication::parse(args)?;
    let store = PathBuf::from(args.take("--store")?);
    let cache_config = args.cache_config()?;
    let root = PathBuf::from(args.take("--release-file")?);
    let pinned = parse_digest(&args.take("--release")?)?;
    let peer_text = args.take("--peers")?;
    let peers = peer_text
        .split(',')
        .filter(|value| !value.is_empty())
        .map(str::parse)
        .collect::<std::result::Result<Vec<SocketAddr>, _>>()?;
    let output = PathBuf::from(args.take("--output")?);
    let (mut release_limits, overall_timeout) = release_limits(args)?;
    let request_ms = args.optional("--request-ms", "2000").parse()?;
    let parallelism = args.optional("--parallelism", "2").parse()?;
    let max_connections = args.optional("--max-connections", "32768").parse()?;
    let max_response_bytes = args.take("--max-response-bytes")?.parse()?;
    let transport = fetch_transport(args)?;
    let transport_name = transport_name(&transport);
    args.finish()?;
    let release = read_pinned_release(&root, pinned)?;
    authentication.verify(&release, &mut release_limits)?;
    let options = CellReleaseFetchOptionsV2 {
        limits: CellReleaseFetchLimitsV1 {
            peer: CellPeerLimitsV1 {
                request_timeout: Duration::from_millis(request_ms),
                overall_timeout,
                max_cell_bytes: release_limits.max_payload_bytes.min(MAX_CELL_BYTES),
                parallelism,
                max_connections,
                max_response_bytes,
            },
            release: release_limits,
        },
        transport,
    };
    options.validate()?;
    let store = CellStoreV1::open(&store, cache_config)?;
    let observed =
        fetch_release_with_options_to_file(&store, &release, pinned, &peers, options, &output)?;
    let report = observed.report;
    println!("{{\"schema\":\"trnm.cell.release.fetch.v1\",\"release\":\"{}\",\"cells\":{},\"payload_bytes\":{},\"chunks\":{},\"cached_chunks\":{},\"downloaded_chunks\":{},\"downloaded_bytes\":{},\"received_response_bytes\":{},\"max_response_bytes\":{},\"connection_attempts\":{},\"rejected_responses\":{},\"suppliers\":{},\"transport\":\"{}\",\"request_attempts\":{}}}",
        digest_hex(report.release_id), report.cells, report.payload_bytes, report.chunks,
        report.cached_chunks, report.downloaded_chunks, report.downloaded_bytes,
        report.received_response_bytes, max_response_bytes, report.connection_attempts,
        report.rejected_responses, report.supplying_peers.len(), transport_name, observed.request_attempts);
    Ok(())
}

fn fetch_transport(args: &mut Args) -> Result<CellFetchTransportV2> {
    let transport = args.optional("--transport", "single-request-v1");
    let scheduling = args.optional("--scheduling", "ordered");
    match (transport.as_str(), scheduling.as_str()) {
        ("single-request-v1", "ordered") => Ok(CellFetchTransportV2::OrderedV1),
        ("single-request-v1", "rarest-first-v1") => Ok(CellFetchTransportV2::RarestFirstV1),
        ("persistent-v2", "ordered") => Ok(CellFetchTransportV2::PersistentV2 {
            max_requests: args.take("--max-requests")?.parse()?,
            max_requests_per_connection: args.take("--max-requests-per-connection")?.parse()?,
        }),
        ("persistent-rarest-v3", "rarest-first-v1") => {
            Ok(CellFetchTransportV2::PersistentRarestFirstV3 {
                max_requests: args.take("--max-requests")?.parse()?,
                max_requests_per_connection: args.take("--max-requests-per-connection")?.parse()?,
            })
        }
        ("persistent-v2", _) => {
            Err(CellErrorV1::Invalid("persistent transport requires ordered scheduling").into())
        }
        ("persistent-rarest-v3", _) => {
            Err(CellErrorV1::Invalid("persistent V3 requires rarest-first-v1 scheduling").into())
        }
        _ => Err(CellErrorV1::Invalid("fetch transport/scheduling profile").into()),
    }
}

fn transport_name(transport: &CellFetchTransportV2) -> &'static str {
    match transport {
        CellFetchTransportV2::OrderedV1 => "single-request-v1",
        CellFetchTransportV2::RarestFirstV1 => "rarest-first-v1",
        CellFetchTransportV2::PersistentV2 { .. } => "persistent-v2",
        CellFetchTransportV2::PersistentRarestFirstV3 { .. } => "persistent-rarest-v3",
    }
}

fn verify_release(args: &mut Args) -> Result<()> {
    let authentication = ReleaseAuthentication::parse(args)?;
    let store = PathBuf::from(args.take("--store")?);
    let cache_config = args.cache_config()?;
    let root = PathBuf::from(args.take("--release-file")?);
    let pinned = parse_digest(&args.take("--release")?)?;
    let (mut limits, _) = release_limits(args)?;
    args.finish()?;
    let release = read_pinned_release(&root, pinned)?;
    authentication.verify(&release, &mut limits)?;
    CellStoreV1::open(&store, cache_config)?.verify_release_complete(&release, limits)?;
    println!(
        "{{\"schema\":\"trnm.cell.release.verify.v1\",\"release\":\"{}\",\"cells\":{}}}",
        digest_hex(pinned),
        release.cells().len()
    );
    Ok(())
}

// This cache-only legacy profile is not model-use authority. A caller that
// requires PQ must select cell-pq-v2; that branch has no unsigned/Ed fallback.
enum ReleaseAuthentication {
    ContentAddress,
    Pq {
        authorization: PathBuf,
        key: Box<CellPqKeyPinV2>,
        network: [u8; 32],
        parameters: [u8; 32],
        sequence: u64,
    },
}
impl ReleaseAuthentication {
    fn parse(args: &mut Args) -> Result<Self> {
        match args
            .optional("--authentication-profile", "content-cache-v1")
            .as_str()
        {
            "content-cache-v1" => Ok(Self::ContentAddress),
            CELL_PQ_PROFILE_V2 => {
                let authorization = PathBuf::from(args.take("--pq-authorization")?);
                let spki_path = PathBuf::from(args.take("--pq-signer-spki")?);
                let key_id = parse_digest(&args.take("--pq-signer-key-id")?)?;
                let generation = args.take("--pq-generation")?.parse()?;
                let sequence = args.take("--pq-sequence")?.parse()?;
                let network = parse_digest(&args.take("--pq-network")?)?;
                let parameters = parse_digest(&args.take("--pq-parameters")?)?;
                let not_before = args.take("--pq-key-not-before")?.parse()?;
                let expires_at = args.take("--pq-key-expires")?.parse()?;
                let revoked_at = args
                    .0
                    .remove("--pq-key-revoked-at")
                    .map(|s| s.parse())
                    .transpose()?;
                let spki = cell_pq::read_regular(&spki_path, false)?;
                let key = Box::new(CellPqKeyPinV2 {
                    key_id,
                    generation,
                    spki,
                    not_before,
                    expires_at,
                    revoked_at,
                });
                key.validate()?;
                Ok(Self::Pq {
                    authorization,
                    key,
                    network,
                    parameters,
                    sequence,
                })
            }
            _ => Err(CellErrorV1::Invalid("unknown release authentication profile").into()),
        }
    }
    fn verify(
        &self,
        release: &CellReleaseManifestV1,
        limits: &mut CellReleaseLimitsV1,
    ) -> Result<()> {
        if let Self::Pq {
            authorization,
            key,
            network,
            parameters,
            sequence,
        } = self
        {
            let raw = cell_pq::read_regular::<CELL_PQ_RELEASE_BYTES_V2>(authorization, false)?;
            let auth = CellPqReleaseAuthorizationV2::decode(&raw)?;
            let monotonic = Instant::now();
            let wall = SystemTime::now().duration_since(UNIX_EPOCH)?;
            let expected = CellPqReleaseExpectationV2 {
                network: *network,
                parameters: *parameters,
                key,
                sequence: *sequence,
                now: wall.as_secs(),
            };
            let checked = auth.verify_at(release, &expected)?;
            // This CLI pins an immutable acquisition policy for this command.
            // Runtime activation requires the actual owner's current view.
            checked.release_at(&expected)?;
            let left = Duration::from_secs(checked.expires_at())
                .checked_sub(wall)
                .ok_or(CellErrorV1::Invalid("PQ release expired"))?;
            limits.deadline = limits.deadline.min(
                monotonic
                    .checked_add(left)
                    .ok_or(CellErrorV1::Invalid("PQ release deadline overflow"))?,
            );
            if Instant::now() >= limits.deadline {
                return Err(CellErrorV1::Invalid("PQ release deadline").into());
            }
        }
        Ok(())
    }
}
fn pq_key_public(args: &mut Args) -> Result<()> {
    let seed = PathBuf::from(args.take("--pq-seed-file")?);
    let output = PathBuf::from(args.take("--output")?);
    args.finish()?;
    let spki = cell_pq::public_spki(&seed)?;
    let id =
        ml_dsa_65_key_id_from_spki(&spki).map_err(|_| CellErrorV1::Invalid("PQ public SPKI"))?;
    cell_pq::write_new(&output, &spki)?;
    println!(
        "{{\"schema\":\"trnm.cell.pq-key.v2\",\"key_id\":\"{}\",\"spki_bytes\":1974}}",
        digest_hex(id)
    );
    Ok(())
}
fn sign_release(args: &mut Args) -> Result<()> {
    if args.take("--authentication-profile")? != CELL_PQ_PROFILE_V2 {
        return Err(CellErrorV1::Invalid("PQ release profile required").into());
    }
    let root = PathBuf::from(args.take("--release-file")?);
    let pinned = parse_digest(&args.take("--release")?)?;
    let output = PathBuf::from(args.take("--output")?);
    let seed = PathBuf::from(args.take("--pq-seed-file")?);
    let signer_key_id = parse_digest(&args.take("--pq-signer-key-id")?)?;
    let network = parse_digest(&args.take("--pq-network")?)?;
    let parameters = parse_digest(&args.take("--pq-parameters")?)?;
    let generation = args.take("--pq-generation")?.parse()?;
    let sequence = args.take("--pq-sequence")?.parse()?;
    let issued_at = args.take("--pq-issued")?.parse()?;
    let expires_at = args.take("--pq-expires")?.parse()?;
    let withdrawn = args.optional("--pq-withdrawn", "false").parse()?;
    args.finish()?;
    let release = read_pinned_release(&root, pinned)?;
    let cell_context =
        trnm_data_availability::cell::discovery::cell_discovery_context_digest(release.context())?;
    let key = cell_pq::signing_key(&seed, signer_key_id)?;
    let auth = CellPqReleaseAuthorizationV2::sign(
        CellPqReleaseStatementV2 {
            network,
            parameters,
            release: pinned,
            cell_context,
            signer_key_id,
            generation,
            sequence,
            issued_at,
            expires_at,
            withdrawn,
        },
        &key,
    )?;
    cell_pq::write_new(&output, &auth.encode()?)?;
    println!("{{\"schema\":\"trnm.cell.release.authorization.v2\",\"release\":\"{}\",\"key_id\":\"{}\",\"bytes\":3509}}",digest_hex(pinned),digest_hex(signer_key_id));
    Ok(())
}

struct Args(BTreeMap<String, String>);

impl Args {
    fn new(values: &[String]) -> Result<Self> {
        if !values.len().is_multiple_of(2) {
            return Err(CellErrorV1::Invalid("expected --key value pairs").into());
        }
        let mut result = BTreeMap::new();
        for pair in values.chunks_exact(2) {
            if !pair[0].starts_with("--")
                || result.insert(pair[0].clone(), pair[1].clone()).is_some()
            {
                return Err(CellErrorV1::Invalid("invalid or duplicate argument").into());
            }
        }
        Ok(Self(result))
    }
    fn take(&mut self, key: &'static str) -> Result<String> {
        self.0
            .remove(key)
            .ok_or_else(|| CellErrorV1::Invalid(key).into())
    }
    fn cache_config(&mut self) -> Result<CellCacheConfigV4> {
        let config = CellCacheConfigV4 {
            max_database_bytes: self.take("--cache-max-db-bytes")?.parse()?,
            max_logical_bytes: self.take("--cache-max-bytes")?.parse()?,
            max_chunk_rows: self.take("--cache-max-chunks")?.parse()?,
            max_manifest_rows: self.take("--cache-max-manifests")?.parse()?,
        };
        config.validate()?;
        Ok(config)
    }
    fn fetch_timeout(&mut self) -> Result<Duration> {
        match (self.0.remove("--seconds"), self.0.remove("--overall-ms")) {
            (Some(seconds), None) => Ok(Duration::from_secs(seconds.parse()?)),
            (None, Some(milliseconds)) => Ok(Duration::from_millis(milliseconds.parse()?)),
            _ => Err(CellErrorV1::Invalid(
                "fetch requires exactly one of --seconds or --overall-ms",
            )
            .into()),
        }
    }
    fn optional(&mut self, key: &str, default: &str) -> String {
        self.0.remove(key).unwrap_or_else(|| default.to_owned())
    }
    fn finish(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(CellErrorV1::Invalid("unknown argument").into())
        }
    }
}
