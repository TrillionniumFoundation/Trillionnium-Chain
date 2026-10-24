//! Explicit configured-peer cell cache pilot. This executable cannot publish a
//! Chain release, change CURRENT, or authorize model execution.

use std::{
    collections::BTreeMap,
    error::Error,
    io::Write,
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use trnm_data_availability::cell::{
    digest_hex, fetch_cell_to_file, fetch_release_to_file, parse_digest, read_pinned_release,
    serve_cells, serve_cells_bounded, CellCacheConfigV4, CellContextV1, CellErrorV1,
    CellPeerLimitsV1, CellReleaseFetchLimitsV1, CellReleaseLimitsV1, CellReleaseManifestV1,
    CellServeLimitsV1, CellStoreV1, MAX_CELL_BYTES,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const USAGE: &str = "trnm-cell: finite configured-peer content cache (no model authority)
Writers (pack,fetch,verify,prepare-release,fetch-release,verify-release) also require --cache-max-bytes N --cache-max-chunks N --cache-max-manifests N --cache-max-db-bytes N. Persisted TCL4/schema4 caps must match on every reopen; the main DB image cap derives separate WAL/SHM file-length caps; held readers can refuse writes before mutation. No allocated-block reservation or journal/TEMP/output/global-disk quota is claimed.
pack --store DB --input FILE --family FAMILY --base HEX --parent HEX --tokenizer HEX --layout HEX --runtime HEX [--chunk-bytes 1048576]
serve --store DB --bind IP:PORT --seconds N [--request-ms 2000] [--max-connections 8192] [--bounded-workers 1..4 --max-served-bytes N]
fetch --store DB --manifest HEX --peers IP:PORT,IP:PORT --output ABSENT_FILE --max-bytes N (--seconds N | --overall-ms N) [--parallelism 2] [--request-ms 2000] [--max-connections 32768] [--max-response-bytes N]
  Response-byte default: 2 * max-bytes + 2097152 + 9 * max-connections; 0 is cache-only.
verify --store DB --manifest HEX
manifest --store DB --manifest HEX --output ABSENT_FILE
prepare-release --store DB --manifests HEX,HEX --output ABSENT_TCR1 --max-bytes N --max-chunks N (--seconds N | --overall-ms N)
  Verify all locally declared members and prepare their canonical TCR1 root; no selection authority.
fetch-release --store DB --release-file OWNER_TCR1 --release HEX --peers IP:PORT,IP:PORT --output ABSENT_MARKER --max-bytes N --max-chunks N (--seconds N | --overall-ms N) --max-response-bytes N [--parallelism 2] [--request-ms 2000] [--max-connections 32768]
  One aggregate reservation covers all declared members. Output is the exact TCR1 completion marker, not weights or use authority.
verify-release --store DB --release-file OWNER_TCR1 --release HEX --max-bytes N --max-chunks N (--seconds N | --overall-ms N)";

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
        "pack" => pack(&mut args),
        "serve" => serve(&mut args),
        "fetch" => fetch(&mut args),
        "verify" => verify(&mut args),
        "manifest" => manifest(&mut args),
        "prepare-release" => prepare_release(&mut args),
        "fetch-release" => fetch_release(&mut args),
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
    if explicit_workers && !(1..=4).contains(&workers) {
        return Err(CellErrorV1::Invalid("serving worker budget").into());
    }
    let served_bytes = if workers == 0 {
        None
    } else {
        Some(args.take("--max-served-bytes")?.parse()?)
    };
    args.finish()?;
    if let Some(max_response_bytes) = served_bytes {
        let listener = TcpListener::bind(bind)?;
        println!(
            "{{\"schema\":\"trnm.cell.listen.v1\",\"address\":\"{}\"}}",
            listener.local_addr()?
        );
        std::io::stdout().flush()?;
        let report = serve_cells_bounded(
            &listener,
            &store,
            &AtomicBool::new(false),
            CellServeLimitsV1 {
                request_timeout: Duration::from_millis(request_ms),
                overall_timeout: Duration::from_secs(seconds),
                max_workers: workers,
                max_connections,
                max_response_bytes,
            },
        )?;
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
    args.finish()?;
    let store = CellStoreV1::open(&store, cache_config)?;
    let (_, report) = fetch_cell_to_file(
        &store,
        pinned,
        &peers,
        CellPeerLimitsV1 {
            request_timeout: Duration::from_millis(request_ms),
            overall_timeout,
            max_cell_bytes,
            parallelism,
            max_connections,
            max_response_bytes,
        },
        &output,
    )?;
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
    let (release_limits, overall_timeout) = release_limits(args)?;
    let request_ms = args.optional("--request-ms", "2000").parse()?;
    let parallelism = args.optional("--parallelism", "2").parse()?;
    let max_connections = args.optional("--max-connections", "32768").parse()?;
    let max_response_bytes = args.take("--max-response-bytes")?.parse()?;
    args.finish()?;
    let release = read_pinned_release(&root, pinned)?;
    let store = CellStoreV1::open(&store, cache_config)?;
    let report = fetch_release_to_file(
        &store,
        &release,
        pinned,
        &peers,
        CellReleaseFetchLimitsV1 {
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
        &output,
    )?;
    println!("{{\"schema\":\"trnm.cell.release.fetch.v1\",\"release\":\"{}\",\"cells\":{},\"payload_bytes\":{},\"chunks\":{},\"cached_chunks\":{},\"downloaded_chunks\":{},\"downloaded_bytes\":{},\"received_response_bytes\":{},\"max_response_bytes\":{},\"connection_attempts\":{},\"rejected_responses\":{},\"suppliers\":{}}}",
        digest_hex(report.release_id), report.cells, report.payload_bytes, report.chunks,
        report.cached_chunks, report.downloaded_chunks, report.downloaded_bytes,
        report.received_response_bytes, max_response_bytes, report.connection_attempts,
        report.rejected_responses, report.supplying_peers.len());
    Ok(())
}

fn verify_release(args: &mut Args) -> Result<()> {
    let store = PathBuf::from(args.take("--store")?);
    let cache_config = args.cache_config()?;
    let root = PathBuf::from(args.take("--release-file")?);
    let pinned = parse_digest(&args.take("--release")?)?;
    let (limits, _) = release_limits(args)?;
    args.finish()?;
    let release = read_pinned_release(&root, pinned)?;
    CellStoreV1::open(&store, cache_config)?.verify_release_complete(&release, limits)?;
    println!(
        "{{\"schema\":\"trnm.cell.release.verify.v1\",\"release\":\"{}\",\"cells\":{}}}",
        digest_hex(pinned),
        release.cells().len()
    );
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
