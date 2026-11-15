//! PQ dispatch in the same CLI. No signature failure enters the v1 branch.
use super::*;
use crate::cell_pq;
use trnm_data_availability::cell::{
    discovery::pq::*,
    pq::{CellPqKeyPinV2, CellPqKeyPinsV2},
};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;

pub(super) fn run(command: &str, args: &mut Args, started: Instant) -> Result<()> {
    match command {
        "key-public" => key_public(args),
        "pin-key" => pin_key(args),
        "context-digest" => super::context_digest(args),
        "init" => init(args),
        "sign" => sign(args),
        "announce" => announce(args, started),
        "serve" => serve(args),
        "fetch" => fetch(args, started),
        _ => Err(invalid("unknown PQ discovery command")),
    }
}
fn read_keys(path: &Path) -> Result<CellPqKeyPinsV2> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() < 8 || meta.len() > 8 + 64 * 2039 || meta.nlink() != 1 {
        return Err(invalid("PQ authority roster size/type/links"));
    }
    let mut wire = Vec::new();
    file.take(8 + 64 * 2039 + 1).read_to_end(&mut wire)?;
    Ok(CellPqKeyPinsV2::decode(&wire)?)
}
fn keys(args: &mut Args) -> Result<CellPqKeyPinsV2> {
    read_keys(&PathBuf::from(args.take("--pq-keys-file")?))
}
fn key_public(args: &mut Args) -> Result<()> {
    let seed = PathBuf::from(args.take("--secret-key-file")?);
    let output = PathBuf::from(args.take("--spki-output")?);
    args.finish()?;
    let spki = cell_pq::public_spki(&seed)?;
    let id = ml_dsa_65_key_id_from_spki(&spki).map_err(|_| invalid("PQ SPKI"))?;
    cell_pq::write_new(&output, &spki)?;
    println!(
        "{{\"schema\":\"trnm.cell.discovery.owner.v2\",\"owner\":\"{}\",\"spki_bytes\":1974}}",
        digest_hex(id)
    );
    Ok(())
}
fn pin_key(args: &mut Args) -> Result<()> {
    let spki = cell_pq::read_regular(&PathBuf::from(args.take("--spki")?), false)?;
    let key_id = args.nonzero_digest("--owner")?;
    let generation = args.number("--owner-generation")?;
    let not_before = args.number("--key-not-before")?;
    let expires_at = args.number("--key-expires")?;
    let revoked_at = args
        .0
        .remove("--key-revoked-at")
        .map(|v| parse(&v))
        .transpose()?;
    let prior = args.0.remove("--prior-pins");
    let output = PathBuf::from(args.take("--keys-output")?);
    args.finish()?;
    let mut pins = if let Some(path) = prior {
        read_keys(Path::new(&path))?.pins().cloned().collect()
    } else {
        Vec::new()
    };
    pins.push(CellPqKeyPinV2 {
        spki,
        key_id,
        generation,
        not_before,
        expires_at,
        revoked_at,
    });
    let keys = CellPqKeyPinsV2::new(pins)?;
    cell_pq::write_new(&output, &keys.encode())?;
    println!(
        "{{\"schema\":\"trnm.cell.discovery.pins.v2\",\"authority_digest\":\"{}\"}}",
        digest_hex(keys.digest())
    );
    Ok(())
}
fn init(args: &mut Args) -> Result<()> {
    let path = PathBuf::from(args.take("--directory")?);
    let context = args.context()?;
    let keys = keys(args)?;
    args.finish()?;
    let directory = CellProviderDirectoryV2::open(&path, context, keys)?;
    let usage = directory.usage()?;
    println!("{{\"schema\":\"trnm.cell.discovery.init.v2\",\"profile\":\"{CELL_DISCOVERY_PROFILE_V2}\",\"namespace\":\"{}\",\"retained_identities\":{},\"maximum_identities\":{},\"retained_wire_bytes\":{},\"database_bytes\":{},\"maximum_database_bytes\":{},\"database_bound_includes_journal_or_rss\":false,\"use_authority\":false}}",digest_hex(context.namespace),usage.retained_identities,usage.maximum_identities,usage.retained_wire_bytes,usage.database_bytes,usage.maximum_database_bytes);
    Ok(())
}
fn sign(args: &mut Args) -> Result<()> {
    let output = PathBuf::from(args.take("--record-output")?);
    let seed = PathBuf::from(args.take("--secret-key-file")?);
    let request = args.request()?;
    let owner = args.nonzero_digest("--owner")?;
    let statement = CellProviderStatementV2 {
        request,
        owner,
        owner_generation: args.number("--owner-generation")?,
        endpoint: args.number("--endpoint")?,
        sequence: args.number("--sequence")?,
        issued_unix_seconds: args.number("--issued-unix-seconds")?,
        expires_unix_seconds: args.number("--expires-unix-seconds")?,
        withdrawn: args
            .0
            .remove("--withdrawn")
            .map(|v| parse(&v))
            .transpose()?
            .unwrap_or(false),
    };
    args.finish()?;
    let key = cell_pq::signing_key(&seed, owner)?;
    let record = CellProviderRecordV2::sign(statement, &key)?;
    let wire = record.encode();
    cell_pq::write_new(&output, &wire)?;
    println!("{{\"schema\":\"trnm.cell.discovery.record.v2\",\"record_bytes\":{},\"record_sha256\":\"{}\",\"owner\":\"{}\",\"sequence\":{},\"use_authority\":false}}",wire.len(),digest_hex(Sha256::digest(&wire).into()),digest_hex(owner),record.statement().sequence);
    Ok(())
}
fn announce(args: &mut Args, started: Instant) -> Result<()> {
    let path = PathBuf::from(args.take("--record")?);
    let owner = args.nonzero_digest("--owner")?;
    let request = args.request()?;
    let bootstrap = args.number("--bootstrap")?;
    let keys = keys(args)?;
    let addresses = args.addresses()?;
    let limits = args.client_limits()?;
    args.finish()?;
    let original = deadline(started, limits.overall_timeout)?;
    let wire = cell_pq::read_regular::<CELL_PROVIDER_RECORD_BYTES_V2>(&path, false)?;
    let record = CellProviderRecordV2::decode(&wire)?;
    if record.statement().request != request || record.statement().owner != owner {
        return Err(invalid("PQ advertisement differs from owner/context pins"));
    }
    let observed =
        announce_cell_provider_pq(&record, bootstrap, &keys, &addresses, limits, original)?;
    println!("{{\"schema\":\"trnm.cell.discovery.announce.v2\",\"discovery\":{},\"use_authority\":false}}",observation_json(&observed));
    Ok(())
}
fn serve(args: &mut Args) -> Result<()> {
    let path = PathBuf::from(args.take("--directory")?);
    let context = args.context()?;
    let keys = keys(args)?;
    let bind: SocketAddr = args.number("--bind")?;
    let addresses = args.addresses()?;
    let limits = CellRendezvousLimitsV2 {
        request_timeout: Duration::from_millis(args.number("--request-ms")?),
        lifetime: args.overall_timeout()?,
        max_connections: args.number("--max-connections")?,
    };
    args.finish()?;
    limits.validate()?;
    let directory = CellProviderDirectoryV2::open(&path, context, keys)?;
    let listener = TcpListener::bind(bind)?;
    println!("{{\"schema\":\"trnm.cell.discovery.listen.v2\",\"address\":\"{}\",\"profile\":\"{CELL_DISCOVERY_PROFILE_V2}\",\"namespace\":\"{}\"}}",listener.local_addr()?,digest_hex(context.namespace));
    std::io::stdout().flush()?;
    let report = serve_cell_rendezvous_pq(
        &listener,
        &directory,
        &addresses,
        &AtomicBool::new(false),
        limits,
    )?;
    println!("{{\"schema\":\"trnm.cell.discovery.serve.v2\",\"connections\":{},\"rejected_requests\":{},\"record_validation_attempts\":{}}}",report.connections,report.rejected_requests,report.record_validation_attempts);
    Ok(())
}
fn fetch(args: &mut Args, started: Instant) -> Result<()> {
    let path = PathBuf::from(args.take("--directory")?);
    let keys = keys(args)?;
    let store = PathBuf::from(args.take("--store")?);
    let cache = CellCacheConfigV4 {
        max_database_bytes: args.number("--cache-max-db-bytes")?,
        max_logical_bytes: args.number("--cache-max-bytes")?,
        max_chunk_rows: args.number("--cache-max-chunks")?,
        max_manifest_rows: args.number("--cache-max-manifests")?,
    };
    cache.validate()?;
    let request = args.request()?;
    let bootstraps = list(&args.take("--bootstraps")?, MAX_DISCOVERY_BOOTSTRAPS, parse)?;
    let output = PathBuf::from(args.take("--output")?);
    let addresses = args.addresses()?;
    let limits = args.client_limits()?;
    args.finish()?;
    let original = deadline(started, limits.overall_timeout)?;
    let directory = CellProviderDirectoryV2::open(&path, request.context, keys)?;
    let store = CellStoreV1::open(&store, cache)?;
    let options = CellDiscoveryOptionsV2 {
        request,
        bootstraps,
        addresses,
    };
    let (_, report) =
        fetch_discovered_cell_to_file_pq(&store, &directory, &options, limits, original, &output)?;
    let f = &report.fetch;
    println!("{{\"schema\":\"trnm.cell.discovery.fetch.v2\",\"profile\":\"{CELL_DISCOVERY_PROFILE_V2}\",\"manifest\":\"{}\",\"bytes\":{},\"received_response_bytes\":{},\"connection_attempts\":{},\"discovery\":{},\"discovered_providers\":{},\"use_authority\":false}}",digest_hex(f.manifest_id),f.payload_bytes,f.received_response_bytes,f.connection_attempts,observation_json(&report.discovery),endpoints_json(report.discovered_providers.iter()));
    Ok(())
}
fn observation_json(value: &CellDiscoveryObservationV2) -> String {
    format!("{{\"connection_attempts\":{},\"received_response_bytes\":{},\"record_validation_attempts\":{},\"rejected_records\":{},\"capacity_rejections\":{},\"rejected_bootstraps\":{}}}",value.connection_attempts,value.received_response_bytes,value.record_validation_attempts,value.rejected_records,value.capacity_rejections,value.rejected_bootstraps)
}
