//! Ordinary CLI admission for an independently owner-pinned TCD1 byte plan.
//! The existing CPR2 option authenticates TCR1, never the wrapper's metadata.

use std::{net::SocketAddr, path::Path, path::PathBuf, time::Duration};

use trnm_data_availability::cell::{
    digest_hex, fetch_closure_to_file, parse_digest, CellContextV1, CellErrorV1, CellFileRoleV1,
    CellLoaderContextV1, CellPeerLimitsV1, CellReleaseClosureV1, CellReleaseFetchLimitsV1,
    CellStoreV1, MAX_CELL_BYTES,
};

use super::{release_limits, Args, ReleaseAuthentication, Result};

pub(super) fn fetch(args: &mut Args) -> Result<()> {
    // A new caller must explicitly select its authentication policy. Unknown
    // or failed PQ admission never retries the content-address-only branch.
    if !args.0.contains_key("--authentication-profile") {
        return Err(
            CellErrorV1::Invalid("closure requires explicit authentication profile").into(),
        );
    }
    let authentication = ReleaseAuthentication::parse(args)?;
    let store_path = PathBuf::from(args.take("--store")?);
    let cache_config = args.cache_config()?;
    let root = PathBuf::from(args.take("--closure-file")?);
    let closure_id = parse_digest(&args.take("--closure")?)?;
    let selected_generation = args.take("--loader-generation")?.parse()?;
    let loader_profile = parse_digest(&args.take("--loader-profile")?)?;
    let required_roles = roles(&args.take("--required-roles")?)?;
    let context = CellContextV1 {
        family: args.take("--family")?,
        base: parse_digest(&args.take("--base")?)?,
        parent: parse_digest(&args.take("--parent")?)?,
        tokenizer: parse_digest(&args.take("--tokenizer")?)?,
        layout: parse_digest(&args.take("--layout")?)?,
        runtime: parse_digest(&args.take("--runtime")?)?,
    };
    let peers = args
        .take("--peers")?
        .split(',')
        .filter(|value| !value.is_empty())
        .map(str::parse)
        .collect::<std::result::Result<Vec<SocketAddr>, _>>()?;
    let output = PathBuf::from(args.take("--output")?);
    let (mut release, overall_timeout) = release_limits(args)?;
    let request_timeout = Duration::from_millis(args.optional("--request-ms", "2000").parse()?);
    let parallelism = args.optional("--parallelism", "2").parse()?;
    let max_connections = args.optional("--max-connections", "32768").parse()?;
    let max_response_bytes = args.take("--max-response-bytes")?.parse()?;
    args.finish()?;
    let expected = CellLoaderContextV1 {
        closure_id,
        context,
        selected_generation,
        loader_profile,
        required_roles,
        max_payload_bytes: release.max_payload_bytes,
        max_chunks: release.max_chunks,
    };
    let closure = read_closure(&root)?;
    closure.verify_for_loader(&expected)?;
    authentication.verify(closure.release(), &mut release)?;
    // Both independent pin admission and any required CPR2 authentication must
    // succeed before opening a writable cache or dialing a peer.
    let store = CellStoreV1::open(&store_path, cache_config)?;
    let report = fetch_closure_to_file(
        &store,
        &closure,
        &expected,
        &peers,
        CellReleaseFetchLimitsV1 {
            peer: CellPeerLimitsV1 {
                request_timeout,
                overall_timeout,
                max_cell_bytes: release.max_payload_bytes.min(MAX_CELL_BYTES),
                parallelism,
                max_connections,
                max_response_bytes,
            },
            release,
        },
        &output,
    )?;
    let members = report.release;
    println!("{{\"schema\":\"trnm.cell.closure.fetch.v1\",\"closure\":\"{}\",\"generation\":{},\"release\":\"{}\",\"cells\":{},\"payload_bytes\":{},\"chunks\":{},\"cached_chunks\":{},\"downloaded_chunks\":{},\"downloaded_bytes\":{},\"received_response_bytes\":{},\"max_response_bytes\":{},\"connection_attempts\":{},\"rejected_responses\":{},\"suppliers\":{},\"selection_authority\":false,\"use_authority\":false}}",
        digest_hex(report.closure_id), report.selected_generation, digest_hex(members.release_id),
        members.cells, members.payload_bytes, members.chunks, members.cached_chunks,
        members.downloaded_chunks, members.downloaded_bytes, members.received_response_bytes,
        max_response_bytes, members.connection_attempts, members.rejected_responses,
        members.supplying_peers.len());
    Ok(())
}

fn roles(text: &str) -> Result<Vec<CellFileRoleV1>> {
    if text.len() > 128 {
        return Err(CellErrorV1::Invalid("closure required roles length").into());
    }
    text.split(',')
        .map(|role| match role {
            "base" => Ok(CellFileRoleV1::Base),
            "tokenizer" => Ok(CellFileRoleV1::Tokenizer),
            "preprocessor" => Ok(CellFileRoleV1::Preprocessor),
            "adapter" => Ok(CellFileRoleV1::Adapter),
            "router" => Ok(CellFileRoleV1::Router),
            "configuration" => Ok(CellFileRoleV1::Configuration),
            _ => Err(CellErrorV1::Invalid("closure required role").into()),
        })
        .collect()
}

fn read_closure(path: &Path) -> Result<CellReleaseClosureV1> {
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(CellErrorV1::Invalid("closure descriptor IO unsupported").into())
    }
    #[cfg(unix)]
    {
        use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};
        use trnm_data_availability::cell::MAX_CELL_CLOSURE_BYTES_V1;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_CELL_CLOSURE_BYTES_V1 as u64
        {
            return Err(CellErrorV1::Invalid("closure input size/type").into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_CELL_CLOSURE_BYTES_V1 as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(CellErrorV1::Invalid("closure input changed length").into());
        }
        Ok(CellReleaseClosureV1::decode(&bytes)?)
    }
}
