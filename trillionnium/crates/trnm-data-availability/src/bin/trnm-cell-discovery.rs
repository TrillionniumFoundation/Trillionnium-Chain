//! Explicit finite development rendezvous and bootstrap-discovered Cell fetch.
//! An advertisement is not custody, payment, model selection or use authority.
//! Configured-peer trnm-cell remains separate; both use finite TCL2 cache limits.

const USAGE: &str = "trnm-cell-discovery: opt-in finite development discovery (Unix)
Every command requires --profile cell-provider-discovery-dev-v1.
Context flags: --namespace HEX --network HEX --parameters HEX --genesis HEX
Scope flags: --scope loopback-dev --ports N[,N] OR --scope scoped --cidrs IP/PREFIX[,IP/PREFIX] --ports N[,N]
Client limits: (--seconds N | --overall-ms N) --request-ms N --max-bytes N --parallelism N --max-connections N --max-response-bytes N
init --directory DB <context>
key-public --secret-key-file RAW_32_BYTE_PRIVATE_FILE
context-digest --family FAMILY --base HEX --parent HEX --tokenizer HEX --layout HEX --runtime HEX
sign --record-output ABSENT_FILE --secret-key-file RAW_32_BYTE_PRIVATE_FILE --owner HEX --manifest HEX --cell-context HEX --endpoint IP:PORT --sequence N --issued-unix-seconds N --expires-unix-seconds N <context>
announce --record EXACT_335_BYTE_FILE --owner HEX --manifest HEX --cell-context HEX --bootstrap IP:PORT <context> <scope> <client limits>
serve --directory DB --bind IP:PORT (--seconds N | --overall-ms N) --request-ms N --max-connections N <context> <scope>
fetch --directory DB --store DB --cache-max-bytes N --cache-max-chunks N --cache-max-manifests N --manifest HEX --cell-context HEX --bootstraps IP:PORT[,IP:PORT] --output ABSENT_FILE <context> <scope> <client limits>
All pins, namespace, numeric addresses and limits are explicit. No DNS/referrals/DHT.
Private seed files must be regular, nonsymlink, exactly 32 raw bytes, one link,
and mode 0600 or stricter; seed bytes are never printed. Records are public.
Fetch response/connection totals already include the separate discovery breakdown.
Discovery supplies location hints, not retention, funding or installation authority.";

fn main() {
    #[cfg(unix)]
    if let Err(error) = unix::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        let values: Vec<_> = std::env::args_os().skip(1).collect();
        if values.is_empty() || values == [std::ffi::OsString::from("--help")] {
            println!("{USAGE}");
        } else {
            eprintln!("discovery file identity unsupported");
            std::process::exit(1);
        }
    }
}

#[cfg(unix)]
mod unix {
    use std::{
        collections::BTreeMap,
        error::Error,
        fs::{File, OpenOptions},
        io::{Read, Write},
        net::{IpAddr, SocketAddr, TcpListener},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        str::FromStr,
        sync::atomic::AtomicBool,
        time::{Duration, Instant},
    };

    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use trnm_data_availability::cell::{
        digest_hex,
        discovery::{
            announce_cell_provider, cell_discovery_context_digest, fetch_discovered_cell_to_file,
            serve_cell_rendezvous, CellDiscoveryAddressPolicyV1, CellDiscoveryCidrV1,
            CellDiscoveryContextV1, CellDiscoveryObservationV1, CellDiscoveryOptionsV1,
            CellDiscoveryRequestV1, CellProviderDirectoryV1, CellProviderRecordV1,
            CellProviderStatementV1, CellRendezvousLimitsV1, CELL_DISCOVERY_PROFILE_V1,
            CELL_PROVIDER_RECORD_BYTES_V1, MAX_DISCOVERY_BOOTSTRAPS,
        },
        parse_digest, CellCacheConfigV2, CellContextV1, CellDigestV1, CellErrorV1,
        CellPeerLimitsV1, CellStoreV1,
    };

    type Result<T> = std::result::Result<T, Box<dyn Error>>;

    pub(super) fn run() -> Result<()> {
        // Capture once before parsing or opening any file. Network commands
        // pass this original deadline through the one shared library session.
        let started = Instant::now();
        let mut values = Vec::new();
        let mut bytes = 0_usize;
        for value in std::env::args_os().skip(1) {
            let value = value
                .into_string()
                .map_err(|_| invalid("UTF-8 arguments"))?;
            bytes = bytes
                .checked_add(value.len())
                .ok_or_else(|| invalid("argument byte bound"))?;
            if values.len() >= 128 || value.len() > 4096 || bytes > 65_536 {
                return Err(invalid("argument count/byte bound"));
            }
            values.push(value);
        }
        if values.is_empty() || values == ["--help"] {
            println!("{}", super::USAGE);
            return Ok(());
        }
        let mut args = Args::new(&values[1..])?;
        if args.take("--profile")? != CELL_DISCOVERY_PROFILE_V1 {
            return Err(invalid("explicit discovery development profile required"));
        }
        match values[0].as_str() {
            "init" => init(&mut args),
            "key-public" => key_public(&mut args),
            "context-digest" => context_digest(&mut args),
            "sign" => sign(&mut args),
            "announce" => announce(&mut args, started),
            "serve" => serve(&mut args),
            "fetch" => fetch(&mut args, started),
            _ => Err(invalid("unknown discovery command; use --help")),
        }
    }

    fn init(args: &mut Args) -> Result<()> {
        let path = PathBuf::from(args.take("--directory")?);
        let context = args.context()?;
        args.finish()?;
        let directory = CellProviderDirectoryV1::open(&path, context)?;
        let usage = directory.usage()?;
        println!(
            "{{\"schema\":\"trnm.cell.discovery.init.v1\",\"profile\":\"{CELL_DISCOVERY_PROFILE_V1}\",\"namespace\":\"{}\",\"retained_identities\":{},\"maximum_identities\":{},\"retained_wire_bytes\":{},\"database_bytes\":{},\"maximum_database_bytes\":{},\"database_bound_includes_journal_or_rss\":false,\"use_authority\":false}}",
            digest_hex(context.namespace), usage.retained_identities, usage.maximum_identities,
            usage.retained_wire_bytes, usage.database_bytes, usage.maximum_database_bytes
        );
        Ok(())
    }

    fn key_public(args: &mut Args) -> Result<()> {
        let path = PathBuf::from(args.take("--secret-key-file")?);
        args.finish()?;
        let key = signing_key(&path)?;
        println!(
            "{{\"schema\":\"trnm.cell.discovery.owner.v1\",\"owner\":\"{}\"}}",
            digest_hex(key.verifying_key().to_bytes())
        );
        Ok(())
    }

    fn context_digest(args: &mut Args) -> Result<()> {
        let context = CellContextV1 {
            family: args.take("--family")?,
            base: args.digest("--base")?,
            parent: args.digest("--parent")?,
            tokenizer: args.digest("--tokenizer")?,
            layout: args.digest("--layout")?,
            runtime: args.digest("--runtime")?,
        };
        args.finish()?;
        println!(
            "{{\"schema\":\"trnm.cell.discovery.context.v1\",\"cell_context\":\"{}\"}}",
            digest_hex(cell_discovery_context_digest(&context)?)
        );
        Ok(())
    }

    fn sign(args: &mut Args) -> Result<()> {
        let output = PathBuf::from(args.take("--record-output")?);
        let seed = PathBuf::from(args.take("--secret-key-file")?);
        let request = args.request()?;
        let statement = CellProviderStatementV1 {
            request,
            owner: args.nonzero_digest("--owner")?,
            endpoint: args.number("--endpoint")?,
            sequence: args.number("--sequence")?,
            issued_unix_seconds: args.number("--issued-unix-seconds")?,
            expires_unix_seconds: args.number("--expires-unix-seconds")?,
        };
        args.finish()?;
        let key = signing_key(&seed)?;
        let record = CellProviderRecordV1::sign(statement, &key)?;
        let wire = record.encode();
        write_new(&output, &wire)?;
        println!(
            "{{\"schema\":\"trnm.cell.discovery.record.v1\",\"record_bytes\":{},\"record_sha256\":\"{}\",\"owner\":\"{}\",\"manifest\":\"{}\",\"sequence\":{},\"use_authority\":false}}",
            wire.len(), digest_hex(Sha256::digest(&wire).into()),
            digest_hex(record.statement().owner), digest_hex(request.manifest), record.statement().sequence
        );
        Ok(())
    }

    fn announce(args: &mut Args, started: Instant) -> Result<()> {
        let record_path = PathBuf::from(args.take("--record")?);
        let owner = args.nonzero_digest("--owner")?;
        let request = args.request()?;
        let bootstrap: SocketAddr = args.number("--bootstrap")?;
        let addresses = args.addresses()?;
        let limits = args.client_limits()?;
        args.finish()?;
        let original_deadline = deadline(started, limits.overall_timeout)?;
        let wire = read_regular::<CELL_PROVIDER_RECORD_BYTES_V1>(&record_path, false)?;
        let record = CellProviderRecordV1::decode(&wire)?;
        if record.statement().request != request || record.statement().owner != owner {
            return Err(invalid(
                "advertisement differs from explicit owner/context/manifest pins",
            ));
        }
        let observed =
            announce_cell_provider(&record, bootstrap, &addresses, limits, original_deadline)?;
        println!(
            "{{\"schema\":\"trnm.cell.discovery.announce.v1\",\"record_sha256\":\"{}\",\"manifest\":\"{}\",\"discovery\":{},\"custody_authority\":false,\"payment_authority\":false,\"use_authority\":false}}",
            digest_hex(Sha256::digest(wire).into()), digest_hex(request.manifest), observation_json(&observed)
        );
        Ok(())
    }

    fn serve(args: &mut Args) -> Result<()> {
        let path = PathBuf::from(args.take("--directory")?);
        let context = args.context()?;
        let bind: SocketAddr = args.number("--bind")?;
        let addresses = args.addresses()?;
        let limits = CellRendezvousLimitsV1 {
            request_timeout: Duration::from_millis(args.number("--request-ms")?),
            lifetime: args.overall_timeout()?,
            max_connections: args.number("--max-connections")?,
        };
        args.finish()?;
        limits.validate()?;
        let directory = CellProviderDirectoryV1::open(&path, context)?;
        let listener = TcpListener::bind(bind)?;
        // Explicit bind is an inbound address, including operator-selected port
        // zero. Advertisement/outbound scope does not invent a listener port.
        println!(
            "{{\"schema\":\"trnm.cell.discovery.listen.v1\",\"address\":\"{}\",\"profile\":\"{CELL_DISCOVERY_PROFILE_V1}\",\"namespace\":\"{}\"}}",
            listener.local_addr()?, digest_hex(context.namespace)
        );
        std::io::stdout().flush()?;
        let report = serve_cell_rendezvous(
            &listener,
            &directory,
            &addresses,
            &AtomicBool::new(false),
            limits,
        )?;
        println!(
            "{{\"schema\":\"trnm.cell.discovery.serve.v1\",\"connections\":{},\"rejected_requests\":{},\"record_validation_attempts\":{}}}",
            report.connections, report.rejected_requests, report.record_validation_attempts
        );
        Ok(())
    }

    fn fetch(args: &mut Args, started: Instant) -> Result<()> {
        let path = PathBuf::from(args.take("--directory")?);
        let store = PathBuf::from(args.take("--store")?);
        let cache_config = CellCacheConfigV2 {
            max_logical_bytes: args.number("--cache-max-bytes")?,
            max_chunk_rows: args.number("--cache-max-chunks")?,
            max_manifest_rows: args.number("--cache-max-manifests")?,
        };
        cache_config.validate()?;
        let request = args.request()?;
        let bootstraps = list(&args.take("--bootstraps")?, MAX_DISCOVERY_BOOTSTRAPS, parse)?;
        let output = PathBuf::from(args.take("--output")?);
        let addresses = args.addresses()?;
        let limits = args.client_limits()?;
        args.finish()?;
        let original_deadline = deadline(started, limits.overall_timeout)?;
        let directory = CellProviderDirectoryV1::open(&path, request.context)?;
        let store = CellStoreV1::open(&store, cache_config)?;
        let options = CellDiscoveryOptionsV1 {
            request,
            bootstraps,
            addresses,
        };
        // A single call owns discovery, manifest, chunks, retries and output.
        // There is no discover-then-refetch path that can mint another budget.
        let (_, report) = fetch_discovered_cell_to_file(
            &store,
            &directory,
            &options,
            limits,
            original_deadline,
            &output,
        )?;
        let fetch = &report.fetch;
        println!(
            "{{\"schema\":\"trnm.cell.discovery.fetch.v1\",\"profile\":\"{CELL_DISCOVERY_PROFILE_V1}\",\"manifest\":\"{}\",\"payload_sha256\":\"{}\",\"bytes\":{},\"cached_chunks\":{},\"downloaded_chunks\":{},\"downloaded_bytes\":{},\"received_response_bytes\":{},\"connection_attempts\":{},\"rejected_responses\":{},\"manifest_initial_cache_hit\":{},\"discovery\":{},\"discovered_providers\":{},\"suppliers\":{},\"custody_authority\":false,\"payment_authority\":false,\"use_authority\":false}}",
            digest_hex(fetch.manifest_id), digest_hex(fetch.payload_sha256), fetch.payload_bytes,
            fetch.cached_chunks, fetch.downloaded_chunks, fetch.downloaded_bytes,
            fetch.received_response_bytes, fetch.connection_attempts, fetch.rejected_responses,
            report.manifest_initial_cache_hit, observation_json(&report.discovery),
            endpoints_json(report.discovered_providers.iter()), endpoints_json(fetch.supplying_peers.iter())
        );
        Ok(())
    }

    fn observation_json(value: &CellDiscoveryObservationV1) -> String {
        format!(
            "{{\"connection_attempts\":{},\"received_response_bytes\":{},\"record_validation_attempts\":{},\"rejected_records\":{},\"capacity_rejections\":{},\"rejected_bootstraps\":{}}}",
            value.connection_attempts, value.received_response_bytes, value.record_validation_attempts,
            value.rejected_records, value.capacity_rejections, value.rejected_bootstraps
        )
    }

    fn endpoints_json<'a>(values: impl Iterator<Item = &'a SocketAddr>) -> String {
        // SocketAddr's numeric display is JSON-safe. Arbitrary user text,
        // file names and secret material never enter this manual JSON writer.
        format!(
            "[{}]",
            values
                .map(|value| format!("\"{value}\""))
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    fn signing_key(path: &Path) -> Result<SigningKey> {
        let mut seed = read_regular::<32>(path, true)?;
        let key = SigningKey::from_bytes(&seed);
        // Clear this local buffer, without claiming compiler-guaranteed memory
        // erasure, a key vault, or protection from the privileged local host.
        seed.fill(0);
        Ok(key)
    }

    fn read_regular<const N: usize>(path: &Path, private: bool) -> Result<[u8; N]> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != N as u64 {
            return Err(invalid(
                "input must be a regular file of the exact declared byte length",
            ));
        }
        if private && (metadata.mode() & 0o077 != 0 || metadata.nlink() != 1) {
            return Err(invalid(
                "private seed file requires owner-only permissions and one link",
            ));
        }
        let mut bytes = [0; N];
        file.read_exact(&mut bytes)?;
        let mut trailing = [0];
        if file.read(&mut trailing)? != 0 || file.metadata()?.len() != N as u64 {
            return Err(invalid("input changed length while reading"));
        }
        Ok(bytes)
    }

    fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn deadline(started: Instant, duration: Duration) -> Result<Instant> {
        let deadline = started
            .checked_add(duration)
            .ok_or_else(|| invalid("absolute deadline overflow"))?;
        if Instant::now() >= deadline {
            return Err(invalid("discovery absolute deadline"));
        }
        Ok(deadline)
    }

    fn invalid(message: &'static str) -> Box<dyn Error> {
        Box::new(CellErrorV1::Invalid(message))
    }

    fn parse<T: FromStr>(value: &str) -> Result<T> {
        value
            .parse()
            .map_err(|_| invalid("invalid numeric argument"))
    }

    fn list<T>(
        value: &str,
        maximum: usize,
        mut parse_item: impl FnMut(&str) -> Result<T>,
    ) -> Result<Vec<T>> {
        let mut values = Vec::new();
        for item in value.split(',') {
            if item.is_empty() || values.len() >= maximum {
                return Err(invalid("explicit list count/empty item"));
            }
            values.push(parse_item(item)?);
        }
        Ok(values)
    }

    struct Args(BTreeMap<String, String>);

    impl Args {
        fn new(values: &[String]) -> Result<Self> {
            if !values.len().is_multiple_of(2) {
                return Err(invalid("arguments must be explicit --key value pairs"));
            }
            let mut map = BTreeMap::new();
            for pair in values.chunks_exact(2) {
                if !pair[0].starts_with("--")
                    || map.insert(pair[0].clone(), pair[1].clone()).is_some()
                {
                    return Err(invalid("duplicate or malformed argument"));
                }
            }
            Ok(Self(map))
        }

        fn take(&mut self, key: &str) -> Result<String> {
            self.0
                .remove(key)
                .ok_or_else(|| invalid("missing explicit argument; use --help"))
        }

        fn number<T: FromStr>(&mut self, key: &str) -> Result<T> {
            parse(&self.take(key)?)
        }

        fn digest(&mut self, key: &str) -> Result<CellDigestV1> {
            Ok(parse_digest(&self.take(key)?)?)
        }

        fn nonzero_digest(&mut self, key: &str) -> Result<CellDigestV1> {
            let value = self.digest(key)?;
            if value == [0; 32] {
                return Err(invalid("zero discovery pin"));
            }
            Ok(value)
        }

        fn context(&mut self) -> Result<CellDiscoveryContextV1> {
            Ok(CellDiscoveryContextV1 {
                namespace: self.nonzero_digest("--namespace")?,
                network: self.nonzero_digest("--network")?,
                parameters: self.nonzero_digest("--parameters")?,
                genesis: self.nonzero_digest("--genesis")?,
            })
        }

        fn request(&mut self) -> Result<CellDiscoveryRequestV1> {
            Ok(CellDiscoveryRequestV1 {
                context: self.context()?,
                cell_context: self.nonzero_digest("--cell-context")?,
                manifest: self.nonzero_digest("--manifest")?,
            })
        }

        fn overall_timeout(&mut self) -> Result<Duration> {
            let duration = match (self.0.remove("--seconds"), self.0.remove("--overall-ms")) {
                (Some(value), None) => Duration::from_secs(parse(&value)?),
                (None, Some(value)) => Duration::from_millis(parse(&value)?),
                _ => return Err(invalid("exactly one --seconds or --overall-ms is required")),
            };
            if duration.is_zero() || duration > Duration::from_secs(86_400) {
                return Err(invalid("finite overall timeout"));
            }
            Ok(duration)
        }

        fn addresses(&mut self) -> Result<CellDiscoveryAddressPolicyV1> {
            let scope = self.take("--scope")?;
            let ports = list(&self.take("--ports")?, 16, parse)?;
            let addresses = match scope.as_str() {
                "loopback-dev" => CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports },
                "scoped" => {
                    let cidrs = list(&self.take("--cidrs")?, 8, |value| {
                        let (ip, prefix) = value
                            .split_once('/')
                            .ok_or_else(|| invalid("explicit numeric CIDR"))?;
                        Ok(CellDiscoveryCidrV1::new(
                            parse::<IpAddr>(ip)?,
                            parse(prefix)?,
                        )?)
                    })?;
                    CellDiscoveryAddressPolicyV1::ScopedDeployment { cidrs, ports }
                }
                _ => {
                    return Err(invalid(
                        "explicit loopback-dev or scoped address policy required",
                    ))
                }
            };
            addresses.validate()?;
            Ok(addresses)
        }

        fn client_limits(&mut self) -> Result<CellPeerLimitsV1> {
            let limits = CellPeerLimitsV1 {
                request_timeout: Duration::from_millis(self.number("--request-ms")?),
                overall_timeout: self.overall_timeout()?,
                max_cell_bytes: self.number("--max-bytes")?,
                parallelism: self.number("--parallelism")?,
                max_connections: self.number("--max-connections")?,
                max_response_bytes: self.number("--max-response-bytes")?,
            };
            limits.validate()?;
            Ok(limits)
        }

        fn finish(&self) -> Result<()> {
            if !self.0.is_empty() {
                return Err(invalid("unknown argument"));
            }
            Ok(())
        }
    }
}
