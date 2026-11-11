//! Explicit local operator entry point for the TCA1 model-choice owner.
//! Neither an observation nor a successful byte read grants execution authority.

const USAGE: &str = "trnm-cell-adoption: explicit node-local model-data choices (Unix)
Common: --owner-db ABSOLUTE_DB --policy-file OPERATOR_JSON --anchor APPROVED_TCV1
The database parent must already be canonical, owned by this user and mode 0700.
Every command except init also requires --recovery-floor INDEPENDENT_FLOOR_JSON.
init
status
observe --candidate TCV1 [--parent-commitment HEX64] [--evidence-file JSON]
decide --request-id HEX32 --expected-snapshot FLOOR_JSON --action adopt|defer|retain|rollback --version-commitment HEX64 --local-review HEX64
verify-selected --candidate TCV1 --expected-snapshot FLOOR_JSON --execution-file CURRENT_OPERATOR_JSON --cache EXISTING_TCL4_DB --read-ms N
HEX32 and HEX64 mean exactly 32 and 64 bytes in lowercase hexadecimal.
Policy JSON schema trnm.cell.adoption.policy.v1 requires node_id, policy_id, scope,
execution {network,consensus,fees,root_authority,node_software,protocol_configuration},
mutable_roles [Base,Adapter,Router] in that order or a subset, max_model_payload_bytes,
and max_model_chunks. All six execution pins and all three identities are HEX32.
The anchor and policy come from the local operator, never from candidate metadata.
Policy, anchor, current execution, floor and expected-snapshot files require absolute
paths, canonical private 0700 parents owned by this user, and single-link regular
0600/0400 files owned by this user. Symlinks and identity changes during reads refuse.
Execution JSON has exactly the six execution fields and supplies the owner's current
pins; this CLI compares them but cannot attest that they describe the running host.
Evidence JSON schema trnm.cell.adoption.evidence.v1 accepts optional HEX64 references
evaluation, reproduction, chain_observation, settlement; references verify no claims.
Floor JSON has exactly schema trnm.cell.adoption.recovery-floor.v1 and snapshot_tas1,
the lowercase hexadecimal encoding of an independently retained TAS1 snapshot.
Each successful command prints a recovery_floor object. Retain that object through
an independent owner/custody path before relying on its rollback-detection bound.
Floor files inside the database directory are refused. Different paths alone do not
establish independent custody; restoring an old database and floor together is unsafe.
Init selects nothing; observe never adopts. Decisions require an explicit local review.
An old request may replay a historical receipt: recovery_floor always describes the
current observed journal. Verification scans actual cached bytes under the choice guard.
No command changes the policy, software, consensus, fees or Root; no command grants
FinalUse, authenticates an evaluator, confirms a chain event or proves model quality.";

fn main() {
    #[cfg(unix)]
    if let Err(error) = unix::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args.is_empty() || args == [std::ffi::OsString::from("--help")] {
            println!("{USAGE}");
        } else {
            eprintln!("local adoption file profile requires Unix");
            std::process::exit(1);
        }
    }
}

#[cfg(unix)]
mod unix {
    use std::{
        collections::{BTreeMap, BTreeSet},
        error::Error,
        fs::{self, File, Metadata, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };

    use serde::{de::DeserializeOwned, Deserialize, Deserializer};
    use serde_json::{json, Value};
    use trnm_data_availability::cell::{
        CellAdoptionActionV1, CellAdoptionOwnerV1, CellAdoptionPolicyV1, CellAdoptionReceiptV1,
        CellAdoptionSnapshotV1, CellCandidateEvidenceV1, CellExecutionBoundaryV1, CellFileRoleV1,
        CellLoaderContextV1, CellModelUpdateBoundaryV1, CellReleaseClosureV1, CellReleaseLimitsV1,
        CellStoreV1, CellVersionLoaderContextV1, CellVersionManifestV1, MAX_CELL_VERSION_BYTES_V1,
    };

    type Result<T> = std::result::Result<T, Box<dyn Error>>;

    pub(super) fn run() -> Result<()> {
        let started = Instant::now();
        let values = arguments()?;
        if values.is_empty() || values == ["--help"] {
            println!("{}", super::USAGE);
            return Ok(());
        }
        let command = values[0].as_str();
        if !matches!(
            command,
            "init" | "status" | "observe" | "decide" | "verify-selected"
        ) {
            return Err(invalid("unknown local adoption command; use --help"));
        }
        let mut args = Args::new(&values[1..])?;
        let common = Common {
            owner: args.path("--owner-db")?,
            policy: args.path("--policy-file")?,
            anchor: args.path("--anchor")?,
            floor: if command == "init" {
                None
            } else {
                Some(args.path("--recovery-floor")?)
            },
        };
        let result = match command {
            "init" | "status" => {
                args.finish()?;
                let setup = common.setup()?;
                let mut owner = common.open(&setup.policy)?;
                output(command, &owner.snapshot()?, Value::Null)
            }
            "observe" => observe(args, &common)?,
            "decide" => decide(args, &common)?,
            "verify-selected" => verify(args, &common, started)?,
            _ => unreachable!(),
        };
        let mut stdout = std::io::stdout().lock();
        serde_json::to_writer(&mut stdout, &result)?;
        writeln!(stdout)?;
        stdout.flush()?;
        Ok(())
    }

    fn observe(mut args: Args<'_>, common: &Common) -> Result<Value> {
        let candidate_path = args.path("--candidate")?;
        let parent = args
            .optional("--parent-commitment")
            .map(parse_hex::<64>)
            .transpose()?;
        let evidence_path = args.optional("--evidence-file").map(PathBuf::from);
        args.finish()?;
        let setup = common.setup()?;
        let version = version(&candidate_path)?;
        let evidence = match evidence_path {
            Some(path) => {
                let value: EvidenceFile = read_json(&path, 4096)?;
                if value.schema != "trnm.cell.adoption.evidence.v1" {
                    return Err(invalid("adoption evidence JSON schema"));
                }
                CellCandidateEvidenceV1 {
                    evaluation: value.evaluation.map(|v| v.0),
                    reproduction: value.reproduction.map(|v| v.0),
                    chain_observation: value.chain_observation.map(|v| v.0),
                    settlement: value.settlement.map(|v| v.0),
                }
            }
            None => CellCandidateEvidenceV1::default(),
        };
        let mut owner = common.open(&setup.policy)?;
        let observed = owner.observe_candidate(&version, parent, evidence)?;
        Ok(output(
            "observe",
            &owner.snapshot()?,
            json!({
                "candidate": hex(&observed.candidate),
                "parent": observed.parent.map(|v| hex(&v)),
                "evidence_reference_commitment": hex(&observed.evidence),
                "payload_bytes_verified": false
            }),
        ))
    }

    fn decide(mut args: Args<'_>, common: &Common) -> Result<Value> {
        let request = parse_hex::<32>(args.take("--request-id")?)?;
        let expected_path = args.path("--expected-snapshot")?;
        let action = match args.take("--action")? {
            "adopt" => CellAdoptionActionV1::Adopt,
            "defer" => CellAdoptionActionV1::Defer,
            "retain" => CellAdoptionActionV1::Retain,
            "rollback" => CellAdoptionActionV1::Rollback,
            _ => {
                return Err(invalid(
                    "explicit adopt/defer/retain/rollback action required",
                ))
            }
        };
        let candidate = parse_hex::<64>(args.take("--version-commitment")?)?;
        let review = parse_hex::<64>(args.take("--local-review")?)?;
        args.finish()?;
        let setup = common.setup()?;
        let expected = common.read_floor(&expected_path)?;
        let mut owner = common.open(&setup.policy)?;
        let receipt = owner.decide(request, &expected, action, candidate, review)?;
        // A reconciled request can return an older receipt. The exported floor
        // must be the current journal observation, never that receipt's after.
        Ok(output("decide", &owner.snapshot()?, receipt_json(&receipt)))
    }

    fn verify(mut args: Args<'_>, common: &Common, started: Instant) -> Result<Value> {
        let candidate_path = args.path("--candidate")?;
        let expected_path = args.path("--expected-snapshot")?;
        let execution_path = args.path("--execution-file")?;
        let cache_path = args.path("--cache")?;
        let milliseconds = args.take("--read-ms")?;
        let read_ms: u64 = milliseconds.parse()?;
        if read_ms == 0 || read_ms > 60_000 || read_ms.to_string() != milliseconds {
            return Err(invalid("read-ms must be canonical decimal in 1..=60000"));
        }
        args.finish()?;
        let deadline = started
            .checked_add(Duration::from_millis(read_ms))
            .ok_or_else(|| invalid("verification deadline"))?;
        let setup = common.setup()?;
        let candidate = version(&candidate_path)?;
        let expected = common.read_floor(&expected_path)?;
        let execution: ExecutionFile = read_operator_json(&execution_path, 4096)?;
        let current_execution = execution.boundary();
        setup.policy.boundary().verify_version(&candidate)?;
        // Mutable version-specific identities are bound by the selected TCV1.
        // Budgets come from the independent policy and immutable anchor.
        let model = loader(
            candidate.model().closure(),
            setup.model_bytes,
            setup.model_chunks,
        );
        let environment = loader(
            candidate.environment(),
            setup.environment_bytes,
            setup.environment_chunks,
        );
        let expected_loader = CellVersionLoaderContextV1 {
            commitment: candidate.commitment(),
            model: &model,
            environment: &environment,
        };
        let limits = CellReleaseLimitsV1 {
            max_payload_bytes: setup
                .model_bytes
                .checked_add(setup.environment_bytes)
                .ok_or_else(|| invalid("verification byte budget overflow"))?,
            max_chunks: setup
                .model_chunks
                .checked_add(setup.environment_chunks)
                .ok_or_else(|| invalid("verification chunk budget overflow"))?,
            deadline,
        };
        let cache = CellStoreV1::open_read_only(&cache_path)?;
        let mut owner = common.open(&setup.policy)?;
        let readback =
            owner.with_selected_guard(&expected, &candidate, &current_execution, || {
                candidate.verify_cached(&cache, &expected_loader, limits)
            })?;
        Ok(output(
            "verify-selected",
            &owner.snapshot()?,
            json!({
                "verified_snapshot": snapshot_json(&expected),
                "candidate": hex(&readback.commitment),
                "model_root": hex(&readback.model_root),
                "environment_closure": hex(&readback.environment_closure),
                "manifests": readback.manifests,
                "payload_bytes": readback.payload_bytes,
                "chunks": readback.chunks,
                "payload_bytes_verified": true,
                "safe_tensor_parser_executed": false,
                "host_execution_attested": false
            }),
        ))
    }

    struct Common {
        owner: PathBuf,
        policy: PathBuf,
        anchor: PathBuf,
        floor: Option<PathBuf>,
    }

    struct Setup {
        policy: CellAdoptionPolicyV1,
        model_bytes: u64,
        model_chunks: u64,
        environment_bytes: u64,
        environment_chunks: u64,
    }

    impl Common {
        fn setup(&self) -> Result<Setup> {
            let config: PolicyFile = read_operator_json(&self.policy, 65_536)?;
            if config.schema != "trnm.cell.adoption.policy.v1" {
                return Err(invalid("adoption policy JSON schema"));
            }
            let anchor = CellVersionManifestV1::decode(&read_operator_file(
                &self.anchor,
                MAX_CELL_VERSION_BYTES_V1,
            )?)?;
            let boundary = CellModelUpdateBoundaryV1::new(
                &anchor,
                config.mutable_roles.iter().map(MutableRole::role).collect(),
                config.execution.boundary(),
                config.max_model_payload_bytes,
                config.max_model_chunks,
            )?;
            let policy = CellAdoptionPolicyV1::new(
                config.node_id.0,
                config.policy_id.0,
                config.scope.0,
                boundary,
            )?;
            let mut environment_bytes = 0_u64;
            let mut environment_chunks = 0_u64;
            for manifest in anchor.manifests().iter().filter(|manifest| {
                anchor
                    .environment()
                    .release()
                    .cells()
                    .contains(&manifest.id())
            }) {
                environment_bytes = environment_bytes
                    .checked_add(manifest.size())
                    .ok_or_else(|| invalid("anchor environment byte overflow"))?;
                environment_chunks = environment_chunks
                    .checked_add(manifest.chunks().len() as u64)
                    .ok_or_else(|| invalid("anchor environment chunk overflow"))?;
            }
            Ok(Setup {
                policy,
                model_bytes: config.max_model_payload_bytes,
                model_chunks: config.max_model_chunks,
                environment_bytes,
                environment_chunks,
            })
        }

        fn read_floor(&self, path: &Path) -> Result<CellAdoptionSnapshotV1> {
            let parent = self
                .owner
                .parent()
                .ok_or_else(|| invalid("owner database parent"))?
                .canonicalize()?;
            if path.canonicalize()?.starts_with(&parent) {
                return Err(invalid("recovery floor must be supplied outside the owner database directory; independent custody is still required"));
            }
            let value: FloorFile = read_operator_json(path, 4096)?;
            if value.schema != "trnm.cell.adoption.recovery-floor.v1" {
                return Err(invalid("adoption recovery floor JSON schema"));
            }
            let bytes = parse_hex_bytes(&value.snapshot_tas1)?;
            Ok(CellAdoptionSnapshotV1::decode(&bytes)?)
        }

        fn open(&self, policy: &CellAdoptionPolicyV1) -> Result<CellAdoptionOwnerV1> {
            match &self.floor {
                None => Ok(CellAdoptionOwnerV1::create(&self.owner, policy)?),
                Some(path) => Ok(CellAdoptionOwnerV1::open(
                    &self.owner,
                    policy,
                    &self.read_floor(path)?,
                )?),
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PolicyFile {
        schema: String,
        node_id: Hex<32>,
        policy_id: Hex<32>,
        scope: Hex<32>,
        execution: ExecutionFile,
        mutable_roles: Vec<MutableRole>,
        max_model_payload_bytes: u64,
        max_model_chunks: u64,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecutionFile {
        network: Hex<32>,
        consensus: Hex<32>,
        fees: Hex<32>,
        root_authority: Hex<32>,
        node_software: Hex<32>,
        protocol_configuration: Hex<32>,
    }

    impl ExecutionFile {
        fn boundary(&self) -> CellExecutionBoundaryV1 {
            CellExecutionBoundaryV1 {
                network: self.network.0,
                consensus: self.consensus.0,
                fees: self.fees.0,
                root_authority: self.root_authority.0,
                node_software: self.node_software.0,
                protocol_configuration: self.protocol_configuration.0,
            }
        }
    }

    #[derive(Deserialize)]
    enum MutableRole {
        Base,
        Adapter,
        Router,
    }
    impl MutableRole {
        fn role(&self) -> CellFileRoleV1 {
            match self {
                Self::Base => CellFileRoleV1::Base,
                Self::Adapter => CellFileRoleV1::Adapter,
                Self::Router => CellFileRoleV1::Router,
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EvidenceFile {
        schema: String,
        evaluation: Option<Hex<64>>,
        reproduction: Option<Hex<64>>,
        chain_observation: Option<Hex<64>>,
        settlement: Option<Hex<64>>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FloorFile {
        schema: String,
        snapshot_tas1: String,
    }

    struct Hex<const N: usize>([u8; N]);
    impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
        fn deserialize<D: Deserializer<'de>>(
            deserializer: D,
        ) -> std::result::Result<Self, D::Error> {
            let value = String::deserialize(deserializer)?;
            parse_hex::<N>(&value)
                .map(Self)
                .map_err(serde::de::Error::custom)
        }
    }

    fn loader(closure: &CellReleaseClosureV1, bytes: u64, chunks: u64) -> CellLoaderContextV1 {
        CellLoaderContextV1 {
            closure_id: closure.id(),
            context: closure.release().context().clone(),
            selected_generation: closure.selected_generation(),
            loader_profile: closure.loader_profile(),
            required_roles: closure
                .files()
                .iter()
                .map(|f| f.role)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            max_payload_bytes: bytes,
            max_chunks: chunks,
        }
    }

    fn snapshot_json(snapshot: &CellAdoptionSnapshotV1) -> Value {
        json!({
            "policy_digest": hex(&snapshot.policy_digest()),
            "revision": snapshot.revision(),
            "selected": snapshot.selected().map(|v| hex(&v)),
            "history_digest": hex(&snapshot.history_digest())
        })
    }

    fn output(command: &str, snapshot: &CellAdoptionSnapshotV1, result: Value) -> Value {
        json!({
            "schema": "trnm.cell.adoption.command.v1",
            "command": command,
            "snapshot": snapshot_json(snapshot),
            "recovery_floor": {
                "schema": "trnm.cell.adoption.recovery-floor.v1",
                "snapshot_tas1": hex(&snapshot.encode())
            },
            "result": result,
            "independent_recovery_floor_required": true,
            "use_authority": false,
            "final_use_granted": false,
            "independent_evaluation_verified": false,
            "chain_confirmation_verified": false
        })
    }

    fn receipt_json(receipt: &CellAdoptionReceiptV1) -> Value {
        let action = match receipt.action() {
            CellAdoptionActionV1::Adopt => "adopt",
            CellAdoptionActionV1::Defer => "defer",
            CellAdoptionActionV1::Retain => "retain",
            CellAdoptionActionV1::Rollback => "rollback",
        };
        json!({
            "request_id": hex(&receipt.request_id()),
            "action": action,
            "candidate": hex(&receipt.candidate()),
            "before": snapshot_json(receipt.before()),
            "after": snapshot_json(receipt.after()),
            "local_review": hex(&receipt.review_commitment()),
            "evidence_set_commitment": hex(&receipt.evidence_set_commitment())
        })
    }

    fn version(path: &Path) -> Result<CellVersionManifestV1> {
        Ok(CellVersionManifestV1::decode(&read_file(
            path,
            MAX_CELL_VERSION_BYTES_V1,
        )?)?)
    }

    fn read_json<T: DeserializeOwned>(path: &Path, limit: usize) -> Result<T> {
        Ok(serde_json::from_slice(&read_file(path, limit)?)?)
    }

    fn read_operator_json<T: DeserializeOwned>(path: &Path, limit: usize) -> Result<T> {
        Ok(serde_json::from_slice(&read_operator_file(path, limit)?)?)
    }

    /// Explicit operator inputs have a different filesystem trust boundary
    /// from public candidate/evidence bytes. This excludes other-user writes;
    /// it does not authenticate a same-login owner or provide rollback custody.
    fn read_operator_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
        if !path.is_absolute() {
            return Err(invalid("absolute operator input path required"));
        }
        let parent_path = path
            .parent()
            .ok_or_else(|| invalid("operator input parent"))?;
        if parent_path.canonicalize()? != parent_path {
            return Err(invalid("canonical operator input parent required"));
        }
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(parent_path)?;
        let parent_identity = parent.metadata()?;
        check_operator_parent(&parent_identity)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let before = file.metadata()?;
        check_operator_metadata(&before, limit)?;
        let stamp = FileStamp::new(&before);
        check_operator_identity(
            path,
            &file,
            &stamp,
            parent_path,
            &parent,
            &parent_identity,
            limit,
        )?;
        let mut bytes = Vec::new();
        (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > limit || bytes.len() as u64 != before.len() {
            return Err(invalid("operator input size changed during read"));
        }
        check_operator_identity(
            path,
            &file,
            &stamp,
            parent_path,
            &parent,
            &parent_identity,
            limit,
        )?;
        Ok(bytes)
    }

    fn check_operator_parent(metadata: &Metadata) -> Result<()> {
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(invalid("private operator input parent owner/mode"));
        }
        Ok(())
    }

    fn check_operator_metadata(metadata: &Metadata, limit: usize) -> Result<()> {
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || !matches!(metadata.mode() & 0o7777, 0o400 | 0o600)
            || metadata.len() > limit as u64
        {
            return Err(invalid("private bounded operator input owner/mode/links"));
        }
        Ok(())
    }

    fn check_operator_identity(
        path: &Path,
        file: &File,
        expected: &FileStamp,
        parent_path: &Path,
        parent: &File,
        original_parent: &Metadata,
        limit: usize,
    ) -> Result<()> {
        for metadata in [file.metadata()?, fs::symlink_metadata(path)?] {
            check_operator_metadata(&metadata, limit)?;
            if &FileStamp::new(&metadata) != expected {
                return Err(invalid("operator input changed during read"));
            }
        }
        for metadata in [parent.metadata()?, fs::symlink_metadata(parent_path)?] {
            check_operator_parent(&metadata)?;
            if (metadata.dev(), metadata.ino()) != (original_parent.dev(), original_parent.ino()) {
                return Err(invalid("operator input parent replaced during read"));
            }
        }
        Ok(())
    }

    #[derive(Eq, PartialEq)]
    struct FileStamp {
        device: u64,
        inode: u64,
        bytes: u64,
        links: u64,
        uid: u32,
        gid: u32,
        mode: u32,
        modified: i64,
        modified_ns: i64,
        changed: i64,
        changed_ns: i64,
    }

    impl FileStamp {
        fn new(value: &Metadata) -> Self {
            Self {
                device: value.dev(),
                inode: value.ino(),
                bytes: value.len(),
                links: value.nlink(),
                uid: value.uid(),
                gid: value.gid(),
                mode: value.mode(),
                modified: value.mtime(),
                modified_ns: value.mtime_nsec(),
                changed: value.ctime(),
                changed_ns: value.ctime_nsec(),
            }
        }
    }

    fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > limit as u64 {
            return Err(invalid("bounded regular input file required"));
        }
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(invalid("input file grew beyond byte bound"));
        }
        Ok(bytes)
    }

    fn parse_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
        if value.len() != N * 2 {
            return Err(invalid("exact hexadecimal byte width required"));
        }
        parse_hex_bytes(value)?
            .try_into()
            .map_err(|_| invalid("hexadecimal width"))
    }

    fn parse_hex_bytes(value: &str) -> Result<Vec<u8>> {
        if value.is_empty()
            || !value.len().is_multiple_of(2)
            || !value
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        {
            return Err(invalid("canonical lowercase hexadecimal required"));
        }
        let nibble = |v: u8| {
            if v.is_ascii_digit() {
                v - b'0'
            } else {
                v - b'a' + 10
            }
        };
        Ok(value
            .as_bytes()
            .chunks_exact(2)
            .map(|v| nibble(v[0]) * 16 + nibble(v[1]))
            .collect())
    }

    fn hex(value: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(value.len() * 2);
        for &byte in value {
            out.push(DIGITS[(byte >> 4) as usize] as char);
            out.push(DIGITS[(byte & 15) as usize] as char);
        }
        out
    }

    fn arguments() -> Result<Vec<String>> {
        let mut args = Vec::new();
        let mut bytes = 0_usize;
        for value in std::env::args_os().skip(1) {
            let value = value
                .into_string()
                .map_err(|_| invalid("UTF-8 arguments required"))?;
            bytes = bytes
                .checked_add(value.len())
                .ok_or_else(|| invalid("argument byte bound"))?;
            if args.len() >= 64 || value.len() > 4096 || bytes > 32_768 {
                return Err(invalid("argument count/byte bound"));
            }
            args.push(value);
        }
        Ok(args)
    }

    struct Args<'a>(BTreeMap<&'a str, &'a str>);
    impl<'a> Args<'a> {
        fn new(values: &'a [String]) -> Result<Self> {
            if !values.len().is_multiple_of(2) {
                return Err(invalid("every named argument requires one value"));
            }
            let mut args = BTreeMap::new();
            for pair in values.chunks_exact(2) {
                if !pair[0].starts_with("--")
                    || pair[1].is_empty()
                    || args.insert(pair[0].as_str(), pair[1].as_str()).is_some()
                {
                    return Err(invalid("named arguments must be nonempty and unique"));
                }
            }
            Ok(Self(args))
        }
        fn take(&mut self, name: &str) -> Result<&'a str> {
            self.0
                .remove(name)
                .ok_or_else(|| invalid(&format!("required argument {name}")))
        }
        fn optional(&mut self, name: &str) -> Option<&'a str> {
            self.0.remove(name)
        }
        fn path(&mut self, name: &str) -> Result<PathBuf> {
            Ok(PathBuf::from(self.take(name)?))
        }
        fn finish(self) -> Result<()> {
            if self.0.is_empty() {
                Ok(())
            } else {
                Err(invalid("unknown local adoption argument"))
            }
        }
    }

    fn invalid(message: &str) -> Box<dyn Error> {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, message).into()
    }
}
