//! Fresh SP27-05 entry: an explicit local payload fault, never a V1 alias.

use super::*;
use paged::CustodyProfile;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultSpec {
    schema: String,
    source: Spec,
    custody: paged::FaultProfileV2,
    expected: PagedExpected,
}

impl FaultSpec {
    fn validate(&self) -> Result<()> {
        check(
            self.schema == "trnm.sp27-05-payload-fault-source.v1"
                && self.source.schema == "trnm.cell-sealed-research-source.v2",
            "explicit SP27-05 payload-fault source namespace required",
        )?;
        self.custody.validate()?;
        self.expected.validate()?;
        check(
            digest(&self.source.operation)? != [0; 32]
                && self.source.operation != self.expected.previous_operation,
            "fresh SP27-05 operation differs from previous operation",
        )
    }
}

pub fn run_payload_faults() -> Result<()> {
    let arguments: Vec<_> = std::env::args().collect();
    check(
        arguments.len() == 3,
        "usage: sp27_storage_payload_faults_v1 SOURCE_JSON INDEPENDENT_SHA256",
    )?;
    let raw = read_pinned(
        &Input {
            path: PathBuf::from(&arguments[1]),
            sha256: arguments[2].clone(),
        },
        128 * 1024,
    )?;
    let input: FaultSpec = serde_json::from_slice(&raw)?;
    input.validate()?;
    let spec = &input.source;
    check(
        spec.output.is_absolute(),
        "absolute create-only output required",
    )?;
    fs::create_dir(&spec.output)?;
    fs::set_permissions(&spec.output, fs::Permissions::from_mode(0o700))?;
    write_new(&spec.output.join("original-sp27-source-inputs.json"), &raw)?;
    let mut report = json!({
        "schema":"trnm.sp27-05-payload-fault-native.v1","stage":"initial",
        "source_input_sha256":arguments[2],"storage_profile":input.custody.schema(),
        "original_hepta_owner_used":false,"hepta_final_use":false,
        "installation_authorized":false,"m12_funding_admitted":false,
        "independent_operators":false,"production_activation":false,
        "loopback_only":true,"typed_snapshot_admitted":false,
        "composition_worker_executed":false,"actual_model_run":"not_started",
        "original_version_pins_verified":false,"original_transport_plan_verified":false,
        "original_seconds":spec.seconds,"snapshot_payload_limit":spec.max_snapshot_bytes,
        "worker_rss_limit":spec.runtime_rss_bytes,"threads":spec.threads,
        "scope":"single-host diagnostic fault experiment; local payload faults only"
    });
    let started = Instant::now();
    let result = observe_with_custody(spec, &mut report, Some((&input.custody, &input.expected)));
    report["entry_elapsed_ms"] = json!(started.elapsed().as_millis());
    report["passed"] = json!(result.is_ok());
    if let Err(error) = &result {
        report["error"] = json!(error.to_string());
    }
    write_new(
        &spec.output.join("native-result.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    println!("{}", serde_json::to_string(&report)?);
    result
}
