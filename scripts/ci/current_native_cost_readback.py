#!/usr/bin/env python3
"""Read two exact frozen 6f native archives; never execute their contents."""
import hashlib, json, os, re, urllib.error, urllib.parse, urllib.request, uuid, zipfile
from pathlib import Path, PurePosixPath
from current_native_sql_delta import sql_commit_delta, sql_commit_delta_selfcheck
from current_native_decode_delta import decode_delta, _self_test as decode_delta_selfcheck

REPO = "TrillionniumFoundation/Trillionnium-Chain"
BRANCH = "fix/chain-retained-failure-readback-20261104"
TARGETS = json.loads(r'''[{"id":13295252045,"name":"pon-fixed-host-root-f0-x64-head-6f458c4fbf07a0a44d7d7a6f451aa960c1b0a029-1","size":17423749,"digest":"sha256:b0d584b01e51bda9d5481aeb8c2a430dcf785c7f5eb2357939642291a4dfceca","run":41771598282,"job":126382307968,"head":"6f458c4fbf07a0a44d7d7a6f451aa960c1b0a029","tree":"76d3b416eccc6a810634062e036f646f22bffc76","kind":"f0","report_schema":"native-public-v3-fixed-host-root-f0-v1","phase_modes":["baseline","valid-work-root"]},{"id":13295139319,"name":"pon-native-campaign-x64-head-release-6f458c4fbf07a0a44d7d7a6f451aa960c1b0a029-1","size":56882314,"digest":"sha256:ac3f2a7bcbe21c6b9943e7c136959df4d09ed485f5ae9bb116294d0df99ac488","run":41771598274,"job":126382436057,"head":"6f458c4fbf07a0a44d7d7a6f451aa960c1b0a029","tree":"76d3b416eccc6a810634062e036f646f22bffc76","kind":"campaign","report_schema":"native-public-v3-separate-process-campaign-v2","phase_modes":["baseline","from-zero","late-product"]}]''')
ROOT = Path(os.environ["READBACK_OUT"])
API = "https://api.github.com/repos/" + REPO
TOKEN = os.environ["GH_TOKEN"]
MAX_METADATA = 2 * 1024 * 1024
MAX_MEMBER = 32 * 1024 * 1024
MAX_SELECTED = 160 * 1024 * 1024
MAX_MEMBERS = 25000
MAX_STDOUT = 70000

class Refused(Exception):
    pass

def require(condition, label):
    if not condition:
        raise Refused(label)

require(os.environ["GITHUB_REPOSITORY"] == REPO, "REPOSITORY")
require(os.environ["GITHUB_REF"] == "refs/heads/" + BRANCH, "REF")
require(os.environ["GITHUB_EVENT_NAME"] == "push", "EVENT")
require(len(TARGETS) == len({x["id"] for x in TARGETS}) == 2, "TARGETS")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

AUTH = urllib.request.build_opener(NoRedirect())

def request_api(path):
    require(path.startswith("/actions/"), "API_PATH")
    req = urllib.request.Request(API + path, headers={
        "Authorization": "Bearer " + TOKEN,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "trnm-retained-failure-readback-v1",
    })
    return AUTH.open(req, timeout=60)

def read_json(path):
    with request_api(path) as response:
        raw = response.read(MAX_METADATA + 1)
    require(len(raw) <= MAX_METADATA, "METADATA_LIMIT")
    return json.loads(raw)

def write_json(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with path.open("xb") as stream:
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()

def archive(target, destination):
    # Only the GitHub API receives Authorization. The signed artifact URL is
    # fetched using a new request with no token and is never printed or saved.
    try:
        response = request_api("/actions/artifacts/" + str(target["id"]) + "/zip")
    except urllib.error.HTTPError as error:
        require(error.code in (301, 302, 303, 307, 308), "ARCHIVE_REDIRECT_STATUS")
        location = error.headers.get("Location")
        error.close()
        require(isinstance(location, str), "ARCHIVE_LOCATION")
        parsed = urllib.parse.urlsplit(location)
        require(parsed.scheme == "https" and parsed.hostname
                and parsed.username is None and parsed.password is None,
                "ARCHIVE_LOCATION_SCHEME")
        unsigned = urllib.request.Request(location, headers={
            "User-Agent": "trnm-retained-failure-readback-v1"})
        response = urllib.request.build_opener(NoRedirect()).open(unsigned, timeout=120)
    digest = hashlib.sha256()
    total = 0
    with response, destination.open("xb") as stream:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            require(total <= target["size"], "ARCHIVE_SIZE_OVERRUN")
            digest.update(block)
            stream.write(block)
    require(total == target["size"], "ARCHIVE_SIZE")
    require("sha256:" + digest.hexdigest() == target["digest"], "ARCHIVE_DIGEST")
    return total

MATCH = re.compile(
    r"^test result:|^failures:|^thread .*panicked|^test .+ \.\.\. FAILED"
    r"|^error(?:\[[^]]+\])?:|^Error:|^Caused by:")
KEY = re.compile(
    r"confirm|denominator|planned|failure|criteria|criterion|lifetime|shutdown"
    r"|server_exit|returncode|exit_code|head_sha|tested_commit|tested_tree"
    r"|source_sha|physical|qualification|activation|passed|unobserved"
    r"|deadline|cancelled|pending|unknown|elapsed|duration|host_errors"
    r"|observed|scheduled|within|before_original|slo|success|known_empty|^mode$|^number$|^code$|^kind$"
    r"|^schema$|^status$|^phase$|^name$|^label$|^reason$|^error$")

# The first F0 raw member has no separately published member digest in the
# original console. Its entire fixed ZIP is authenticated before it is read;
# record its actual complete member digest without inventing a prior pin.
NATIVE_REPORTS = {int(key): value for key, value in json.loads(r'''{"13295252045":{"execution/raw/report.json":[null,null]},"13295139319":{"run-1-raw/report.json":[null,"5906c5088d58e33adaa41da45f97abadb6765bb77ac75cf87e86809002a7de2a"],"run-2-raw/report.json":[null,"91066a546d4457985cdbfa51d00db34245c9d81197cfd6c77cedc54b502771cf"],"run-3-raw/report.json":[null,"832196caef64d6cde8c28217a05c316feaea36bc6db17694c59c266e02c7ae14"]}}''').items()}
SOURCE_MEMBERS = frozenset(("source-before.json", "source-after.json"))
EXTRA_KEY = re.compile(
    r"^(?:prepared|selector_invocation_attempted|head|tree|source_verified|commit"
    r"|binary_sha256_before|binary_sha256_after|format_passed|execution_finished"
    r"|source_recompiled|PREPARATION_OUTCOME|ARM_OUTCOME|EXECUTION_OUTCOME"
    r"|FINALIZATION_OUTCOME|F0_SOURCE_AFTER_STATUS)$")
SQL_DELTA_COLUMNS = (
    "site", "status", "cohort", "reason", "wall_reason", "cpu_reason",
    "complete_wall_ns", "complete_cpu_ns", "calls_started", "calls_returned",
    "calls_succeeded", "calls_failed", "calls_abandoned", "calls_unwinding",
    "cpu_ns_known_sum", "wall_unknown_calls", "cpu_known_calls", "cpu_unknown_calls",
    "ended_calls", "calls_in_flight", "wall_ns")
DECODE_DELTA_COLUMNS = (
    "calls", "exact_hits", "original_decodes", "retained",
    "bounded_probe_refusals", "borrow_conflicts")

def compact_sql(value):
    rows = []
    for site in value["sites"]:
        delta = site.get("delta")
        rows.append([site.get(key) if index < 8 else
                     delta.get(key) if isinstance(delta, dict) else None
                     for index, key in enumerate(SQL_DELTA_COLUMNS)])
    return {"status": value["status"], "rows": rows}

def compact_decode(value):
    delta = value.get("delta")
    return {"status": value["status"], "reason": value["reason"],
            "delta": [delta[key] for key in DECODE_DELTA_COLUMNS] if isinstance(delta, dict) else None,
            "retained_before": value["retained_before"], "retained_after": value["retained_after"],
            "sql_reads_inferred": False, "timing_attributed": False}

def selected(name, target):
    if name in NATIVE_REPORTS[target["id"]] or name in SOURCE_MEMBERS:
        return True
    if target["kind"] == "f0":
        return name in {
            "finalization/result.json", "execution/results.json", "prepared/prepared.json",
            "workflow-predeclared.json", "workflow-outcomes.json",
            "execution/source-before.json", "execution/source-after.json",
            "execution/supplement.stdout.log", "execution/supplement.stderr.log",
            "systemd-run.stdout.log", "systemd-run.stderr.log", "finalization.stdout.log",
            "finalization.stderr.log", "preflight.log"}
    return (name in {"results.json", "preflight.log"}
            or re.fullmatch(r"run-[123]-phase-readback\.json", name) is not None
            or re.fullmatch(r"run-[123]\.(?:stdout|stderr)\.log", name) is not None)

def priority(info):
    if any(info.filename in reports for reports in NATIVE_REPORTS.values()):
        return (0, info.filename)
    if info.filename in ("finalization/result.json", "execution/results.json", "results.json"):
        return (1, info.filename)
    if info.filename in SOURCE_MEMBERS:
        return (2, info.filename)
    return (3, info.filename)

NATIVE_STAGE_NAMES = (
    "record", "packet", "delta", "verify_state", "verify_history", "publish",
    "read_active", "state_at", "execute", "admission", "activation",
    "complete_commitment", "complete_state_root", "account_graph",
    "persisted_state_root", "execution_parent_binding",
)
NATIVE_TOTAL_FIELDS = (
    "calls", "wall_ns", "cpu_known_calls", "cpu_unknown_calls", "cpu_ns", "unwinding_calls",
)
NATIVE_SNAPSHOT_KEYS = (
    "native_history_arithmetic_before", "native_history_arithmetic_after",
    "client_native_history_arithmetic_before", "client_native_history_arithmetic_after",
)
def f0_terminal_projection(value, target, record):
    # Copy the current F0 producer's six fixed rows and cleanup facts.
    # These are original observations, not newly recomputed verdicts.
    require(isinstance(value, dict), "F0_TERMINAL_OBJECT")
    final = record["member"] == "finalization/result.json"
    expected = "fixed-host-root-f0-finalization-v1" if final else "pon-fixed-host-root-f0-execution-v1"
    require(value.get("schema") == expected, "F0_TERMINAL_SCHEMA")
    denominator = value.get("denominator") if final else value
    denominator = denominator if isinstance(denominator, dict) else {}
    raw_rounds = denominator.get("all_planned_rounds")
    round_fields = (
        "phase", "round", "scheduled_offset_ns", "actual_started_ns", "actual_ended_ns",
        "elapsed_from_scheduled_ns", "start_lateness_from_schedule_ns",
        "end_lateness_from_four_second_deadline_ns", "observed_exactly_once",
        "confirmed_inside_original_window", "four_second_slo_met",
    )
    rounds_available = (isinstance(raw_rounds, list) and len(raw_rounds) == 6
                        and all(isinstance(row, dict) for row in raw_rounds))
    raw_services = value.get("services")
    service_fields = (
        "phase", "service", "ownership_validated", "cleanup_attempted", "remaining",
        "known_empty", "failure", "observed_empty_at_readback",
        "controller_terminal_before_phase_observation",
    )
    services_available = (isinstance(raw_services, list) and len(raw_services) == 3
                          and all(isinstance(row, dict) for row in raw_services))
    projection = {
        "schema": "trnm-retained-f0-terminal-readback-v1",
        "artifact": target["id"], "measured_head": target["head"],
        "measured_run": target["run"], "measured_job": target["job"],
        "member": record["member"], "member_bytes": record["bytes"], "member_sha256": record["sha256"],
        "original_fields": {key: value.get(key) for key in (
            "schema", "head", "tree", "failure", "native_result_failure", "report_validation_failure",
            "complete_success", "controller_resources_complete", "all_services_known_empty")},
        "denominator_fields": {key: denominator.get(key) for key in (
            "planned_confirmations", "planned_business_packet_exposures", "four_second_slo_successes",
            "report_observed", "native_result_observed", "native_complete_success",
            "controller_resources_complete", "controller_resource_failure",
            "report_failure", "native_result_failure")},
        "step_returncode": (value["step"].get("returncode")
                            if isinstance(value.get("step"), dict) else None),
        "rounds_available": rounds_available,
        "all_planned_rounds": [{key: row.get(key) for key in round_fields} for row in raw_rounds]
                              if rounds_available else None,
        "services_available": services_available,
        "services": [{key: row.get(key) for key in service_fields} for row in raw_services]
                    if services_available else None,
        "source_tests_executed": False, "acceptance_granted": False, "production_activation": False,
        "scope": "Literal retained F0 denominator and cleanup fields; missing values remain null; no changed confirmation threshold or new native verdict; all original selected fields and ZIP retained.",
    }
    scalar_fields(projection)
    rendered = json.dumps(projection, sort_keys=True, separators=(",", ":")) + "\n"
    require(len(rendered) <= 12000, "F0_CONSOLE_LIMIT")
    return projection, rendered

def console_json(target, name, fields):
    # Console limits affect presentation only. Every selected field and
    # the exact original member remain in the retained readback/archive.
    shallow = [field for field in fields if field["pointer"].count("/") <= 6]
    preferred = re.compile(r"confirm|planned|scheduled|criteria|failure|returncode|exit_code|tested_")
    shallow.sort(key=lambda field: (0 if preferred.search(field["pointer"]) else 1,
                                     field["pointer"].count("/"), field["pointer"]))
    shown = []
    for field in shallow:
        row = dict(field)
        if isinstance(row["value"], str) and len(row["value"]) > 512:
            row["value"] = row["value"][:512]
            row["value_truncated"] = True
        proposal = shown + [row]
        if len(json.dumps(proposal, sort_keys=True)) > 12000:
            break
        shown = proposal
    return json.dumps({"artifact": target["id"], "member": name,
                       "fields": shown, "console_fields_omitted": len(fields) - len(shown),
                       "console_depth_limit": 6,
                       "original_member_retained": True}, sort_keys=True) + "\n"

def bounded_console(excerpt, remaining, target, name):
    parts = excerpt.splitlines(keepends=True)
    def marker(count):
        return json.dumps({"artifact": target["id"], "member": name,
                           "console_lines_omitted": count,
                           "original_excerpt_and_member_retained": True},
                          sort_keys=True) + "\n"
    allowance = max(0, remaining - len(marker(len(parts))))
    kept = []
    used = 0
    for part in parts:
        if used + len(part) > allowance:
            break
        kept.append(part)
        used += len(part)
    omitted = len(parts) - len(kept)
    rendered = "".join(kept)
    if omitted:
        suffix = marker(omitted)
        if len(rendered) + len(suffix) <= remaining:
            rendered += suffix
    require(len(rendered) <= remaining, "CONSOLE_BOUND")
    return rendered, len(kept), omitted

def scalar_fields(value, extra_key=None):
    found = []
    stack = [("", value)]
    visited = 0
    while stack:
        path, item = stack.pop()
        visited += 1
        require(visited <= 200000, "JSON_NODE_LIMIT")
        if isinstance(item, dict):
            for key, child in reversed(list(item.items())):
                point = path + "/" + key.replace("~", "~0").replace("/", "~1")
                if isinstance(child, (dict, list)):
                    stack.append((point, child))
                elif KEY.search(key) or (extra_key is not None and extra_key.search(key)):
                    found.append({"pointer": point, "value": child})
        elif isinstance(item, list):
            for index in range(len(item) - 1, -1, -1):
                stack.append((path + "/" + str(index), item[index]))
    return found

def native_stage_delta(before, after):
    def unknown(reason):
        return {"status": "unknown", "reason": reason, "rows": None}
    if not all(isinstance(x, dict) for x in (before, after)):
        return unknown("snapshot_missing_or_null")
    for snapshot in (before, after):
        if snapshot.get("schema") != "pon-native-history-arithmetic-observation-v1":
            return unknown("snapshot_schema")
        if snapshot.get("stage_observation_failed") is not False:
            return unknown("stage_observation_failed_or_missing")
        if snapshot.get("has_consensus_authority") is not False:
            return unknown("unexpected_authority_field")
        rows = snapshot.get("stages")
        if (not isinstance(rows, list) or len(rows) != len(NATIVE_STAGE_NAMES)
                or any(not isinstance(row, dict) for row in rows)
                or [row.get("stage") for row in rows] != list(NATIVE_STAGE_NAMES)):
            return unknown("stage_identity_or_availability")
    rows = []
    for index, name in enumerate(NATIVE_STAGE_NAMES):
        values = []
        for snapshot in (before, after):
            totals = snapshot["stages"][index].get("totals")
            if not isinstance(totals, dict) or set(totals) != set(NATIVE_TOTAL_FIELDS):
                return unknown("stage_totals_fields:" + name)
            row = [totals[key] for key in NATIVE_TOTAL_FIELDS]
            if any(type(n) is not int or not 0 <= n < (1 << 64) - 1 for n in row):
                return unknown("invalid_or_saturated_counter:" + name)
            if row[0] != row[2] + row[3] or row[5] > row[0]:
                return unknown("stage_call_accounting:" + name)
            values.append(row)
        delta = [end - start for start, end in zip(*values)]
        if any(n < 0 for n in delta):
            return unknown("counter_regressed:" + name)
        if delta[0] != delta[2] + delta[3] or delta[5] > delta[0]:
            return unknown("delta_call_accounting:" + name)
        if delta[0] == 0 and any(delta[1:]):
            return unknown("counter_changed_without_completed_call:" + name)
        complete_cpu = delta[4] if delta[0] > 0 and delta[3] == 0 else None
        rows.append(delta + [complete_cpu, "observed_calls" if delta[0] else "not_entered"])
    return {"status": "observed", "rows": rows}


def confirmation_projection(phase):
    # Both pinned campaign sources schedule exactly ROUNDS = 3.
    # Their original loop stops after the first unconfirmed round.
    raw = phase.get("confirmations")
    fields = (
        "round", "started_ns", "ended_ns", "confirmed_inside_pressure_window",
        "transaction", "included_block", "tip",
    )
    valid = (
        isinstance(raw, list) and len(raw) <= 3
        and all(isinstance(row, dict)
                and type(row.get("round")) is int and row["round"] == index
                and type(row.get("confirmed_inside_pressure_window")) is bool
                for index, row in enumerate(raw))
    )
    rows = []
    for index in range(3):
        observed = index < len(raw) if valid else None
        row = {"planned_round_index": index, "observed": observed}
        row.update({key: raw[index].get(key) if observed else None for key in fields})
        rows.append(row)
    confirmed = sum(row["confirmed_inside_pressure_window"] for row in raw) if valid else None
    return {
        "schema": "trnm-original-campaign-confirmation-readback-v1",
        "status": "observed" if valid else "unknown",
        "reason": None if valid else "confirmation_array_missing_or_invalid",
        "planned_rounds": 3,
        "observed_rounds": len(raw) if valid else None,
        "confirmed_rounds": confirmed,
        "observed_unconfirmed_rounds": len(raw) - confirmed if valid else None,
        "unobserved_rounds": 3 - len(raw) if valid else None,
        "rounds": rows,
        "scope": "Original confirmed_inside_pressure_window only; unobserved fields remain null; no inferred timestamps or changed window.",
    }

def native_history_projection(value, target, record):
    require(isinstance(value, dict)
            and value.get("schema") == target["report_schema"]
            and value.get("state_backend") == "authenticated-v1", "NATIVE_REPORT_SCHEMA")
    phases = value.get("phases")
    modes = target["phase_modes"]
    require(isinstance(phases, list) and len(phases) == len(modes)
            and all(isinstance(p, dict) for p in phases)
            and [p.get("mode") for p in phases] == modes, "NATIVE_PHASE_IDENTITIES")
    kept = []
    phase_keys = (
        "mode", "duration_seconds", "state_backend", "finite_phase_criteria_met",
        "all_signed_rounds_confirmed_in_window", "genuine_budget_depletion_observed",
        "startup_or_campaign_error", "verifier_errors", "observer_complete",
        "receiver_client_state_equal", "client_observation_scope",
    )
    for index, phase in enumerate(phases):
        row = {key: phase[key] for key in phase_keys if key in phase}
        row["scheduled_phase_index"] = index
        row["confirmation_readback"] = confirmation_projection(phase)
        row["snapshot_keys_present"] = [key for key in NATIVE_SNAPSHOT_KEYS if key in phase]
        row["snapshots"] = {key: phase.get(key) for key in NATIVE_SNAPSHOT_KEYS}
        row["receiver_stage_deltas"] = native_stage_delta(
            phase.get(NATIVE_SNAPSHOT_KEYS[0]), phase.get(NATIVE_SNAPSHOT_KEYS[1]))
        row["client_stage_deltas"] = native_stage_delta(
            phase.get(NATIVE_SNAPSHOT_KEYS[2]), phase.get(NATIVE_SNAPSHOT_KEYS[3]))
        for role, first in (("receiver", 0), ("client", 2)):
            before = phase.get(NATIVE_SNAPSHOT_KEYS[first])
            after = phase.get(NATIVE_SNAPSHOT_KEYS[first + 1])
            row[role + "_sql_commit_delta"] = sql_commit_delta(before, after)
            row[role + "_decode_delta"] = decode_delta(
                before.get("account_node_decode_arithmetic") if isinstance(before, dict) else None,
                after.get("account_node_decode_arithmetic") if isinstance(after, dict) else None)
        kept.append(row)
    projection = {
        "schema": "trnm-current-native-history-sql-decode-cost-readback-v1",
        "artifact": target["id"], "measured_head": target["head"],
        "measured_run": target["run"], "measured_job": target["job"],
        "member": record["member"], "member_bytes": record["bytes"],
        "member_sha256": record["sha256"],
        "finite_experiment_criteria_met": value.get("finite_experiment_criteria_met"),
        "scheduled_phases": len(modes), "stage_names": NATIVE_STAGE_NAMES,
        "sql_delta_columns": SQL_DELTA_COLUMNS, "decode_delta_columns": DECODE_DELTA_COLUMNS,
        "delta_columns": ["calls", "wall_ns", "cpu_known_calls", "cpu_unknown_calls",
                          "cpu_ns_known_sum", "unwinding_calls", "complete_cpu_ns", "observation_status"],
        "phases": kept, "source_tests_executed": False, "acceptance_granted": False,
        "scope": "Before/after cumulative owner counters; setup and final read_active excluded; receiver includes service cleanup, client includes native replay and confirmation; nested costs are not additive; current-thread CPU excludes scoped workers; errors/cancellation are included but stage result codes are unavailable; unknown or unentered CPU is not zero; SQL child measures its original Transaction::commit API including existing error cleanup, not pure fsync. Closed SQL cohorts and unknown values are explicit. Decoder counters are not SQL reads or timing attribution.",
    }
    scalar_fields(projection)  # Keep the original node cap on selected data only.
    compact = {key: item for key, item in projection.items() if key != "phases"}
    compact["phases"] = []
    for phase in kept:
        row = {key: item for key, item in phase.items() if key != "snapshots"}
        for key in ("startup_or_campaign_error", "verifier_errors"):
            if key in row:
                rendered = json.dumps(row[key], sort_keys=True)
                if len(rendered) > 1024:
                    row[key] = {"rendered_prefix": rendered[:1024], "console_truncated": True,
                                "original_value_retained": True}
        for role in ("receiver", "client"):
            row[role + "_sql_commit_delta"] = compact_sql(row[role + "_sql_commit_delta"])
            row[role + "_decode_delta"] = compact_decode(row[role + "_decode_delta"])
        compact["phases"].append(row)
    return projection, compact


# These synthetic controls validate only the reader; they add no native tests.
sql_checks = sql_commit_delta_selfcheck()
require(sql_checks["passed"] == 17, "SQL_READER_SELF_CHECK_COUNT")
require(decode_delta_selfcheck(), "DECODE_READER_SELF_CHECK")
reader_checks = {"schema": "trnm-current-native-cost-reader-selfchecks-v1",
                 "sql": sql_checks, "decode_control_groups_passed": 5,
                 "source_tests_executed": False, "acceptance_granted": False}
write_json(ROOT / "reader-selfchecks.json", reader_checks)
print(json.dumps(reader_checks, sort_keys=True), flush=True)

results = []
had_error = False
for target in TARGETS:
    reports = NATIVE_REPORTS.get(target["id"], {})
    output = ROOT / str(target["id"])
    output.mkdir()
    stage = "metadata"
    printed = 0
    try:
        metadata = read_json("/actions/artifacts/" + str(target["id"]))
        run = read_json("/actions/runs/" + str(target["run"]))
        job = read_json("/actions/jobs/" + str(target["job"]))
        require(metadata["id"] == target["id"] and metadata["name"] == target["name"],
                "ARTIFACT_IDENTITY")
        require(metadata["size_in_bytes"] == target["size"]
                and metadata["digest"] == target["digest"] and not metadata["expired"],
                "ARTIFACT_METADATA")
        require(metadata["workflow_run"]["id"] == run["id"] == job["run_id"] == target["run"],
                "RUN_IDENTITY")
        require(metadata["workflow_run"]["head_sha"] == run["head_sha"] == target["head"],
                "SOURCE_IDENTITY")
        require(job["id"] == target["job"] and job["status"] == "completed"
                and job["conclusion"] == "failure", "ORIGINAL_FAILED_JOB")
        write_json(output / "metadata.json", metadata)
        write_json(output / "run.json", run)
        write_json(output / "job.json", job)
        stage = "archive"
        path = output / "original.zip"
        received = archive(target, path)
        stage = "members"
        records = []
        omitted = []
        selected_bytes = 0
        command_token = uuid.uuid4().hex
        print("::stop-commands::" + command_token, flush=True)
        try:
            with zipfile.ZipFile(path) as bundle:
                infos = bundle.infolist()
                require(len(infos) <= MAX_MEMBERS, "MEMBER_COUNT")
                require(len(infos) == len({x.filename for x in infos}), "DUPLICATE_MEMBER")
                for info in infos:
                    parts = PurePosixPath(info.filename).parts
                    require(not info.filename.startswith("/") and ".." not in parts
                            and "\\" not in info.filename, "MEMBER_PATH")
                index = [{"name": x.filename, "bytes": x.file_size,
                          "compressed_bytes": x.compress_size, "crc32": x.CRC}
                         for x in infos]
                index_sha = write_json(output / "members.json", index)
                if reports:
                    require(set(reports) <= {x.filename for x in infos}, "NATIVE_REPORT_MEMBER_MISSING")
                chosen = sorted((x for x in infos if not x.is_dir() and selected(x.filename, target)),
                                key=priority)
                for member_index, info in enumerate(chosen):
                    if info.file_size > MAX_MEMBER or selected_bytes + info.file_size > MAX_SELECTED:
                        omitted.append({"name": info.filename, "reason": "bounded reader size limit"})
                        continue
                    raw = bundle.read(info)
                    selected_bytes += len(raw)
                    require(len(raw) == info.file_size, "MEMBER_SIZE")
                    record = {"member": info.filename, "bytes": len(raw),
                              "sha256": hashlib.sha256(raw).hexdigest()}
                    native_report = info.filename in reports
                    if native_report:
                        expected_size, expected_sha = reports[info.filename]
                        require((expected_size is None or record["bytes"] == expected_size)
                                and (expected_sha is None or record["sha256"] == expected_sha),
                                "NATIVE_REPORT_BYTES_OR_HASH")
                        record["member_digest_pinned_separately"] = expected_sha is not None
                    try:
                        content = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        record["read_status"] = "non_utf8_uninterpreted"
                        records.append(record)
                        continue
                    if info.filename.endswith(".json"):
                        value = json.loads(content)
                        if info.filename in SOURCE_MEMBERS:
                            require(isinstance(value, dict)
                                    and value.get("schema") == "trnm-ci-source-v1"
                                    and value.get("tested_commit") == target["head"]
                                    and value.get("tested_tree") == target["tree"]
                                    and value.get("tracked_worktree_verified") is True,
                                    "ORIGINAL_SOURCE_GUARD")
                            record["source_guard_verified"] = True
                        if native_report:
                            projection, compact = native_history_projection(value, target, record)
                            record["native_history_cost_projection"] = projection
                            excerpt = json.dumps(projection, sort_keys=True) + "\n"
                            console_excerpt = json.dumps(compact, sort_keys=True, separators=(",", ":")) + "\n"
                        else:
                            extra_key = EXTRA_KEY
                            fields = scalar_fields(value, extra_key)
                            record["scalar_fields"] = fields
                            excerpt = json.dumps({"artifact": target["id"], "member": info.filename,
                                                  "fields": fields}, sort_keys=True) + "\n"
                            if target["kind"] == "f0" and info.filename in (
                                    "execution/results.json", "finalization/result.json"):
                                projection, console_excerpt = f0_terminal_projection(value, target, record)
                                record["f0_terminal_projection"] = projection
                            else:
                                console_excerpt = console_json(target, info.filename, fields)
                    else:
                        lines = content.splitlines()
                        picked = set()
                        for number, line in enumerate(lines):
                            clean = re.sub(r"\x1b\[[0-9;]*m", "", line)
                            if MATCH.search(clean):
                                picked.update(range(max(0, number - 2), min(len(lines), number + 12)))
                        # Bound display only. The original ZIP remains intact.
                        picked.update(range(max(0, len(lines) - 40), len(lines)))
                        positions = sorted(picked)
                        shown = positions[-240:]
                        record["matching_context_lines"] = len(positions)
                        record["displayed_context_lines"] = len(shown)
                        record["context_truncated"] = len(shown) != len(positions)
                        excerpt = "\n".join(
                            f"artifact={target['id']} member={info.filename} line={i + 1} {lines[i]}"
                            for i in shown) + ("\n" if shown else "")
                        console_lines = []
                        truncated_lines = 0
                        essential = re.compile(
                            r"^thread .*panicked|^called .*Err|^test result: FAILED"
                            r"|^test .+ \.\.\. FAILED|^failures:|^error(?:\[[^]]+\])?:|^Error:")
                        ordered = sorted(shown, key=lambda i: (
                            0 if essential.search(re.sub(r"\x1b\[[0-9;]*m", "", lines[i])) else 1, i))
                        for i in ordered:
                            line = lines[i]
                            if len(line) > 2048:
                                line = line[:2048] + " [console line truncated; original retained]"
                                truncated_lines += 1
                            console_lines.append(
                                f"artifact={target['id']} member={info.filename} line={i + 1} {line}")
                        console_excerpt = "\n".join(console_lines) + ("\n" if console_lines else "")
                        record["console_truncated_lines"] = truncated_lines
                    record["read_status"] = "read"
                    with (output / f"excerpt-{member_index:04}.txt").open("x") as stream:
                        stream.write(excerpt)
                    record["excerpt_file"] = f"excerpt-{member_index:04}.txt"
                    rendered, displayed_lines, omitted_lines = bounded_console(
                        console_excerpt, MAX_STDOUT - printed, target, info.filename)
                    if native_report:
                        require(omitted_lines == 0, "NATIVE_COST_CONSOLE_LIMIT")
                    if "f0_terminal_projection" in record:
                        require(omitted_lines == 0, "F0_TERMINAL_CONSOLE_LIMIT")
                    record["stdout_emitted"] = displayed_lines > 0
                    record["stdout_lines_emitted"] = displayed_lines
                    record["stdout_lines_omitted"] = omitted_lines
                    if rendered:
                        print(rendered, end="", flush=True)
                        printed += len(rendered)
                    records.append(record)
                if reports:
                    require({row["member"] for row in records
                             if row.get("read_status") == "read"
                             and "native_history_cost_projection" in row}
                            == set(reports), "NATIVE_REPORT_SET_INCOMPLETE")
                require({row["member"] for row in records if row.get("source_guard_verified")}
                        == SOURCE_MEMBERS, "ORIGINAL_SOURCE_GUARDS_INCOMPLETE")
        finally:
            print("::" + command_token + "::", flush=True)
        result = {
            "schema": "trnm-current-native-cost-artifact-readback-v1",
            "target": target, "downloaded_zip_bytes": received,
            "downloaded_zip_sha256": target["digest"].split(":", 1)[1],
            "member_index_sha256": index_sha,
            "selected_text_bytes": selected_bytes, "records": records,
            "omitted_members": omitted, "reader_status": "completed",
            "source_tests_executed": False, "acceptance_granted": False,
            "production_activation": False,
            "scope": "Read original failed evidence only; excerpts are bounded, original archive retained."
        }
        write_json(output / "readback.json", result)
        summary = {key: result[key] for key in (
            "schema", "target", "downloaded_zip_bytes", "downloaded_zip_sha256",
            "member_index_sha256", "selected_text_bytes", "reader_status",
            "source_tests_executed", "acceptance_granted", "production_activation")}
        summary["omitted_members"] = len(omitted)
        summary["records"] = len(records)
        print(json.dumps(summary, sort_keys=True), flush=True)
        results.append(summary)
    except Exception as error:
        had_error = True
        result = {"target": target, "reader_status": "failed", "stage": stage,
                  "error_type": type(error).__name__,
                  "http_status": getattr(error, "code", None),
                  "reason": str(error) if isinstance(error, Refused) else None,
                  "source_tests_executed": False, "acceptance_granted": False}
        write_json(output / "reader-failure.json", result)
        print(json.dumps(result, sort_keys=True), flush=True)
        results.append(result)

write_json(ROOT / "readback.json", {
    "schema": "trnm-current-native-cost-readback-cohort-v1",
    "planned_artifacts": len(TARGETS), "results": results,
    "source_tests_executed": False, "acceptance_granted": False,
    "production_activation": False})
raise SystemExit(1 if had_error else 0)
