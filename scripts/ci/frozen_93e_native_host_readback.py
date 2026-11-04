#!/usr/bin/env python3
"""Read existing Host observations from two exact 93e archives; execute no archived code."""
import hashlib, json, os, re, urllib.error, urllib.parse, urllib.request, uuid, zipfile
from pathlib import Path, PurePosixPath

REPO = "TrillionniumFoundation/Trillionnium-Chain"
BRANCH = "fix/chain-retained-failure-readback-20261104"
TARGETS = json.loads(r'''[{"id":13310800965,"name":"pon-fixed-host-root-f0-x64-head-93e207c8d2ccb8509f78566223abc371b9d8118b-1","size":16348465,"digest":"sha256:e85f77ebb5645473de6af3f5b7c144dd571445ce63c94e60c6890c86c3ba4a8c","run":41806693160,"job":126495361302,"head":"93e207c8d2ccb8509f78566223abc371b9d8118b","tree":"1066c67970802b52070ece6fcc77bc9b2806a4e1","kind":"f0","report_schema":"native-public-v3-fixed-host-root-f0-v1","phase_modes":["baseline","valid-work-root"]},{"id":13309959342,"name":"pon-native-campaign-x64-head-release-93e207c8d2ccb8509f78566223abc371b9d8118b-1","size":56708044,"digest":"sha256:fc33a1681edcf53f0cfcbda2744eaaeb0a261e81c121c810fb63f83ea75f1ca7","run":41806693023,"job":126495362295,"head":"93e207c8d2ccb8509f78566223abc371b9d8118b","tree":"1066c67970802b52070ece6fcc77bc9b2806a4e1","kind":"campaign","report_schema":"native-public-v3-separate-process-campaign-v2","phase_modes":["baseline","from-zero","late-product"]}]''')
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
        "User-Agent": "trnm-current-native-host-readback-v1",
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
            "User-Agent": "trnm-current-native-host-readback-v1"})
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

KEY = re.compile(
    r"confirm|denominator|planned|failure|criteria|criterion|lifetime|shutdown"
    r"|server_exit|returncode|exit_code|head_sha|tested_commit|tested_tree"
    r"|source_sha|physical|qualification|activation|passed|unobserved"
    r"|deadline|cancelled|pending|unknown|elapsed|duration|host_errors"
    r"|observed|scheduled|within|before_original|slo|success|known_empty|^mode$|^number$|^code$|^kind$"
    r"|^schema$|^status$|^phase$|^name$|^label$|^reason$|^error$")

# Raw member bytes and SHA256 below are fixed by the completed original 93e
# cost readback (run 41821892261 / job 126546814496; source c3e8351493d78ba119c201dd458373a246edb9e7).
# Authenticate the entire fixed ZIP and each complete selected raw member.
NATIVE_REPORTS = {int(key): value for key, value in json.loads(r'''{"13310800965":{"execution/raw/report.json":[10548484,"23f82de3a7283c43b4739606a64b60557995144bfc215207dc308712b9a491b5"]},"13309959342":{"run-1-raw/report.json":[21435437,"1e5c2b32f47cba29a725aae3cf5a0ee1af807ecd4e48ca48359b20a735e7c3be"],"run-2-raw/report.json":[21612214,"fa97c28ec26df8352818280b9567b4730f794fc7fd4364680f4d271995f17bea"],"run-3-raw/report.json":[21513234,"69d69c5e51b35187cab066e22fd7fad2f7b5a3be6ee19c01f00247a96173e4bd"]}}''').items()}
SOURCE_MEMBERS = frozenset(("source-before.json", "source-after.json"))
EXTRA_KEY = re.compile(
    r"^(?:prepared|selector_invocation_attempted|head|tree|source_verified|commit"
    r"|binary_sha256_before|binary_sha256_after|format_passed|execution_finished"
    r"|source_recompiled|PREPARATION_OUTCOME|ARM_OUTCOME|EXECUTION_OUTCOME"
    r"|FINALIZATION_OUTCOME|F0_SOURCE_AFTER_STATUS)$")

def selected(name, target):
    return name in NATIVE_REPORTS[target["id"]] or name in SOURCE_MEMBERS


def priority(info):
    return (0 if any(info.filename in reports for reports in NATIVE_REPORTS.values()) else 1,
            info.filename)

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

PHASES = ('decode', 'context_owner_wait', 'context', 'work',
          'admission_owner_wait', 'admission', 'submit_result')
PHASES_V4 = PHASES + ('admission_prepare', 'execution', 'commit_owner_wait', 'commit',
                     'cpu_wait', 'body_decode', 'response_encoding', 'history_epoch_open',
                     'history_epoch_close', 'history_import', 'cpu_settle', 'root_commitment')
PHASE_PARENTS_V4 = dict.fromkeys(('admission_prepare', 'execution', 'commit_owner_wait', 'commit'),
                               'admission') | {'root_commitment': 'execution'}

def integer(value):
    require(type(value) is int and value >= 0, 'nonnegative integer observation required')
    return value


def outcome(value):
    require(value is None or type(value) is bool, 'boolean or unknown outcome required')
    return 'accepted' if value is True else 'rejected' if value is False else 'unknown'


def validate_v4_interval(value, *, phase=False):
    require(type(value) is dict, 'v4 interval object required')
    required = {'started_ns', 'ended_ns', 'wall_ns', 'completed', 'accepted', 'error_code'}
    if phase:
        required |= {'phase', 'parent_phase', 'started', 'thread_cpu_ns'}
    require(set(value) == required, 'v4 exact interval shape required')
    require(type(value['completed']) is bool, 'v4 completed boolean required')
    outcome(value['accepted'])
    require(value['completed'] is (value['accepted'] is not None), 'v4 completion/outcome mismatch')
    code = value['error_code']
    require(code is None or (isinstance(code, str) and re.fullmatch('[A-Z][A-Z0-9_]*', code)
                            and value['accepted'] is False), 'v4 typed rejection code required')
    for key in ('started_ns', 'ended_ns', 'wall_ns') + (('thread_cpu_ns',) if phase else ()):
        if value[key] is not None:
            require(integer(value[key]) < 1 << 64, 'v4 interval u64 required')
    start, end, wall = (value[key] for key in ('started_ns', 'ended_ns', 'wall_ns'))
    if start is not None and end is not None:
        require(end >= start and wall == end - start, 'v4 monotonic interval mismatch')
    if not phase and start is None:
        require(not value['completed'] and all(value[key] is None for key in
                ('ended_ns', 'wall_ns', 'accepted', 'error_code')), 'v4 unentered wait must remain unknown')
    if phase:
        require(type(value['started']) is bool, 'v4 started boolean required')
        require(value['parent_phase'] == PHASE_PARENTS_V4.get(value['phase']),
                'v4 inclusive parent phase mismatch')
        if not value['started']:
            require(not value['completed'] and all(value[key] is None for key in
                    ('accepted', 'error_code', 'started_ns', 'ended_ns', 'wall_ns', 'thread_cpu_ns')),
                    'v4 unentered phase must remain unknown')


def validate_v4_phases(phases):
    require(isinstance(phases, list) and [p.get('phase') for p in phases if isinstance(p, dict)]
            == list(PHASES_V4) and len(phases) == len(PHASES_V4),
            'v4 nineteen ordered phase slots required')
    for phase in phases:
        validate_v4_interval(phase, phase=True)
    by_phase = {phase['phase']: phase for phase in phases}
    for child in phases:
        parent = by_phase.get(child['parent_phase'])
        if parent is not None and child['completed'] and parent['completed'] and all(
                span[key] is not None for span in (parent, child) for key in ('started_ns', 'ended_ns')):
            require(parent['started_ns'] <= child['started_ns'] <= child['ended_ns'] <= parent['ended_ns'],
                    'v4 child interval escapes its inclusive parent')


def validate_history_import_observation(value: dict) -> None:
    """Local diagnostic consistency only; no Host, work or State authority."""
    def number(value):
        require(type(value) is int and 0 <= value < 1 << 64, 'IMPORT_OBSERVATION_U64')
        return value

    def known(value):
        return None if value is None else number(value)

    def hash_or_unknown(value):
        require(value is None or (isinstance(value, list) and len(value) == 32
                and all(type(n) is int and 0 <= n <= 255 for n in value)), 'IMPORT_OBSERVATION_HASH')

    require(isinstance(value, dict)
            and value.get('schema') == 'pon-local-history-import-observation-v1', 'IMPORT_OBSERVATION_SCHEMA')
    require(value.get('packet_capacity') == 16 and type(value.get('packet_capacity')) is int
            and all(value.get(key) is True for key in ('cpu_intervals_are_nested_not_additive',
                    'host_checks_are_nested_not_additive', 'phase_cpu_excludes_scoped_workers',
                    'host_cpu_includes_each_calling_thread'))
            and value.get('host_cpu_is_full_worker_cpu') is False
            and value.get('observation_has_consensus_authority') is False,
            'IMPORT_OBSERVATION_SCOPE')
    require(isinstance(value.get('clock_scope'), str) and 0 < len(value['clock_scope']) <= 2048,
            'IMPORT_OBSERVATION_SCOPE')
    failures = number(value.get('measurement_failures'))
    for field in ('tip', 'after', 'supplied_packets'):
        require(field in value, 'IMPORT_OBSERVATION_CONTEXT_REQUIRED')
    hash_or_unknown(value['tip'])
    hash_or_unknown(value['after'])
    known(value['supplied_packets'])
    validate_v4_phases(value.get('phases'))
    packets = value.get('packets')
    require(isinstance(packets, list) and len(packets) <= 16, 'IMPORT_OBSERVATION_PACKET_BOUND')
    indices = []
    for packet in packets:
        require(isinstance(packet, dict) and set(packet) == {'packet_index', 'packet_id', 'phases'},
                'IMPORT_OBSERVATION_PACKET_SHAPE')
        index = number(packet['packet_index'])
        require(index < 16, 'IMPORT_OBSERVATION_PACKET_BOUND')
        indices.append(index)
        hash_or_unknown(packet['packet_id'])
        validate_v4_phases(packet['phases'])
    require(indices == sorted(set(indices)), 'IMPORT_OBSERVATION_PACKET_IDENTITY')
    host = value.get('host_checks')
    names = ('resolve', 'initial', 'checkpoint', 'final')
    require(isinstance(host, list) and len(host) == 4
            and [row.get('phase') for row in host if isinstance(row, dict)] == list(names),
            'IMPORT_OBSERVATION_HOST_SLOTS')
    count_fields = ('calls_started', 'calls_completed', 'calls_accepted', 'calls_rejected',
                    'calls_unfinished', 'wall_clock_unknown_calls', 'cpu_clock_unknown_calls')
    time_fields = ('first_started_ns', 'last_ended_ns', 'wall_ns', 'thread_cpu_ns')
    for row in host:
        require(set(row) == {'phase', 'last_error_code', *count_fields, *time_fields},
                'IMPORT_OBSERVATION_HOST_SHAPE')
        for key in count_fields:
            number(row[key])
        for key in time_fields:
            known(row[key])
        ended = row['calls_completed'] + row['calls_unfinished']
        require(row['calls_completed'] == row['calls_accepted'] + row['calls_rejected']
                and ended <= row['calls_started'] and (failures != 0 or ended == row['calls_started'])
                and row['wall_clock_unknown_calls'] <= ended and row['cpu_clock_unknown_calls'] <= ended,
                'IMPORT_OBSERVATION_HOST_COUNTS')
        if row['phase'] != 'checkpoint':
            require(row['calls_started'] <= 1 or failures != 0, 'IMPORT_OBSERVATION_HOST_REUSED')
        start, end = row['first_started_ns'], row['last_ended_ns']
        if start is not None and end is not None:
            require(start <= end, 'IMPORT_OBSERVATION_HOST_TIME')
        if row['calls_started'] == 0:
            require(all(row[key] is None for key in time_fields) and row['last_error_code'] is None,
                    'IMPORT_OBSERVATION_HOST_UNENTERED')
        for total, unknown in (('wall_ns', 'wall_clock_unknown_calls'),
                               ('thread_cpu_ns', 'cpu_clock_unknown_calls')):
            if row[unknown] or ended == 0:
                require(row[total] is None, 'IMPORT_OBSERVATION_HOST_UNKNOWN_TOTAL')
            elif failures == 0:
                require(row[total] is not None, 'IMPORT_OBSERVATION_HOST_MISSING_TOTAL')
        code = row['last_error_code']
        require(code is None or (isinstance(code, str) and re.fullmatch('[A-Z][A-Z0-9_]*', code)
                and row['calls_rejected'] > 0), 'IMPORT_OBSERVATION_HOST_ERROR')
    native = next(phase for phase in value['phases'] if phase['phase'] == 'history_import')
    if native['completed'] and native['started_ns'] is not None and native['ended_ns'] is not None:
        for packet in packets:
            for phase in packet['phases']:
                if phase['completed'] and phase['started_ns'] is not None and phase['ended_ns'] is not None:
                    require(native['started_ns'] <= phase['started_ns'] <= phase['ended_ns'] <= native['ended_ns'],
                            'IMPORT_OBSERVATION_PACKET_OUTSIDE_NATIVE')
        checkpoint = host[2]
        if checkpoint['first_started_ns'] is not None and checkpoint['last_ended_ns'] is not None:
            require(native['started_ns'] <= checkpoint['first_started_ns']
                    <= checkpoint['last_ended_ns'] <= native['ended_ns'], 'IMPORT_OBSERVATION_HOST_OUTSIDE_NATIVE')
        if host[1]['last_ended_ns'] is not None:
            require(host[1]['last_ended_ns'] <= native['started_ns'], 'IMPORT_OBSERVATION_HOST_ORDER')
        if host[3]['first_started_ns'] is not None:
            require(native['ended_ns'] <= host[3]['first_started_ns'], 'IMPORT_OBSERVATION_HOST_ORDER')
    if host[0]['last_ended_ns'] is not None and host[1]['first_started_ns'] is not None:
        require(host[0]['last_ended_ns'] <= host[1]['first_started_ns'], 'IMPORT_OBSERVATION_HOST_ORDER')


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

HOST_PHASES = ("resolve", "initial", "checkpoint", "final")
HOST_COUNTS = ("calls_started", "calls_completed", "calls_accepted", "calls_rejected",
               "calls_unfinished", "wall_clock_unknown_calls", "cpu_clock_unknown_calls")
HOST_TIMES = ("first_started_ns", "last_ended_ns", "wall_ns", "thread_cpu_ns")
HOST_SUMMARY_COLUMNS = (
    "phase", "status", "valid_rows", "missing_or_invalid_rows", "measurement_failure_rows",
    *HOST_COUNTS, "wall_known_rows", "wall_unknown_rows", "wall_known_sum_ns",
    "wall_complete_recorded_total_ns", "cpu_known_rows", "cpu_unknown_rows", "cpu_known_sum_ns",
    "cpu_complete_recorded_total_ns", "outcomes_complete",
)
IMPORT_COLUMNS = (
    "history_index", "import_status", "observer_status", "succeeded", "measurement_failures",
    "import_wall_ns", "import_thread_cpu_ns", "checkpoint_calls_started",
    "checkpoint_calls_completed", "checkpoint_calls_accepted", "checkpoint_calls_rejected",
    "checkpoint_calls_unfinished", "checkpoint_wall_ns", "checkpoint_thread_cpu_ns",
    "checkpoint_wall_unknown_calls", "checkpoint_cpu_unknown_calls",
)
CLIENT_SCOPE = ("calling client thread only; excludes scoped execution worker CPU; "
                "unknown clock is null; no deadline or acceptance authority")


def u64(value):
    return type(value) is int and 0 <= value < (1 << 64)


def validate_import_stage(value):
    require(isinstance(value, dict), "CLIENT_IMPORT_MISSING_OR_NULL")
    require(value.get("scope") == CLIENT_SCOPE, "CLIENT_IMPORT_CPU_SCOPE")
    require(type(value.get("succeeded")) is bool and "error" in value
            and (value["error"] is None if value["succeeded"] else isinstance(value["error"], str)),
            "CLIENT_IMPORT_OUTCOME")
    for key in ("started_ns", "ended_ns", "wall_ns", "thread_cpu_ns"):
        require(key in value and (value[key] is None or u64(value[key])), "CLIENT_IMPORT_CLOCK")
    require(type(value.get("thread_cpu_observation_available")) is bool
            and value["thread_cpu_observation_available"] is (value["thread_cpu_ns"] is not None),
            "CLIENT_IMPORT_CPU_AVAILABILITY")
    if value["started_ns"] is not None and value["ended_ns"] is not None:
        require(value["started_ns"] <= value["ended_ns"], "CLIENT_IMPORT_CLOCK_ORDER")


def validation(value, validator):
    try:
        validator(value)
        return {"status": "observed", "reason": None}
    except (Refused, ValueError, TypeError, KeyError) as error:
        return {"status": "unknown", "reason": str(error)}


def digest(value):
    if value is None:
        return None
    if isinstance(value, list):
        require(len(value) == 32 and all(type(n) is int and 0 <= n <= 255 for n in value),
                'canonical observed 32-byte digest required')
        return bytes(value).hex()
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value),
            'canonical observed digest required')
    return value


def validate_history_binding(history, native):
    require(history.get("status") == "ok" and history.get("returned_after_window") is False,
            "IMPORT_ORIGINAL_ON_TIME_HISTORY_RESPONSE")
    request = history.get("request")
    require(isinstance(request, dict) and request.get("op") == "history",
            "IMPORT_HISTORY_REQUEST_BINDING")
    for key in ("tip", "after"):
        expected = digest(request.get(key))
        require(expected is not None and (native[key] is None or digest(native[key]) == expected),
                "IMPORT_HISTORY_CONTEXT_MISMATCH")
    if native["supplied_packets"] is not None:
        response = history.get("response")
        page = response.get("value") if isinstance(response, dict) else None
        require(isinstance(page, dict) and isinstance(page.get("packets"), list)
                and native["supplied_packets"] == len(page["packets"]),
                "IMPORT_SUPPLIED_PACKET_COUNT_MISMATCH")


def history_record(index, history):
    if not isinstance(history, dict):
        return {"history_index": index, "history_row_status": "unknown",
                "import_present": False, "observer_present": False, "client_import": None,
                "native_import_observation": None,
                "import_validation": {"status": "unknown", "reason": "HISTORY_ROW_NOT_OBJECT"},
                "observer_validation": {"status": "unknown", "reason": "HISTORY_ROW_NOT_OBJECT"}}
    client = history.get("client_import")
    native = client.get("native_import_observation") if isinstance(client, dict) else None
    import_validation = validation(client, validate_import_stage)
    observer_validation = validation(native, validate_history_import_observation)
    if observer_validation["status"] == "observed":
        observer_validation = validation((history, native), lambda pair: validate_history_binding(*pair))
        if observer_validation["status"] != "observed":
            import_validation = {"status": "unknown", "reason": "HISTORY_BINDING_INVALID"}
        elif import_validation["status"] != "observed":
            observer_validation = {"status": "unknown", "reason": "CLIENT_IMPORT_INVALID"}
    if (import_validation["status"] == observer_validation["status"] == "observed"
            and client["succeeded"] and native["measurement_failures"] == 0):
        native_span = next(slot for slot in native["phases"] if slot["phase"] == "history_import")
        if not (native_span["completed"] and native_span["accepted"] is True
                and all(slot["calls_started"] == slot["calls_accepted"] for slot in native["host_checks"])
                and all(slot["calls_started"] == 1 for slot in native["host_checks"]
                        if slot["phase"] != "checkpoint")
                and native["host_checks"][2]["calls_started"] > 0):
            observer_validation = {"status": "unknown", "reason": "SUCCESSFUL_IMPORT_OBSERVATION_MISMATCH"}
    return {
        "history_index": index, "history_row_status": "observed",
        "history_call": {key: history.get(key) for key in (
            "started_ns", "ended_ns", "status", "returned_after_window", "error",
            "public_request_body_digest")},
        "response_packet_count": (len(history["response"]["value"]["packets"])
                                  if isinstance(history.get("response"), dict)
                                  and isinstance(history["response"].get("value"), dict)
                                  and isinstance(history["response"]["value"].get("packets"), list) else None),
        "request_binding": {key: history["request"].get(key) for key in ("op", "tip", "after")}
                           if isinstance(history.get("request"), dict) else None,
        "import_present": "client_import" in history,
        "observer_present": isinstance(client, dict) and "native_import_observation" in client,
        "client_import": {key: value for key, value in client.items()
                          if key != "native_import_observation"} if isinstance(client, dict) else client,
        "native_import_observation": native,
        "import_validation": import_validation,
        "observer_validation": observer_validation,
    }


def timing_rows(values, expected_rows, coverage):
    """No observations and entered-unknown clocks are never measured zero."""
    known = [value for value in values if value is not None]
    known_sum = sum(known) if known else None
    return {"known_rows": len(known), "unknown_rows": expected_rows - len(known) if expected_rows is not None else None,
            "known_sum_ns": known_sum,
            "complete_recorded_total_ns": (known_sum if coverage and expected_rows is not None and expected_rows > 0
                                            and len(known) == expected_rows else None)}


def phase_summary(records, history_observed):
    imports = [row for row in records if row["import_validation"]["status"] == "observed"]
    observers = [row for row in records if row["observer_validation"]["status"] == "observed"]
    failed_measurements = sum(row["native_import_observation"]["measurement_failures"] != 0
                              for row in observers)
    coverage = history_observed and len(observers) == len(records) and failed_measurements == 0
    client_coverage = history_observed and len(imports) == len(records)
    host = []
    for name in HOST_PHASES:
        slots = [next(slot for slot in row["native_import_observation"]["host_checks"]
                      if slot["phase"] == name) for row in observers]
        counts = {key: sum(slot[key] for slot in slots) for key in HOST_COUNTS} if slots else None
        entered = [slot for slot in slots if slot["calls_started"] > 0]
        wall = timing_rows([slot["wall_ns"] for slot in entered], len(entered) if slots else None, coverage)
        cpu = timing_rows([slot["thread_cpu_ns"] for slot in entered], len(entered) if slots else None, coverage)
        missing = len(records) - len(slots) if history_observed else None
        status = ("unknown" if not slots else "incomplete" if not coverage else
                  "unentered" if not entered else "observed")
        ended = counts["calls_completed"] + counts["calls_unfinished"] if counts is not None else None
        host.append({
            "phase": name, "status": status, "valid_rows": len(slots),
            "missing_or_invalid_rows": missing, "measurement_failure_rows": failed_measurements if history_observed else None,
            "counts": counts, "wall": wall, "cpu": cpu,
            "outcomes_complete": coverage and counts is not None and counts["calls_started"] > 0 and counts["calls_unfinished"] == 0,
            "mean_recorded_invocation_cpu_ns": (
                {"numerator": cpu["complete_recorded_total_ns"], "denominator": ended}
                if cpu["complete_recorded_total_ns"] is not None and ended else None),
            "mean_recorded_invocation_wall_ns": (
                {"numerator": wall["complete_recorded_total_ns"], "denominator": ended}
                if wall["complete_recorded_total_ns"] is not None and ended else None),
        })
    return {
        "history_observed": history_observed, "history_calls": len(records) if history_observed else None,
        "retained_history_rows": len(records),
        "valid_import_stages": len(imports),
        "missing_or_invalid_import_stages": len(records) - len(imports) if history_observed else None,
        "valid_native_observers": len(observers),
        "missing_or_invalid_native_observers": len(records) - len(observers) if history_observed else None,
        "measurement_failure_observers": failed_measurements if history_observed else None,
        "import_outcomes": {
            "succeeded": sum(row["client_import"]["succeeded"] is True for row in imports) if history_observed else None,
            "failed": sum(row["client_import"]["succeeded"] is False for row in imports) if history_observed else None,
            "unknown": len(records) - len(imports) if history_observed else None,
        },
        "client_import_wall": timing_rows([row["client_import"]["wall_ns"] for row in imports],
                                          len(records) if history_observed else None, client_coverage),
        "client_import_cpu": timing_rows([row["client_import"]["thread_cpu_ns"] for row in imports],
                                         len(records) if history_observed else None, client_coverage),
        "host": host,
        "scope": "Sums of retained observations only; missing History/import/observer rows are unknown. Host durations include unfinished invocations; mean denominator is completed plus unfinished. Outcomes remain separate. Host wall intervals may overlap across workers; Host CPU includes each invoking thread; caller CPU excludes scoped workers. None is never filled with zero.",
    }


def compact_host_summary(summary):
    rows = []
    for item in summary["host"]:
        fields = {key: item[key] for key in (
            "phase", "status", "valid_rows", "missing_or_invalid_rows",
            "measurement_failure_rows", "outcomes_complete")}
        if item["counts"] is not None:
            fields.update(item["counts"])
        for label in ("wall", "cpu"):
            fields.update({label + "_" + key: value for key, value in item[label].items()})
        rows.append([fields.get(key) for key in HOST_SUMMARY_COLUMNS])
    return {**{key: value for key, value in summary.items() if key not in ("host", "scope")},
            "host": rows}


def compact_history(row):
    client, native = row["client_import"], row["native_import_observation"]
    client_ok = row["import_validation"]["status"] == "observed"
    observer_ok = row["observer_validation"]["status"] == "observed"
    checkpoint = next(slot for slot in native["host_checks"] if slot["phase"] == "checkpoint") \
        if observer_ok else None
    fields = {
        "history_index": row["history_index"], "import_status": row["import_validation"]["status"],
        "observer_status": row["observer_validation"]["status"],
        "succeeded": client["succeeded"] if client_ok else None,
        "measurement_failures": native["measurement_failures"] if observer_ok else None,
        "import_wall_ns": client["wall_ns"] if client_ok else None,
        "import_thread_cpu_ns": client["thread_cpu_ns"] if client_ok else None,
    }
    if checkpoint is not None:
        fields.update({"checkpoint_" + key: value for key, value in checkpoint.items() if key != "phase"})
    fields["checkpoint_wall_unknown_calls"] = checkpoint["wall_clock_unknown_calls"] if checkpoint else None
    fields["checkpoint_cpu_unknown_calls"] = checkpoint["cpu_clock_unknown_calls"] if checkpoint else None
    return [fields.get(key) for key in IMPORT_COLUMNS]


def host_history_projection(value, target, record):
    require(isinstance(value, dict) and value.get("schema") == target["report_schema"]
            and value.get("state_backend") == "authenticated-v1", "HOST_REPORT_SCHEMA")
    phases = value.get("phases")
    require(isinstance(phases, list) and len(phases) == len(target["phase_modes"])
            and all(isinstance(phase, dict) for phase in phases)
            and [phase.get("mode") for phase in phases] == target["phase_modes"], "HOST_PHASE_IDENTITIES")
    kept = []
    for index, phase in enumerate(phases):
        history = phase.get("history")
        available = isinstance(history, list) and len(history) <= 64
        records = [history_record(index, entry) for index, entry in enumerate(history)] if available else []
        kept.append({
            "scheduled_phase_index": index, "mode": phase["mode"],
            "history_present": "history" in phase, "history_available": available,
            "history_unavailable_reason": None if available else "HISTORY_MISSING_NULL_OR_OVER_BOUND",
            "original_fields": {key: phase.get(key) for key in (
                "duration_seconds", "state_backend", "finite_phase_criteria_met",
                "all_signed_rounds_confirmed_in_window", "startup_or_campaign_error",
                "verifier_errors", "client_observation_scope")},
            "confirmation_readback": confirmation_projection(phase),
            "history": records, "summary": phase_summary(records, available),
        })
    projection = {
        "schema": "trnm-current-native-host-cost-readback-v1",
        "artifact": target["id"], "measured_head": target["head"],
        "measured_run": target["run"], "measured_job": target["job"],
        "member": record["member"], "member_bytes": record["bytes"], "member_sha256": record["sha256"],
        "scheduled_phases": len(target["phase_modes"]), "phases": kept,
        "source_tests_executed": False, "native_tests_executed": 0, "acceptance_granted": False,
        "observation_has_consensus_authority": False,
        "scope": "Read existing HistoryImportObserver only; no instrumentation, archive code execution, changed Host frequency, authorization, budget or deadline. Full client imports, four Host phases, measurement failures and all page/packet phase timestamps are retained. Host epochs differ from campaign/client epochs. Nested wall/CPU intervals are not additive; Host CPU includes every invoking thread and is not an exclusive fraction of caller-only or account_graph CPU. Per-file syscall/parser cost and p99 are not measured.",
    }
    scalar_fields(projection)
    compact = {key: value for key, value in projection.items() if key != "phases"}
    compact["host_summary_columns"] = HOST_SUMMARY_COLUMNS
    compact["history_columns"] = IMPORT_COLUMNS
    compact["phases"] = [{
        "scheduled_phase_index": row["scheduled_phase_index"], "mode": row["mode"],
        "history_available": row["history_available"],
        "history_unavailable_reason": row["history_unavailable_reason"],
        "confirmation_readback": row["confirmation_readback"],
        "summary": compact_host_summary(row["summary"]),
        "history": [compact_history(item) for item in row["history"]],
        "history_rows_console_omitted": 0, "full_history_projection_retained": True,
    } for row in kept]
    # Three campaign members share the unchanged 70k per-artifact console cap.
    while len(json.dumps(compact, sort_keys=True, separators=(",", ":"))) + 1 > 16000:
        candidates = [row for row in compact["phases"] if row["history"]]
        require(bool(candidates), "HOST_CONSOLE_SUMMARY_LIMIT")
        longest = max(candidates, key=lambda row: len(row["history"]))
        longest["history"].pop()
        longest["history_rows_console_omitted"] += 1
    return projection, compact


def host_reader_selfcheck():
    """Synthetic reader controls only; no Node execution or acceptance."""
    passed = []

    def check(name, condition):
        require(condition, "HOST_READER_CONTROL:" + name)
        passed.append(name)

    def fixture():
        phases = [{
            "phase": name, "parent_phase": PHASE_PARENTS_V4.get(name),
            "started": False, "completed": False, "accepted": None, "error_code": None,
            "started_ns": None, "ended_ns": None, "wall_ns": None, "thread_cpu_ns": None,
        } for name in PHASES_V4]
        native_span = next(row for row in phases if row["phase"] == "history_import")
        native_span.update(started=True, completed=True, accepted=True,
                           started_ns=10, ended_ns=100, wall_ns=90, thread_cpu_ns=50)
        slots = []
        for name, start, end, calls, wall, cpu in (
                ("resolve", 1, 2, 1, 1, 1), ("initial", 3, 4, 1, 1, 1),
                ("checkpoint", 20, 90, 2, 20, 10), ("final", 101, 102, 1, 1, 1)):
            slots.append({
                "phase": name, "calls_started": calls, "calls_completed": calls,
                "calls_accepted": calls, "calls_rejected": 0, "calls_unfinished": 0,
                "wall_clock_unknown_calls": 0, "cpu_clock_unknown_calls": 0,
                "first_started_ns": start, "last_ended_ns": end,
                "wall_ns": wall, "thread_cpu_ns": cpu, "last_error_code": None,
            })
        native = {
            "schema": "pon-local-history-import-observation-v1", "packet_capacity": 16,
            "tip": None, "after": None, "supplied_packets": 0, "packets": [],
            "measurement_failures": 0, "phases": phases, "host_checks": slots,
            "host_checks_are_nested_not_additive": True, "cpu_intervals_are_nested_not_additive": True,
            "phase_cpu_excludes_scoped_workers": True, "host_cpu_includes_each_calling_thread": True,
            "host_cpu_is_full_worker_cpu": False, "observation_has_consensus_authority": False,
            "clock_scope": "synthetic independent epoch",
        }
        return {"status": "ok", "returned_after_window": False,
                "request": {"op": "history", "tip": [1] * 32, "after": [0] * 32},
                "response": {"value": {"packets": []}}, "client_import": {
            "scope": CLIENT_SCOPE, "succeeded": True, "error": None,
            "started_ns": 1000, "ended_ns": 1200, "wall_ns": 200, "thread_cpu_ns": 100,
            "thread_cpu_observation_available": True, "native_import_observation": native,
        }}

    def summarize(*items):
        return phase_summary([history_record(index, item) for index, item in enumerate(items)], True)

    def observer(item):
        return item["client_import"]["native_import_observation"]

    good = fixture()
    summary = summarize(good)
    check("complete_positive", summary["host"][2]["cpu"]["complete_recorded_total_ns"] == 10
          and summary["host"][2]["counts"]["calls_started"] == 2
          and summary["client_import_cpu"]["complete_recorded_total_ns"] == 100
          and summary["host"][2]["outcomes_complete"] is True)
    summary = summarize({})
    check("missing_import_unknown", summary["host"][2]["counts"] is None
          and summary["client_import_cpu"]["complete_recorded_total_ns"] is None
          and summary["import_outcomes"]["unknown"] == 1)
    item = fixture()
    del item["client_import"]["native_import_observation"]
    summary = summarize(item)
    check("missing_observer_unknown", summary["host"][2]["counts"] is None
          and summary["client_import_cpu"]["complete_recorded_total_ns"] == 100)
    summary = phase_summary([], False)
    check("missing_history_unknown", summary["history_calls"] is None
          and all(value is None for value in summary["import_outcomes"].values())
          and summary["client_import_cpu"]["unknown_rows"] is None
          and summary["host"][2]["counts"] is None)
    item = fixture()
    item["client_import"].update(succeeded=False, error="EARLY_REFUSAL")
    for slot in observer(item)["host_checks"]:
        slot.update({key: 0 for key in HOST_COUNTS})
        slot.update({key: None for key in HOST_TIMES})
    for slot in observer(item)["phases"]:
        slot.update(started=False, completed=False, accepted=None,
                    started_ns=None, ended_ns=None, wall_ns=None, thread_cpu_ns=None)
    summary = summarize(item)
    check("unentered_is_not_zero_time", summary["host"][2]["status"] == "unentered"
          and summary["host"][2]["counts"]["calls_started"] == 0
          and summary["host"][2]["cpu"]["complete_recorded_total_ns"] is None)
    item = fixture()
    observer(item)["host_checks"][2].update(cpu_clock_unknown_calls=1, thread_cpu_ns=None)
    summary = summarize(item)
    check("unknown_cpu", summary["host"][2]["cpu"]["known_sum_ns"] is None
          and summary["host"][2]["cpu"]["complete_recorded_total_ns"] is None
          and summary["host"][2]["wall"]["complete_recorded_total_ns"] == 20)
    item = fixture()
    observer(item)["host_checks"][2].update(wall_clock_unknown_calls=1, wall_ns=None)
    summary = summarize(item)
    check("unknown_wall", summary["host"][2]["wall"]["known_sum_ns"] is None
          and summary["host"][2]["wall"]["complete_recorded_total_ns"] is None)
    item = fixture()
    observer(item)["host_checks"][3]["phase"] = "checkpoint"
    check("duplicate_host_phase", history_record(0, item)["observer_validation"]["status"] == "unknown")
    item = fixture()
    observer(item)["phases"][1]["phase"] = observer(item)["phases"][0]["phase"]
    check("duplicate_packet_phase", history_record(0, item)["observer_validation"]["status"] == "unknown")
    item = fixture()
    item["client_import"].update(succeeded=False, error="UNFINISHED")
    observer(item)["host_checks"][2].update(calls_completed=1, calls_accepted=1, calls_unfinished=1)
    summary = summarize(item)
    check("unfinished_not_success", summary["host"][2]["counts"]["calls_unfinished"] == 1
          and summary["host"][2]["outcomes_complete"] is False
          and summary["host"][2]["mean_recorded_invocation_cpu_ns"] == {"numerator": 10, "denominator": 2}
          and summary["import_outcomes"]["failed"] == 1)
    item = fixture()
    observer(item)["measurement_failures"] = 1
    summary = summarize(item)
    check("measurement_failure_incomplete", summary["host"][2]["cpu"]["known_sum_ns"] == 10
          and summary["host"][2]["cpu"]["complete_recorded_total_ns"] is None
          and summary["host"][2]["status"] == "incomplete")
    item = fixture()
    observer(item)["host_checks"][2]["calls_started"] = True
    check("bool_is_not_counter", history_record(0, item)["observer_validation"]["status"] == "unknown")
    item = fixture()
    observer(item)["host_checks"][2].update(cpu_clock_unknown_calls=1, thread_cpu_ns=None)
    summary = summarize(good, item)
    check("mixed_known_unknown", summary["host"][2]["cpu"]["known_sum_ns"] == 10
          and summary["host"][2]["cpu"]["unknown_rows"] == 1
          and summary["host"][2]["cpu"]["complete_recorded_total_ns"] is None)
    item = fixture()
    observer(item)["host_checks"][2].update(calls_completed=1, calls_accepted=1, calls_unfinished=1)
    check("success_with_unfinished_rejected", history_record(0, item)["observer_validation"]["status"] == "unknown")
    item = fixture()
    packet = {"packet_index": 0, "packet_id": None, "phases": observer(item)["phases"]}
    observer(item)["packets"] = [packet, packet]
    check("duplicate_packet_identity", history_record(0, item)["observer_validation"]["status"] == "unknown")
    refused = False
    try:
        host_history_projection({"schema": TARGETS[0]["report_schema"], "state_backend": "authenticated-v1",
                                 "phases": [{"mode": "baseline"}, {"mode": "baseline"}]},
                                TARGETS[0], {"member": "synthetic", "bytes": 0, "sha256": "synthetic"})
    except Refused:
        refused = True
    check("duplicate_scheduled_phase", refused)
    item = fixture()
    item["status"] = "failed"
    check("history_response_failure", history_record(0, item)["observer_validation"]["status"] == "unknown")
    item = fixture()
    item["returned_after_window"] = True
    check("late_history_response", history_record(0, item)["observer_validation"]["status"] == "unknown")
    item = fixture()
    item["request"]["op"] = "tip"
    check("wrong_history_operation", history_record(0, item)["observer_validation"]["status"] == "unknown")
    item = fixture()
    observer(item)["tip"] = [2] * 32
    check("wrong_history_tip", history_record(0, item)["observer_validation"]["status"] == "unknown"
          and summarize(item)["client_import_cpu"]["complete_recorded_total_ns"] is None)
    item = fixture()
    observer(item)["after"] = [2] * 32
    check("wrong_history_after", history_record(0, item)["observer_validation"]["status"] == "unknown")
    item = fixture()
    observer(item)["supplied_packets"] = 1
    check("wrong_supplied_packet_count", history_record(0, item)["observer_validation"]["status"] == "unknown")
    return {"passed": len(passed), "controls": passed}


# These synthetic controls validate only this reader; they add no native tests.
host_checks = host_reader_selfcheck()
require(host_checks["passed"] == 22, "HOST_READER_SELF_CHECK_COUNT")
reader_checks = {"schema": "trnm-current-native-host-reader-selfchecks-v1", "host": host_checks,
                 "source_tests_executed": False, "native_tests_executed": 0, "acceptance_granted": False}
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
                            projection, compact = host_history_projection(value, target, record)
                            record["native_host_cost_projection"] = projection
                            excerpt = json.dumps(projection, sort_keys=True) + "\n"
                            console_excerpt = json.dumps(compact, sort_keys=True, separators=(",", ":")) + "\n"
                        else:
                            extra_key = EXTRA_KEY
                            fields = scalar_fields(value, extra_key)
                            record["scalar_fields"] = fields
                            excerpt = json.dumps({"artifact": target["id"], "member": info.filename,
                                                  "fields": fields}, sort_keys=True) + "\n"
                            console_excerpt = console_json(target, info.filename, fields)
                    else:
                        raise Refused("UNEXPECTED_NON_JSON_MEMBER")
                    record["read_status"] = "read"
                    with (output / f"excerpt-{member_index:04}.txt").open("x") as stream:
                        stream.write(excerpt)
                    record["excerpt_file"] = f"excerpt-{member_index:04}.txt"
                    rendered, displayed_lines, omitted_lines = bounded_console(
                        console_excerpt, MAX_STDOUT - printed, target, info.filename)
                    if native_report:
                        require(omitted_lines == 0, "NATIVE_HOST_CONSOLE_LIMIT")
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
                             and "native_host_cost_projection" in row}
                            == set(reports), "NATIVE_REPORT_SET_INCOMPLETE")
                require({row["member"] for row in records if row.get("source_guard_verified")}
                        == SOURCE_MEMBERS, "ORIGINAL_SOURCE_GUARDS_INCOMPLETE")
        finally:
            print("::" + command_token + "::", flush=True)
        result = {
            "schema": "trnm-current-native-host-artifact-readback-v1",
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
    "schema": "trnm-current-native-host-readback-cohort-v1",
    "planned_artifacts": len(TARGETS), "results": results,
    "source_tests_executed": False, "acceptance_granted": False,
    "production_activation": False})
raise SystemExit(1 if had_error else 0)
