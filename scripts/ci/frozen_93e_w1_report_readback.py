#!/usr/bin/env python3
"""Read four fixed original 93e W1 reports; never execute archived code or grant acceptance."""

import hashlib, json, os, re, urllib.error, urllib.parse, urllib.request, uuid, zipfile
from pathlib import Path, PurePosixPath

REPO = "TrillionniumFoundation/Trillionnium-Chain"
BRANCH = "fix/chain-retained-failure-readback-20261104"
BASE = "dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
TARGETS = json.loads(r'''[{"id":13309739790,"name":"w1-fresh-service-head-93e207c8d2ccb8509f78566223abc371b9d8118b-1","size":5295198,"digest":"sha256:df3c4b375bada7baafa983bed982cf4bc2d23a53910f308f5ad27f9338217944","run":41806693679,"job":126495364919,"head":"93e207c8d2ccb8509f78566223abc371b9d8118b","kind":"head","tested":"93e207c8d2ccb8509f78566223abc371b9d8118b","tree":"1066c67970802b52070ece6fcc77bc9b2806a4e1","family":"fresh"},{"id":13309968297,"name":"w1-fresh-service-prospective-merge-5afe5dd267578fe96d91f3800b4c1cd6dda1ef5e-1","size":5478924,"digest":"sha256:6e17cd4bd2440db274520e8350226c21a179efe3c6dd931bd9e75dc187656eac","run":41806693679,"job":126495365320,"head":"93e207c8d2ccb8509f78566223abc371b9d8118b","kind":"prospective-merge","tested":"5afe5dd267578fe96d91f3800b4c1cd6dda1ef5e","tree":"1066c67970802b52070ece6fcc77bc9b2806a4e1","family":"fresh"}]''')
ROOT = Path(os.environ["READBACK_OUT"])
API = "https://api.github.com/repos/" + REPO
TOKEN = os.environ["GH_TOKEN"]
MAX_METADATA = 2 * 1024 * 1024
MAX_MEMBER = 32 * 1024 * 1024
MAX_SELECTED = 160 * 1024 * 1024
MAX_MEMBERS = 25000
MAX_STDOUT = 70000
MAX_NODES = 200000

class Refused(Exception):
    pass

def require(condition, label):
    if not condition:
        raise Refused(label)

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

# The two ZIPs were authenticated by the prior successful W1 small-member reader.
# Report lengths/hashes were not observed there; inspect them under unchanged caps.
MANIFEST = "fresh-service/manifest.json"
REPORTS = (
    ("original", "fresh-service/original/report.json",
     "public-v3-signed-confirmation-pressure-v1",
     "from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline"),
    ("fresh", "fresh-service/fresh/report.json",
     "public-v3-fresh-challenge-confirmation-pressure-v1",
     "fresh_challenge::fresh_challenge_signed_confirmation_keeps_original_pressure_budget"),
)
FIXED_MEMBERS = frozenset(("source.json", "source-after.json", MANIFEST)
                         + tuple(row[1] for row in REPORTS))
MANIFEST_PINS = {
    13309739790: (8892, "e51b4b46bb645ecdab3fdafa9e31ad66c392c6a6a35bb9115001deff550849cf"),
    13309968297: (8914, "cb94ebe189767bdf1ddf7e1eba95968f6faa07819604708d01322986313c2c8f"),
}
MODES = ("attack-free-baseline", "from-zero-pressure")
WINDOW_NS = 4_000_000_000
SOURCE_PREDICATES = {
    "commit": "93e207c8d2ccb8509f78566223abc371b9d8118b",
    "original_producer_blob": "f08831277c66244cc8469285cdfc63aaafaecb48",
    "original_producer_path": "trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs",
    "fresh_producer_blob": "38d20a3344d40ea73a32982568dba14a275b1e10",
    "fresh_producer_path": "trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/fresh_challenge.rs",
    "fresh_driver_blob": "68a3c2307159e17773c6a33c2636c62ddca56507",
    "scope": "Read recorded predicate operands only; no W1, signature, state or acceptance validator runs.",
}

def bounded_json(value):
    # The same node cap applies to each fixed selected JSON member, including reports.
    stack = [value]
    visited = 0
    while stack:
        item = stack.pop()
        visited += 1
        require(visited <= MAX_NODES, "JSON_NODE_LIMIT")
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)

def source_matches(value, target, inner=False):
    # Original from-zero source_identity checks the tested checkout as a head.
    # Its inner merge checkout is not the outer event candidate.
    inner_fresh = inner
    kind = "head" if inner_fresh else target["kind"]
    candidate = target["tested"] if inner_fresh else target["head"]
    expected = {
        "schema": "trnm-ci-source-v1", "kind": kind,
        "tested_commit": target["tested"], "tested_tree": target["tree"],
        "candidate": candidate,
        "base": BASE if kind == "prospective-merge" else None,
        "prospective_merge": target["tested"] if kind == "prospective-merge" else None,
    }
    return (isinstance(value, dict) and all(key in value and value[key] == item
                                          for key, item in expected.items())
            and value.get("tracked_worktree_verified") is True
            and value.get("tests_executed_by_identity_check") is False)

def source_pair(value, target):
    states = []
    for key in ("source_before", "source_after"):
        sample = value.get(key)
        if sample is None:
            states.append("unknown")
        elif (isinstance(sample, dict) and sample.get("commit") == target["tested"]
              and sample.get("tree") == target["tree"]
              and source_matches(sample.get("tracked_source_identity"), target, inner=True)):
            states.append("verified")
        else:
            states.append("mismatch")
    equal = value.get("source_before") == value.get("source_after") if "unknown" not in states else None
    status = ("mismatch" if "mismatch" in states or equal is False else
              "verified" if states == ["verified", "verified"] else "unknown")
    return {"status": status, "before": states[0], "after": states[1],
            "before_after_equal": equal,
            "scope": "Exact original commit/tree and tracked source receipt; missing observations remain unknown."}

def selected_size(size, total):
    require(type(size) is int and type(total) is int and size >= 0 and total >= 0,
            "MEMBER_SIZE_TYPE")
    require(size <= MAX_MEMBER and total + size <= MAX_SELECTED, "BOUNDED_SIZE")


def field(obj, key, kind):
    """Missing/null/ill-typed operands remain unknown, not bool(value) or zero."""
    present = isinstance(obj, dict) and key in obj
    raw = obj.get(key) if isinstance(obj, dict) else None
    problem = "missing" if not present else "null" if raw is None else None
    valid = (type(raw) is bool if kind == "bool" else
             type(raw) is int and 0 <= raw < 1 << 64 if kind == "u64" else
             isinstance(raw, list) if kind == "list" else False)
    if problem is None and not valid:
        problem = "invalid_type_or_range"
    return {"value": raw if problem is None else None, "reason": problem,
            "present": present, "raw": raw}


def flag(obj, key):
    return field(obj, key, "bool")


def positive(obj, key):
    observed = field(obj, key, "u64")
    return {**observed, "value": observed["value"] > 0
            if observed["value"] is not None else None}


def empty_errors(obj):
    observed = field(obj, "verification_errors", "list")
    return {**observed, "value": len(observed["value"]) == 0
            if observed["value"] is not None else None}


def conjunction(operands):
    false = [key for key, item in operands.items() if item["value"] is False]
    unknown = [key for key, item in operands.items() if item["value"] is None]
    value = False if false else None if unknown else True
    return {"value": value, "all_inputs_known": not unknown,
            "false_predicates": false, "unknown_predicates": unknown,
            "operands": operands,
            "scope": "Three-valued readback of recorded operands; not a native execution or acceptance grant."}


def derived_operand(value, reason=None):
    return {"value": value, "reason": reason, "present": value is not None, "raw": None}


def consistent(reported, derived):
    return (reported == derived if type(reported) is bool and type(derived) is bool else None)


def pick(value, names):
    return {key: value.get(key) for key in names} if isinstance(value, dict) else None


def denominator(phase):
    count = field(phase, "client_confirmed_transactions", "u64")
    if count["value"] is not None and count["value"] > 1:
        count = {**count, "value": None, "reason": "outside_single_transaction_denominator"}
    value = count["value"]
    before = flag(phase, "client_confirmed_before_original_window_end")
    issues = []
    if value is not None and before["value"] is not None and bool(value) != before["value"]:
        issues.append("count_and_original_window_flag_disagree")
    start = field(phase, "business_started_ns", "u64")["value"]
    ended = field(phase, "confirmation_ended_ns", "u64")["value"]
    latency = field(phase, "client_confirmation_latency_ns", "u64")["value"]
    if start is not None and ended is not None:
        if ended < start:
            issues.append("confirmation_precedes_business")
        elif latency is not None and latency != ended - start:
            issues.append("confirmation_latency_mismatch")
    # The predicate's later Instant::now() sample is not recorded separately.
    # A false original flag cannot be overturned by an earlier timestamp.
    if value == 1 and ended is not None and ended >= WINDOW_NS:
        issues.append("reported_confirmation_outside_original_window")
    native = phase.get("independent_client_confirmation") if isinstance(phase, dict) else None
    if value == 1 and isinstance(native, dict):
        for key, expected in (("confirmed", True), ("finalized", False),
                              ("execution_authority", False)):
            got = flag(native, key)["value"]
            if got is not None and got is not expected:
                issues.append("native_confirmation_" + key + "_disagrees")
        depth = field(native, "depth", "u64")["value"]
        if depth is not None and depth != 6:
            issues.append("native_confirmation_depth_disagrees")
    return {
        "planned_signed_business_transactions": 1,
        "reported_count": count, "original_window_flag": before,
        "observed_count_slots": 0 if value is None else 1,
        "confirmed_transactions": value,
        "observed_unconfirmed_transactions": 1 - value if value is not None else None,
        "unobserved_count_slots": 1 if value is None else 0,
        "consistency_issues": issues,
        "scope": "One original signed business transaction per phase; RPCs, seven blocks, and replay attempts are separate denominators. Missing counts are unknown.",
    }


def call_projection(value, maximum):
    if value is None:
        return {"status": "unknown", "attempts": None, "rows": None}
    require(isinstance(value, list) and len(value) <= maximum, "CALL_LIST")
    rows = []
    for index, row in enumerate(value):
        require(isinstance(row, dict), "CALL_OBJECT")
        view = pick(row, ("started_ns", "ended_ns", "elapsed_wall_ns", "client_thread_cpu_ns",
                          "status", "returned_after_window", "returned_after_deadline", "error"))
        view["index"] = index
        for key in ("started_ns", "ended_ns", "elapsed_wall_ns", "client_thread_cpu_ns"):
            view[key] = field(row, key, "u64")["value"]
        for key in ("returned_after_window", "returned_after_deadline"):
            view[key] = flag(row, key)["value"]
        rows.append(view)
    return {"status": "observed", "attempts": len(rows), "rows": rows,
            "scope": "Literal call observations; no ACK or History response is counted as a confirmed business transaction."}


def replay_projection(value):
    if value is None:
        return {"status": "unknown", "attempts": None, "accepted": None,
                "rejected": None, "unknown_outcomes": None, "rows": None}
    require(isinstance(value, list) and len(value) <= 16, "REPLAY_LIST")
    rows, previous = [], -1
    for row in value:
        require(isinstance(row, dict), "REPLAY_OBJECT")
        index = field(row, "history_call_index", "u64")["value"]
        require(index is not None and previous < index < 16, "REPLAY_INDEX")
        previous = index
        view = pick(row, (
            "history_call_index", "history_request_ended_ns", "replay_started_ns",
            "replay_ended_ns", "replay_wall_ns", "replay_thread_cpu_ns",
            "prior_after", "next_after", "replay_accepted", "replay_error", "clock_scope"))
        view["replay_accepted"] = flag(row, "replay_accepted")["value"]
        observer = row.get("native_import_observation")
        view["native_import_observation_present"] = isinstance(observer, dict)
        view["native_import_observer_summary"] = pick(observer, (
            "schema", "tip", "after", "supplied_packets", "measurement_failures",
            "host_checks_are_nested_not_additive", "cpu_intervals_are_nested_not_additive",
            "phase_cpu_excludes_scoped_workers", "host_cpu_includes_each_calling_thread",
            "host_cpu_is_full_worker_cpu", "observation_has_consensus_authority"))
        rows.append(view)
    return {"status": "observed", "attempts": len(rows),
            "accepted": sum(row["replay_accepted"] is True for row in rows),
            "rejected": sum(row["replay_accepted"] is False for row in rows),
            "unknown_outcomes": sum(row["replay_accepted"] is None for row in rows),
            "rows": rows,
            "scope": "Original ordered import attempts. Their nested/parallel timings are not added to enclosing calls or phase elapsed time. Full observers remain in the raw report."}


def phase_projection(phase, index):
    phase = phase if isinstance(phase, dict) else {}
    observed = bool(phase)
    window = field(phase, "requested_window_ns", "u64")
    workers = field(phase, "workers", "u64")
    if window["value"] is not None:
        require(window["value"] == WINDOW_NS, "ORIGINAL_WINDOW")
    if workers["value"] is not None:
        require(workers["value"] == 16 * index, "ORIGINAL_WORKERS")
    business = conjunction({
        "client_confirmed_before_original_window_end": flag(phase, "client_confirmed_before_original_window_end"),
        "overlap_demonstrated": flag(phase, "overlap_demonstrated"),
        "verification_errors_empty": empty_errors(phase),
    })
    reported_business = flag(phase, "finite_business_target_met")
    timelines = pick(phase, (
        "business_started_ns", "confirmation_ended_ns", "client_confirmation_latency_ns",
        "independent_replay_and_confirmation_cpu_ns", "independent_replay_and_confirmation_wall_ns",
        "independent_final_confirmation_stage", "independent_client_confirmation",
        "completed_false_calls_before_business", "completed_false_calls_at_confirmation",
        "overlapping_false_calls", "verification_errors"))
    return {
        "phase_index": index, "mode": MODES[index], "observed": observed,
        "requested_window_ns": window, "workers": workers,
        "reported_invariant_target_met": flag(phase, "invariant_target_met"),
        "reported_finite_business_target_met": reported_business,
        "finite_business_predicates": business,
        "finite_business_report_consistent_with_recorded_operands":
            consistent(reported_business["value"], business["value"]),
        "confirmation_denominator": denominator(phase),
        "timeline_and_confirmation": timelines,
        "recorded_invariant_inputs": {
            **pick(phase, ("no_attack_accepted", "accounting_closed",
                           "receiver_matches_valid_honest_prefix", "full_native_state_equal")),
            "service": pick(phase.get("service"), ("error", "status")),
            "scope": "Recorded inputs only; coverage_complete, accounting, roots and signatures are not recomputed.",
        },
        "submissions": call_projection(phase.get("honest_submissions"), 64),
        "history": call_projection(phase.get("honest_history"), 16),
        "heads": call_projection(phase.get("honest_heads"), 256),
        "replays": replay_projection(phase.get("independent_history_page_replay")),
    }


def project_report(value, kind):
    require(isinstance(value, dict), "REPORT_OBJECT")
    spec = next(row for row in REPORTS if row[0] == kind)
    require(value.get("schema") == spec[2], "REPORT_SCHEMA")
    original_phases = value.get("phases")
    if original_phases is None:
        original_phases = []
    require(isinstance(original_phases, list) and len(original_phases) <= 2
            and all(isinstance(row, dict) for row in original_phases), "REPORT_PHASES")
    modes = [row.get("mode") for row in original_phases]
    require(all(mode in MODES for mode in modes) and len(set(modes)) == len(modes)
            and modes == sorted(modes, key=MODES.index), "PHASE_IDENTITIES")
    phase_map = {row["mode"]: row for row in original_phases}
    phases = [phase_projection(phase_map.get(mode), index) for index, mode in enumerate(MODES)]
    operands = {}
    construction = None
    if kind == "fresh":
        coverage = value.get("construction_coverage")
        cpu = field(value, "shared_material_setup_cpu_ns", "u64")
        construction = conjunction({
            "constructed_positive": positive(coverage, "constructed"),
            "full_transcript_rejections_positive": positive(coverage, "full_transcript_rejections"),
            "all_context_bindings_and_challenges_unique":
                flag(coverage, "all_context_bindings_and_challenges_unique"),
            "all_nested_cpu_measurements_known": flag(coverage, "all_nested_cpu_measurements_known"),
            "shared_material_setup_cpu_known":
                {**cpu, "value": cpu["value"] is not None if cpu["reason"] is None else None},
        })
        # A recorded null is the source's None case, hence a known false operand.
        if cpu["present"] and cpu["raw"] is None:
            construction["operands"]["shared_material_setup_cpu_known"] = {
                **cpu, "value": False, "reason": "recorded_none"}
            construction = conjunction(construction["operands"])
        operands["construction_valid"] = derived_operand(
            construction["value"], None if construction["all_inputs_known"] else "construction_operand_unknown")
    for label, phase in zip(("baseline", "pressure"), phases):
        operands[label + "_invariant_target_met"] = phase["reported_invariant_target_met"]
        operands[label + "_finite_business_target_met"] = phase["reported_finite_business_target_met"]
    composite = conjunction(operands)
    invariant = conjunction({key: item for key, item in operands.items()
                             if key.endswith("_invariant_target_met")})
    counts = [phase["confirmation_denominator"] for phase in phases]
    known = [row["confirmed_transactions"] for row in counts
             if row["confirmed_transactions"] is not None]
    return {
        "schema": "trnm-original-w1-report-readback-v1", "report_kind": kind,
        "original_schema": value["schema"], "original_selector": spec[3],
        "source_predicates": SOURCE_PREDICATES,
        "reported_finite_target_met": flag(value, "finite_target_met"),
        "reported_invariant_target_met": flag(value, "invariant_target_met"),
        "fresh_construction_predicates": construction,
        "recorded_construction_coverage": value.get("construction_coverage") if kind == "fresh" else None,
        "finite_target_composite": composite,
        "reported_finite_target_consistent_with_recorded_operands":
            consistent(flag(value, "finite_target_met")["value"], composite["value"]),
        "original_native_assertion": composite if kind == "fresh" else invariant,
        "native_assertion_scope": ("Fresh native assertion is construction plus both phase invariant and finite-business predicates."
                                  if kind == "fresh" else
                                  "Original native assertion covers only both invariant predicates; finite business remains a separate failed gate."),
        "confirmation_denominator": {
            "planned_signed_business_transactions": 2, "observed_count_slots": len(known),
            "known_confirmed_transactions": sum(known),
            "known_observed_unconfirmed_transactions": sum(1 - count for count in known),
            "unobserved_count_slots": 2 - len(known),
            "complete_confirmed_transactions": sum(known) if len(known) == 2 else None,
            "scope": "Two separate original phases, one signed business transaction each; not independent rounds or a new combined acceptance threshold.",
        },
        "phases": phases,
        "source_tests_executed": False, "native_tests_executed": 0,
        "observation_has_consensus_authority": False, "acceptance_granted": False,
        "production_activation": False,
        "scope": "Readback only. Preserve original process, named-test, report-validation and business outcomes separately. Missing and malformed operands remain unknown; false business predicates are evidence, not reader failure or acceptance.",
    }


def native_outcome(row):
    return pick(row, ("name", "process", "passed", "failure", "failure_diagnostic",
                      "named_execution", "report", "report_path", "log_sha256"))


def self_checks():
    def fixture(kind="fresh"):
        phases = []
        for index, mode in enumerate(MODES):
            phases.append({
                "mode": mode, "requested_window_ns": WINDOW_NS, "workers": 16 * index,
                "invariant_target_met": True, "finite_business_target_met": True,
                "client_confirmed_before_original_window_end": True,
                "client_confirmed_transactions": 1, "overlap_demonstrated": True,
                "verification_errors": [], "business_started_ns": 10,
                "confirmation_ended_ns": 100, "client_confirmation_latency_ns": 90,
                "independent_client_confirmation": {
                    "confirmed": True, "finalized": False, "execution_authority": False, "depth": 6},
                "honest_submissions": [], "honest_history": [], "honest_heads": [],
                "independent_history_page_replay": [],
            })
        return {
            "schema": REPORTS[1 if kind == "fresh" else 0][2],
            "finite_target_met": True, "invariant_target_met": True, "phases": phases,
            "shared_material_setup_cpu_ns": 1,
            "construction_coverage": {
                "constructed": 2, "full_transcript_rejections": 2,
                "all_context_bindings_and_challenges_unique": True,
                "all_nested_cpu_measurements_known": True},
        }

    names = []

    def check(name, condition):
        require(condition, "SELFCHECK:" + name)
        names.append(name)

    def refusal(name, action):
        try:
            action()
        except Refused:
            names.append(name)
        else:
            raise Refused("SELFCHECK_NOT_REFUSED:" + name)

    value = project_report(fixture(), "fresh")
    check("complete_positive", value["finite_target_composite"]["value"] is True
          and value["confirmation_denominator"]["complete_confirmed_transactions"] == 2)
    doc = fixture()
    doc["phases"][1]["finite_business_target_met"] = False
    doc["finite_target_met"] = False
    value = project_report(doc, "fresh")
    check("fresh_false_business_operand", value["finite_target_composite"]["false_predicates"]
          == ["pressure_finite_business_target_met"]
          and value["reported_finite_target_consistent_with_recorded_operands"] is True)
    doc = fixture()
    doc["construction_coverage"]["constructed"] = 0
    value = project_report(doc, "fresh")
    check("construction_zero_known_false", value["fresh_construction_predicates"]["value"] is False)
    doc = fixture()
    del doc["construction_coverage"]["constructed"]
    value = project_report(doc, "fresh")
    check("construction_missing_unknown", value["fresh_construction_predicates"]["value"] is None
          and value["finite_target_composite"]["value"] is None)
    doc = fixture()
    doc["construction_coverage"]["constructed"] = True
    check("bool_not_counter", project_report(doc, "fresh")["fresh_construction_predicates"]["value"] is None)
    doc = fixture()
    doc["phases"][1]["finite_business_target_met"] = 1
    check("integer_not_boolean", project_report(doc, "fresh")["finite_target_composite"]["value"] is None)
    doc = fixture()
    doc["shared_material_setup_cpu_ns"] = None
    check("recorded_setup_cpu_none_is_source_false",
          project_report(doc, "fresh")["fresh_construction_predicates"]["value"] is False)
    doc = fixture()
    del doc["shared_material_setup_cpu_ns"]
    check("missing_setup_cpu_unknown", project_report(doc, "fresh")["fresh_construction_predicates"]["value"] is None)
    doc = fixture()
    del doc["phases"][1]["client_confirmed_transactions"]
    value = project_report(doc, "fresh")["confirmation_denominator"]
    check("unobserved_count_not_zero",
          value == {"planned_signed_business_transactions": 2, "observed_count_slots": 1,
                    "known_confirmed_transactions": 1, "known_observed_unconfirmed_transactions": 0,
                    "unobserved_count_slots": 1, "complete_confirmed_transactions": None,
                    "scope": value["scope"]})
    doc = fixture()
    doc["phases"][1]["client_confirmed_transactions"] = 0
    doc["phases"][1]["client_confirmed_before_original_window_end"] = False
    value = project_report(doc, "fresh")
    count = value["confirmation_denominator"]
    check("observed_unconfirmed_denominator",
          count["known_confirmed_transactions"] + count["known_observed_unconfirmed_transactions"]
          + count["unobserved_count_slots"] == 2
          and count["known_observed_unconfirmed_transactions"] == 1
          and not value["phases"][1]["confirmation_denominator"]["consistency_issues"])
    doc = fixture()
    doc["phases"][1]["client_confirmed_transactions"] = 2
    check("count_exceeding_denominator_unknown",
          project_report(doc, "fresh")["confirmation_denominator"]["unobserved_count_slots"] == 1)
    doc = fixture()
    doc["phases"][0]["client_confirmed_before_original_window_end"] = False
    check("inconsistent_count_flag_preserved",
          "count_and_original_window_flag_disagree" in
          project_report(doc, "fresh")["phases"][0]["confirmation_denominator"]["consistency_issues"])
    doc = fixture()
    doc["phases"] = [doc["phases"][0]]
    value = project_report(doc, "fresh")
    check("missing_phase_preserves_planned_slot",
          value["phases"][1]["observed"] is False
          and value["confirmation_denominator"]["unobserved_count_slots"] == 1
          and value["finite_target_composite"]["value"] is None)
    doc = fixture()
    doc["phases"][1] = dict(doc["phases"][0])
    refusal("duplicate_phase_refused", lambda: project_report(doc, "fresh"))
    doc = fixture()
    doc["schema"] = "unrelated-schema"
    refusal("wrong_report_schema_refused", lambda: project_report(doc, "fresh"))
    doc = fixture()
    del doc["phases"]
    value = project_report(doc, "fresh")["confirmation_denominator"]
    check("all_unobserved_slots_remain_unknown", value["unobserved_count_slots"] == 2
          and value["complete_confirmed_transactions"] is None)
    doc = fixture("original")
    doc["phases"][1]["finite_business_target_met"] = False
    value = project_report(doc, "original")
    check("original_native_assertion_separate_from_business",
          value["original_native_assertion"]["value"] is True
          and value["finite_target_composite"]["value"] is False)
    value = project_report(fixture(), "fresh")
    check("positive_never_grants_authority",
          value["acceptance_granted"] is False and value["production_activation"] is False
          and value["observation_has_consensus_authority"] is False
          and value["native_tests_executed"] == 0 and value["source_tests_executed"] is False)
    row = {"process": {"exit_code": 101, "timed_out": True}, "passed": False,
           "failure": "FRESH_NATIVE_PROCESS_REQUIRED", "report": None, "named_execution": None}
    check("native_failure_timeout_and_unexecuted_gate_preserved",
          native_outcome(row)["process"] == row["process"]
          and native_outcome(row)["report"] is None
          and native_outcome(row)["named_execution"] is None
          and native_outcome(row)["passed"] is False)
    refusal("member_size_cap", lambda: selected_size(MAX_MEMBER + 1, 0))
    refusal("aggregate_size_cap", lambda: selected_size(1, MAX_SELECTED))
    refusal("size_bool_refused", lambda: selected_size(True, 0))
    check("size_exact_boundary", selected_size(MAX_MEMBER, MAX_SELECTED - MAX_MEMBER) is None)
    check("wrong_source_rejected", not source_matches({"schema": "trnm-ci-source-v1"}, TARGETS[0]))
    # Exercise the console view with rich rows, a false operand and an unobserved count.
    doc = fixture()
    doc["construction_coverage"]["constructed"] = 0
    del doc["construction_coverage"]["full_transcript_rejections"]
    del doc["phases"][1]["client_confirmed_transactions"]
    for phase in doc["phases"]:
        phase["honest_history"] = [{"started_ns": index, "error": None} for index in range(16)]
        phase["independent_history_page_replay"] = [
            {"history_call_index": index, "replay_started_ns": index * 10,
             "replay_ended_ns": index * 10 + 9, "replay_wall_ns": 9,
             "replay_thread_cpu_ns": 4, "replay_accepted": True if index == 0 else None,
             "replay_error": None, "prior_after": "before-" + str(index),
             "next_after": "after-" + str(index)}
            for index in range(16)]
        phase["independent_client_confirmation"]["diagnostic_payload"] = "x" * 1024
    value = project_report(doc, "fresh")
    before = json.dumps(value, sort_keys=True, separators=(",", ":"))
    compact = compact_report(value)
    check("compact_does_not_mutate_full_projection",
          json.dumps(value, sort_keys=True, separators=(",", ":")) == before)
    changed_phase_keys = {"submissions", "history", "heads", "replays", "timeline_and_confirmation"}
    check("compact_preserves_predicates_denominators_and_unknowns",
          all(compact[key] == item for key, item in value.items() if key != "phases")
          and all(all(shown[key] == item for key, item in phase.items() if key not in changed_phase_keys)
                  for shown, phase in zip(compact["phases"], value["phases"]))
          and compact["confirmation_denominator"]["unobserved_count_slots"] == 1
          and compact["confirmation_denominator"]["complete_confirmed_transactions"] is None
          and compact["fresh_construction_predicates"]["false_predicates"] == ["constructed_positive"]
          and compact["fresh_construction_predicates"]["unknown_predicates"] == ["full_transcript_rejections_positive"])
    missing = fixture()
    del missing["phases"][0]["independent_history_page_replay"]
    missing_compact = compact_report(project_report(missing, "fresh"))
    check("compact_preserves_replay_counts_last_row_and_missing",
          all(phase["replays"]["attempts"] == 16 and phase["replays"]["accepted"] == 1
              and phase["replays"]["rejected"] == 0 and phase["replays"]["unknown_outcomes"] == 15
              and phase["replays"]["console_rows_omitted"] == 15
              and phase["replays"]["rows"] == [[15, 150, 159, 9, 4, None, None, "before-15", "after-15", False]]
              for phase in compact["phases"])
          and missing_compact["phases"][0]["replays"]["rows"] is None
          and missing_compact["phases"][0]["replays"]["console_rows_omitted"] is None
          and missing_compact["phases"][1]["replays"]["rows"] == []
          and missing_compact["phases"][1]["replays"]["console_rows_omitted"] == 0)
    compact_bytes = len(json.dumps(compact, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    check("compact_reduces_console_and_retains_confirmation_operands",
          compact_bytes < len(before.encode("utf-8"))
          and 4 * (compact_bytes + 1) < MAX_STDOUT - 12000
          and all(phase["timeline_and_confirmation"]["independent_client_confirmation"] ==
                  {"confirmed": True, "finalized": False, "execution_authority": False, "depth": 6}
                  for phase in compact["phases"])
          and all(phase["timeline_and_confirmation"]["independent_client_confirmation"]["diagnostic_payload"] == "x" * 1024
                  for phase in value["phases"]))
    return {"schema": "trnm-w1-report-reader-selfchecks-v1", "controls": names,
            "passed": len(names), "source_tests_executed": False, "native_tests_executed": 0,
            "acceptance_granted": False, "production_activation": False}


STDOUT_LEFT = MAX_STDOUT


def emit(value, reserve=0):
    global STDOUT_LEFT
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    size = len(rendered.encode("utf-8"))
    if size <= STDOUT_LEFT - reserve:
        print(rendered, end="", flush=True)
        STDOUT_LEFT -= size
        return True
    return False


def compact_report(projection):
    # Complete projection/raw bytes remain in files; only the console view is reduced.
    value = dict(projection)
    value["phases"] = []
    for phase in projection["phases"]:
        row = dict(phase)
        for key in ("submissions", "history", "heads"):
            row[key] = {name: phase[key][name] for name in ("status", "attempts")}
        row["replays"] = {key: item for key, item in phase["replays"].items() if key != "rows"}
        replays = phase["replays"]["rows"]
        last_replays = replays[-1:] if replays is not None else None
        fields = ("history_call_index", "replay_started_ns", "replay_ended_ns",
                  "replay_wall_ns", "replay_thread_cpu_ns", "replay_accepted", "replay_error",
                  "prior_after", "next_after", "native_import_observation_present")
        row["replays"]["columns"] = fields
        row["replays"]["rows"] = [[item.get(key) for key in fields] for item in last_replays] if last_replays is not None else None
        row["replays"]["console_rows_omitted"] = len(replays) - len(last_replays) if replays is not None else None
        timeline = dict(phase["timeline_and_confirmation"])
        confirmation = timeline.get("independent_client_confirmation")
        if isinstance(confirmation, dict):
            timeline["independent_client_confirmation"] = {
                key: confirmation[key] for key in ("confirmed", "finalized", "execution_authority", "depth")
                if key in confirmation}
        row["timeline_and_confirmation"] = timeline
        value["phases"].append(row)
    value["console_scope"] = "All predicate operands and planned business slots; each replay summary keeps its last observed row. Full calls, confirmation fields and replay rows remain unchanged in the retained projection and raw report."
    return value


def read_target(target):
    output = ROOT / str(target["id"])
    output.mkdir(exist_ok=False)
    records, omissions, projection_errors = [], [], []
    selected_bytes = 0
    stage = "metadata"
    result = {
        "schema": "trnm-w1-report-artifact-readback-v1", "target": target,
        "records": records, "omitted_members": omissions,
        "projection_errors": projection_errors,
        "source_tests_executed": False, "native_tests_executed": 0,
        "acceptance_granted": False, "production_activation": False,
        "observation_has_consensus_authority": False,
    }
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
        result["downloaded_zip_bytes"] = archive(target, path)
        result["downloaded_zip_sha256"] = target["digest"].split(":", 1)[1]
        stage = "members"
        with zipfile.ZipFile(path) as bundle:
            infos = bundle.infolist()
            require(len(infos) <= MAX_MEMBERS, "MEMBER_COUNT")
            require(len(infos) == len({info.filename for info in infos}), "DUPLICATE_MEMBER")
            for info in infos:
                parts = PurePosixPath(info.filename).parts
                require(not info.filename.startswith("/") and ".." not in parts
                        and "\\" not in info.filename, "MEMBER_PATH")
            index = [{"name": info.filename, "bytes": info.file_size,
                      "compressed_bytes": info.compress_size, "crc32": info.CRC} for info in infos]
            result["member_index_sha256"] = write_json(output / "members.json", index)
            chosen = sorted((info for info in infos if not info.is_dir()
                             and info.filename in FIXED_MEMBERS), key=lambda info: info.filename)
            result["absent_fixed_members"] = sorted(FIXED_MEMBERS - {info.filename for info in chosen})
            for number, info in enumerate(chosen):
                try:
                    selected_size(info.file_size, selected_bytes)
                except Refused as error:
                    omissions.append({"member": info.filename, "indexed_bytes": info.file_size,
                                      "reason": str(error)})
                    continue
                # Same bounded ZipFile read as the successful predecessor, including CRC.
                raw = bundle.read(info)
                selected_bytes += len(raw)
                require(len(raw) == info.file_size, "MEMBER_SIZE")
                record = {"member": info.filename, "bytes": len(raw),
                          "sha256": hashlib.sha256(raw).hexdigest(),
                          "original_member_file": f"original-member-{number:04}.bin"}
                with (output / record["original_member_file"]).open("xb") as stream:
                    stream.write(raw)
                records.append(record)
                try:
                    text = raw.decode("utf-8")
                    value = json.loads(text)
                    bounded_json(value)
                    record["original_json"] = value
                    record["read_status"] = "observed"
                except Exception as error:
                    record["read_status"] = "uninterpreted"
                    record["error_type"] = type(error).__name__
                    record["reason"] = str(error) if isinstance(error, Refused) else None
                if info.filename == MANIFEST:
                    size, digest = MANIFEST_PINS[target["id"]]
                    require(record["bytes"] == size and record["sha256"] == digest, "MANIFEST_PIN")
        result["selected_text_bytes"] = selected_bytes
        by_name = {record["member"]: record for record in records}
        stage = "source_guards"
        sources = {}
        for name in ("source.json", "source-after.json"):
            record = by_name.get(name)
            value = record.get("original_json") if record else None
            verified = source_matches(value, target)
            sources[name] = {"status": "verified" if verified else
                             "unknown" if value is None else "mismatch",
                             "original_fields": value}
        result["original_source_guards"] = sources
        require(all(item["status"] == "verified" for item in sources.values()),
                "ORIGINAL_SOURCE_GUARD_REQUIRED")
        require(sources["source.json"]["original_fields"] == sources["source-after.json"]["original_fields"],
                "ORIGINAL_SOURCE_GUARDS_CHANGED")
        manifest_record = by_name.get(MANIFEST)
        manifest = manifest_record.get("original_json") if manifest_record else None
        require(isinstance(manifest, dict)
                and manifest.get("schema") == "trnm-w1-fresh-service-execution-v1", "MANIFEST_SCHEMA")
        result["native_source_binding"] = source_pair(manifest, target)
        require(result["native_source_binding"]["status"] == "verified", "NATIVE_SOURCE_PAIR")
        require(manifest.get("source_expected") == target["tested"], "MANIFEST_EXPECTED_SOURCE")
        runs = manifest.get("runs")
        require(isinstance(runs, list) and len(runs) == 2
                and all(isinstance(row, dict) for row in runs)
                and [row.get("name") for row in runs] == [spec[3] for spec in REPORTS],
                "ORIGINAL_SELECTOR_IDENTITIES")
        result["original_manifest_outcome"] = pick(manifest, (
            "schema", "passed", "all_named_tests_passed", "execution_finished", "failures",
            "requested_window_ns", "attack_workers", "production_activation"))
        stage = "report_projection"
        for spec, native in zip(REPORTS, runs):
            kind, member, _, _ = spec
            require(native.get("report_path") == kind + "/report.json", "REPORT_PATH_BINDING")
            record = by_name.get(member)
            if record is None or record.get("read_status") != "observed":
                projection_errors.append({"member": member, "status": "unknown",
                                          "reason": "REPORT_MEMBER_UNREAD"})
                continue
            try:
                projection = project_report(record["original_json"], kind)
                projection.update({
                    "artifact": target["id"], "measured_run": target["run"],
                    "measured_job": target["job"], "measured_head": target["head"],
                    "tested_commit": target["tested"], "tested_tree": target["tree"],
                    "member": member, "member_bytes": record["bytes"],
                    "member_sha256": record["sha256"],
                    "original_manifest_native_outcome": native_outcome(native),
                })
                record["report_projection"] = projection
                record["projection_file"] = kind + "-projection.json"
                write_json(output / record["projection_file"], projection)
                record["console_projection_emitted"] = emit(compact_report(projection), reserve=12000)
            except Exception as error:
                projection_errors.append({
                    "member": member, "status": "unknown", "error_type": type(error).__name__,
                    "reason": str(error) if isinstance(error, Refused) else None})
        complete = (not result["absent_fixed_members"] and not omissions
                    and not projection_errors
                    and all(record.get("read_status") == "observed" for record in records)
                    and sum("report_projection" in record for record in records) == 2)
        result["reader_status"] = "completed" if complete else "failed"
    except Exception as error:
        result.update({"reader_status": "failed", "stage": stage,
                       "error_type": type(error).__name__, "http_status": getattr(error, "code", None),
                       "reason": str(error) if isinstance(error, Refused) else None,
                       "selected_text_bytes": selected_bytes})
    result["scope"] = (
        "Five fixed JSON members from one authenticated original failed W1 archive. "
        "Full ZIP and selected bytes are retained. Reader completion is evidence extraction only; "
        "original native/report/business failures, timeouts and unknowns remain unchanged.")
    write_json(output / "readback.json", result)
    summary = {key: item for key, item in result.items() if key != "records"}
    summary["records"] = len(records)
    summary["reports_projected"] = sum("report_projection" in record for record in records)
    summary["console_reports_omitted"] = sum(
        record.get("console_projection_emitted") is False for record in records)
    summary["report_member_identities"] = [
        {key: record.get(key) for key in ("member", "bytes", "sha256", "read_status")}
        for record in records if record["member"] in {spec[1] for spec in REPORTS}]
    emit(summary)
    return summary


def main():
    require(os.environ["GITHUB_REPOSITORY"] == REPO, "REPOSITORY")
    require(os.environ["GITHUB_REF"] == "refs/heads/" + BRANCH, "REF")
    require(os.environ["GITHUB_EVENT_NAME"] == "push", "EVENT")
    require(len(TARGETS) == len({row["id"] for row in TARGETS}) == 2, "TARGETS")
    require(set(MANIFEST_PINS) == {row["id"] for row in TARGETS}, "MANIFEST_TARGETS")
    controls = self_checks()
    write_json(ROOT / "reader-selfchecks.json", controls)
    emit(controls)
    # Stop Actions command interpretation while displaying any archived values.
    token = uuid.uuid4().hex
    print("::stop-commands::" + token, flush=True)
    try:
        results = [read_target(target) for target in TARGETS]
        cohort = {
            "schema": "trnm-w1-report-readback-cohort-v1",
            "planned_artifacts": 2, "planned_report_members": 4, "planned_phase_slots": 8,
            "results": results, "source_tests_executed": False, "native_tests_executed": 0,
            "acceptance_granted": False, "production_activation": False,
            "observation_has_consensus_authority": False,
            "scope": "Two original W1 jobs, each with original and fresh reports. Distinct phases keep their original one-business denominator; no new acceptance or performance comparison.",
        }
        write_json(ROOT / "readback.json", cohort)
        return 1 if any(row["reader_status"] != "completed" for row in results) else 0
    finally:
        print("::" + token + "::", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
