#!/usr/bin/env python3
"""Stream two exact retained 69d main databases under explicit diagnostic-only caps."""
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
import zlib
from pathlib import Path, PurePosixPath

REPO = "TrillionniumFoundation/Trillionnium-Chain"
BRANCH = "fix/chain-retained-failure-readback-20261104"
BASE = "dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
TARGETS = json.loads(r'''[{"id":13311000045,"name":"priority-ubuntu-24.04-arm-head-history-69d2e06c48bbbd1e22432f9b557727b140aba361-1","size":61135040,"digest":"sha256:21c716dbe9afccf8f7dea9073ec6beaa13e3bd7c46e20a011e3520f03cc2c6e5","run":41799271270,"job":126471217803,"head":"69d2e06c48bbbd1e22432f9b557727b140aba361","kind":"head","tested":"69d2e06c48bbbd1e22432f9b557727b140aba361","tree":"d9327a589886a3fbf105b268c0bcff70a9852e6b","family":"history","pinned_tip":"4ec7ceacfab64f69595ededeabe5d664e2c2f637f283bd6bd1a5e15d4005d598","last_successful_after":"2f381967b64813bdc9b37dd4f41a84199baae3f038af334f68e1fa10766d298c"},{"id":13311101182,"name":"priority-ubuntu-24.04-arm-prospective-merge-history-69d2e06c48bbbd1e22432f9b557727b140aba361-1","size":61147421,"digest":"sha256:7242a8e2938718e9b582d6680208d4421d0a32756e6775f25e6b5328eaabfd26","run":41799271270,"job":126471218057,"head":"69d2e06c48bbbd1e22432f9b557727b140aba361","kind":"prospective-merge","tested":"bfdfc2bfd4f8ff9cffb6a1711384464abd469ea4","tree":"d9327a589886a3fbf105b268c0bcff70a9852e6b","family":"history","pinned_tip":"a865f5ab93295f1eaa30353bb8259f8da3485540e7535721680a2654394e5fbc","last_successful_after":"2173b7c7d191d68644aa9dd436bea615ff2d51d5689f34395f8fa14b1c7692ee"}]''')
EXPECTED_DDL = json.loads(r'''{"metadata":"CREATE TABLE metadata(key TEXT PRIMARY KEY,value BLOB NOT NULL)","blocks":"CREATE TABLE blocks(id BLOB PRIMARY KEY,parent BLOB,height INTEGER NOT NULL,chainwork BLOB NOT NULL,packet BLOB,state_root BLOB NOT NULL)","active":"CREATE TABLE active(singleton INTEGER PRIMARY KEY CHECK(singleton=1),tip BLOB NOT NULL,generation INTEGER NOT NULL,state_slot INTEGER NOT NULL)","reorg":"CREATE TABLE reorg(singleton INTEGER PRIMARY KEY CHECK(singleton=1),old_tip BLOB NOT NULL,new_tip BLOB NOT NULL,generation INTEGER NOT NULL,cursor INTEGER NOT NULL,done INTEGER NOT NULL)","reorg_lifecycle_v1":"CREATE TABLE reorg_lifecycle_v1(operation INTEGER PRIMARY KEY AUTOINCREMENT,old_tip BLOB NOT NULL CHECK(length(old_tip)=32),new_tip BLOB NOT NULL CHECK(length(new_tip)=32),generation INTEGER NOT NULL CHECK(generation>0),old_slot INTEGER NOT NULL CHECK(old_slot>=0),old_root BLOB NOT NULL CHECK(length(old_root)=32),owner_context BLOB NOT NULL CHECK(length(owner_context)=32),outcome INTEGER NOT NULL CHECK(outcome IN (0,1,2)),cancelled_cursor INTEGER,reason TEXT NOT NULL CHECK(length(reason)<=96),CHECK((outcome IN (0,1) AND cancelled_cursor IS NULL AND reason='') OR (outcome=2 AND cancelled_cursor>=0 AND length(reason)>0)))","steps":"CREATE TABLE steps(ordinal INTEGER PRIMARY KEY,kind INTEGER NOT NULL,block BLOB NOT NULL)"}''')
ROOT = Path(os.environ["READBACK_OUT"])
API = "https://api.github.com/repos/" + REPO
TOKEN = os.environ["GH_TOKEN"]
MAX_METADATA = 2 * 1024 * 1024
MAX_MEMBER = 32 * 1024 * 1024
MAX_SELECTED = 160 * 1024 * 1024
MAX_MEMBERS = 25000
MAX_STDOUT = 70000
MAX_NODES = 200000
MAX_SQL_VM_STEPS = 200000
MAX_SQL_SECONDS = 5
STREAM_CHUNK = 1024 * 1024
EXACT_MAIN_DATABASES = {
    13311000045: {"bytes": 220749824, "compressed_bytes": 22920177},
    13311101182: {"bytes": 220811264, "compressed_bytes": 22931478},
}
PRIOR_GENERIC_REFUSAL = {
    "run": 41812595146, "job": 126515293786,
    "evidence_blob": "4a82c6a726841179196204ac1ae0ca419fb60a54",
    "snapshot_status": "unavailable",
    "reason": "Both exact main databases exceeded the unchanged generic member bound.",
}
PREFIX = "history-native/long-history/confirmer/"
DB_NAME = PREFIX + "native.sqlite"
DB_MEMBERS = (DB_NAME, DB_NAME + "-wal", DB_NAME + "-shm", DB_NAME + "-journal")
TEXT_MEMBERS = (
    "source.json", "history-native/manifest.json", "history-native/history.log",
    "history-native/long-history/config.json",
    "history-native/long-history/source.json",
    "history-native/long-history/summary.json",
)
HISTORY_SELECTOR = "actual_v3_long_chain_public_full_sync_reopen_and_corrupt_index_refusal"

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

def bounded_json(value):
    # Only fixed small selected JSON members are visited. No raw native report is selected.
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
    # Fresh preparation always checks the actual tested checkout as a head.
    # Its merge checkout is not the outer event candidate.
    inner_fresh = inner and target["family"] == "fresh"
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

require(os.environ["GITHUB_REPOSITORY"] == REPO, "REPOSITORY")
require(os.environ["GITHUB_REF"] == "refs/heads/" + BRANCH, "REF")
require(os.environ["GITHUB_EVENT_NAME"] == "push", "EVENT")
require(len(TARGETS) == len({row["id"] for row in TARGETS}) == 2, "TARGETS")
require(all(row["family"] == "history" for row in TARGETS), "FAMILIES")
require({row["id"] for row in TARGETS} == set(EXACT_MAIN_DATABASES), "FIXED_DATABASE_TARGETS")
require(ROOT.is_dir() and ROOT.is_absolute(), "OUTPUT_DIRECTORY")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def parse_object(raw):
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    require(isinstance(value, dict), "JSON_OBJECT")
    bounded_json(value)
    return value


def digest_file(path, limit=MAX_MEMBER):
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            require(total <= limit, "RETAINED_FILE_LIMIT")
            digest.update(chunk)
    return {"bytes": total, "sha256": digest.hexdigest()}


def retained_limit(name, target):
    # Only the one fixed basename under either already authenticated ZIP gets
    # its observed exact cap. All other selected members retain MAX_MEMBER.
    return EXACT_MAIN_DATABASES[target["id"]]["bytes"] if name == DB_NAME else MAX_MEMBER


def stream_fixed_database(bundle, info, destination, target):
    fixed = EXACT_MAIN_DATABASES[target["id"]]
    require(info.filename == DB_NAME and info.file_size == fixed["bytes"]
            and info.compress_size == fixed["compressed_bytes"], "EXACT_DATABASE_DIRECTORY_ENTRY")
    require(not destination.exists(), "DATABASE_DESTINATION_EXISTS")
    partial = destination.with_name(destination.name + ".readback-partial")
    digest = hashlib.sha256()
    total = 0
    crc = 0
    # ZipExtFile validates ZIP decoding; the explicit CRC check below also
    # binds every decompressed byte. No whole-database bytes object is created.
    with bundle.open(info) as source, partial.open("xb") as output:
        while True:
            block = source.read(STREAM_CHUNK)
            require(len(block) <= STREAM_CHUNK, "DATABASE_STREAM_CHUNK")
            if not block:
                break
            total += len(block)
            require(total <= fixed["bytes"], "EXACT_DATABASE_SIZE_OVERRUN")
            output.write(block)
            digest.update(block)
            crc = zlib.crc32(block, crc)
        require(total == fixed["bytes"] == info.file_size, "EXACT_DATABASE_EOF")
        require((crc & 0xffffffff) == info.CRC, "EXACT_DATABASE_CRC")
    partial.chmod(0o444)
    partial.rename(destination)
    return {"member": info.filename, "bytes": total, "sha256": digest.hexdigest(),
            "compressed_bytes": info.compress_size,
            "crc32_expected": info.CRC, "crc32_observed": crc & 0xffffffff,
            "crc32_verified": True, "stream_chunk_max_bytes": STREAM_CHUNK,
            "budget_scope": "explicit-fixed-main-database-diagnostic"}


def table_authorizer(action, first, second, database, context):
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ:
        allowed = set(EXPECTED_DDL) | {"sqlite_master", "sqlite_schema"}
        if database == "main" and first in allowed and context is None:
            return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION and second in ("hex", "length", "count", "min", "max"):
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA and first in ("query_only", "trusted_schema"):
        permitted = {"query_only": {"ON", "on", "1", None},
                     "trusted_schema": {"OFF", "off", "0", None}}
        if second in permitted[first]:
            return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def query_snapshot(path, target, genesis):
    started = time.monotonic_ns()
    vm_steps = 0

    def progress():
        nonlocal vm_steps
        vm_steps += 1000
        return int(vm_steps >= MAX_SQL_VM_STEPS or time.monotonic_ns() - started > MAX_SQL_SECONDS * 1_000_000_000)

    connection = None
    result = {"status": "unavailable", "sqlite_version": sqlite3.sqlite_version,
              "queries_executed": [], "schema_rows": None, "rows": None,
              "post_cleanup_snapshot": True, "activation_entry_at_failure": None,
              "original_failure_location_rewritten": False}
    try:
        # Preserve the original WAL/SHM pair and use SQLite's ordinary read-only
        # WAL path when it exists. Do not force immutable semantics onto that pair.
        wal_present = path.with_name(path.name + "-wal").exists()
        shm_present = path.with_name(path.name + "-shm").exists()
        require(wal_present == shm_present, "QUERY_SIDECAR_SET_CHANGED")
        uri = path.as_uri() + "?mode=ro&cache=private"
        if not wal_present:
            # Only an index-verified, frozen sidecar-free copy is immutable here.
            uri += "&immutable=1"
        result["sqlite_open_mode"] = ("read-only-retained-wal" if wal_present
                                      else "read-only-immutable-no-sidecars")
        connection = sqlite3.connect(uri, uri=True, timeout=0,
                                     isolation_level=None, cached_statements=0)
        connection.enable_load_extension(False)
        require(hasattr(connection, "setlimit"), "SQL_LIMIT_API_UNAVAILABLE")
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_METADATA)
        connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 16384)
        connection.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 64)
        connection.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH, 64)
        connection.set_progress_handler(progress, 1000)
        connection.set_authorizer(table_authorizer)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        require(connection.execute("PRAGMA query_only").fetchone() == (1,), "QUERY_ONLY")
        require(connection.execute("PRAGMA trusted_schema").fetchone() == (0,), "TRUSTED_SCHEMA")

        schema_sql = ("SELECT type,name,tbl_name,sql FROM main.sqlite_schema "
                      "WHERE name IN (?,?,?,?,?,?) ORDER BY name")
        schema_rows = connection.execute(schema_sql, tuple(sorted(EXPECTED_DDL))).fetchall()
        result["schema_rows"] = [list(row) for row in schema_rows]
        require(len(schema_rows) == len(EXPECTED_DDL), "SNAPSHOT_TABLE_SET")
        for kind, name, table, sql in schema_rows:
            require(kind == "table" and name == table and isinstance(sql, str)
                    and sql.strip().rstrip(";") == EXPECTED_DDL[name], "SNAPSHOT_TABLE_SCHEMA")
        result["queries_executed"].append({"name": "fixed_table_schema", "sql": schema_sql})

        def query(name, sql, parameters=(), cap=8):
            cursor = connection.execute(sql, parameters)
            columns = [item[0] for item in cursor.description]
            rows = cursor.fetchmany(cap + 1)
            require(len(rows) <= cap, "SQL_RESULT_ROW_LIMIT")
            output = []
            integer_columns = {"singleton", "generation", "state_slot", "operation", "old_slot",
                               "outcome", "cancelled_cursor", "cursor", "done", "kind",
                               "step_rows", "first_ordinal", "last_ordinal", "height"}
            nullable_integers = {"cancelled_cursor", "first_ordinal", "last_ordinal"}
            for row in rows:
                require(all(value is None or type(value) in (int, str) for value in row),
                        "SQL_VALUE_TYPE")
                for column, value in zip(columns, row):
                    if column in integer_columns:
                        require(type(value) is int or (value is None and column in nullable_integers),
                                "SQL_INTEGER_TYPE")
                # SQLite integers are decimal strings, avoiding downstream >2^53 loss.
                output.append({key: str(value) if type(value) is int else value
                               for key, value in zip(columns, row)})
            result["queries_executed"].append({"name": name, "sql": sql,
                                               "parameters": [value.hex() if isinstance(value, bytes)
                                                              else value for value in parameters],
                                               "row_count": len(output)})
            return output

        rows = {}
        rows["metadata"] = query("metadata",
            "SELECT key,hex(value) AS value FROM main.metadata "
            "WHERE key IN ('genesis','parameters') ORDER BY key", cap=2)
        require(any(row["key"] == "genesis" and row["value"].lower() == genesis
                    for row in rows["metadata"]), "SNAPSHOT_GENESIS_BINDING")
        rows["active"] = query("active",
            "SELECT singleton,hex(tip) AS tip,generation,state_slot FROM main.active ORDER BY singleton LIMIT 2",
            cap=1)
        rows["reorg"] = query("reorg",
            "SELECT singleton,hex(old_tip) AS old_tip,hex(new_tip) AS new_tip,generation,cursor,done "
            "FROM main.reorg ORDER BY singleton LIMIT 2", cap=1)
        rows["lifecycle_latest"] = query("lifecycle_latest",
            "SELECT operation,hex(old_tip) AS old_tip,hex(new_tip) AS new_tip,generation,old_slot,"
            "hex(old_root) AS old_root,hex(owner_context) AS owner_context,outcome,cancelled_cursor,reason "
            "FROM main.reorg_lifecycle_v1 ORDER BY operation DESC LIMIT 3", cap=3)
        rows["steps_summary"] = query("steps_summary",
            "SELECT kind,count(*) AS step_rows,min(ordinal) AS first_ordinal,max(ordinal) AS last_ordinal "
            "FROM main.steps GROUP BY kind ORDER BY kind LIMIT 3", cap=2)
        rows["lineage_records"] = query("lineage_records",
            "SELECT hex(id) AS id,CASE WHEN parent IS NULL THEN NULL ELSE hex(parent) END AS parent,"
            "height,hex(state_root) AS state_root "
            "FROM main.blocks WHERE id IN (?,?,?) ORDER BY height,id",
            (bytes.fromhex(genesis), bytes.fromhex(target["last_successful_after"]),
             bytes.fromhex(target["pinned_tip"])), cap=3)
        result["rows"] = rows
        reorg = rows["reorg"][0] if rows["reorg"] else None
        latest = rows["lifecycle_latest"][0] if rows["lifecycle_latest"] else None
        result["tip_binding"] = {
            "expected_pinned_tip": target["pinned_tip"],
            "expected_genesis": genesis,
            "reorg_new_tip_matches": (reorg["new_tip"].lower() == target["pinned_tip"]
                                     if reorg else None),
            "latest_lifecycle_new_tip_matches": (latest["new_tip"].lower() == target["pinned_tip"]
                                                if latest else None),
            "absence_does_not_prove_activation_not_entered": True,
        }
        result["status"] = "observed"
    except (sqlite3.Error, OSError, Refused, ValueError, TypeError) as error:
        result["error_type"] = type(error).__name__
        result["reason"] = str(error)[:500]
        result["rows"] = None
    finally:
        if connection is not None:
            try:
                connection.close()
            except sqlite3.Error as error:
                result["status"] = "unavailable"
                result["error_type"] = type(error).__name__
                result["reason"] = "SQLITE_CLOSE"
                result["rows"] = None
        result["sqlite_progress_callback_units"] = vm_steps
        result["sqlite_progress_limit_scope"] = (
            "Approximate 1000-unit progress callbacks check the configured VM and elapsed thresholds; "
            "these checks are not hard preemption or an original native cost measurement.")
        result["readback_elapsed_ns"] = time.monotonic_ns() - started
        result["readback_timing_is_not_original_native_cost"] = True
    return result


def verified_origin(raw, target):
    source = parse_object(raw["source.json"])
    manifest = parse_object(raw["history-native/manifest.json"])
    config = parse_object(raw["history-native/long-history/config.json"])
    summary = parse_object(raw["history-native/long-history/summary.json"])
    native_source = parse_object(raw["history-native/long-history/source.json"])
    require(source_matches(source, target), "ORIGINAL_SOURCE")
    require(type(source.get("tracked_entries")) is int and source["tracked_entries"] == 8127
            and type(source.get("tracked_bytes")) is int and source["tracked_bytes"] == 933472602,
            "ORIGINAL_SOURCE_SIZE")
    require(manifest.get("schema") == "trnm-ci-history-native-execution-v1"
            and manifest.get("target") == "ancestry_long_sync"
            and manifest.get("selector") == HISTORY_SELECTOR, "ORIGINAL_MANIFEST")
    require(source_pair(manifest, target)["status"] == "verified", "NATIVE_SOURCE_PAIR")
    require(manifest.get("passed") is False and manifest.get("process", {}).get("exit_code") == 101,
            "ORIGINAL_FAILURE")
    log_observation = manifest.get("log") or {}
    summary_observation = manifest.get("summary_file") or {}
    for name, observation in (("history-native/history.log", log_observation),
                              ("history-native/long-history/summary.json", summary_observation)):
        require(observation.get("sha256") == hashlib.sha256(raw[name]).hexdigest()
                and observation.get("size_bytes") == len(raw[name]), "ORIGINAL_MEMBER_BINDING")
    require(manifest.get("summary") == summary
            and summary.get("schema") == "native-ancestry-long-sync-observation-v1"
            and summary.get("passed") is False
            and summary.get("error") == "PUBLIC_REQUEST_DEADLINE", "ORIGINAL_SUMMARY")
    require(native_source.get("schema") == "native-ancestry-long-sync-source-v1",
            "NATIVE_SOURCE_SCHEMA")
    require(type(config.get("blocks")) is int and config["blocks"] == 4105
            and isinstance(config.get("genesis"), str)
            and re.fullmatch("[0-9a-f]{64}", config["genesis"]), "ORIGINAL_CONFIG")
    log = raw["history-native/history.log"].decode("utf-8")
    diagnostics = []
    diagnostic_literals = []
    for line in log.splitlines():
        if line.startswith("{"):
            value = parse_object(line.encode("utf-8"))
            if value.get("schema") == "native-ancestry-independent-sync-exit-evidence-v1":
                diagnostics.append(value)
                diagnostic_literals.append(line)
    require(len(diagnostics) == 1, "ORIGINAL_DIAGNOSTIC_COUNT")
    diagnostic = diagnostics[0]
    location = diagnostic.get("failure_location") or {}
    require(diagnostic.get("sync_error") == "PUBLIC_REQUEST_DEADLINE"
            and location.get("stage") == "import-call-expression"
            and type(location.get("completed_import_calls")) is int
            and location["completed_import_calls"] == 4104
            and location.get("advertised_page_complete") is True
            and location.get("pinned_tip") == target["pinned_tip"]
            and location.get("last_successful_after") == target["last_successful_after"]
            and "activation_cursor" in location and location["activation_cursor"] is None
            and "durable_committed_blocks" in location and location["durable_committed_blocks"] is None,
            "ORIGINAL_DIAGNOSTIC_BINDING")
    return {"source": source, "manifest_source_binding": source_pair(manifest, target),
            "original_manifest_passed": manifest.get("passed"),
            "original_native_execution_authenticated": manifest.get("native_execution_authenticated"),
            "original_failure_location": location,
            "original_sync_json_literal": diagnostic_literals[0],
            "genesis": config["genesis"]}


def inspect_one(target, output):
    result = {"schema": "trnm-retained-history-post-cleanup-snapshot-v2", "target": target,
              "reader_status": "failed", "snapshot_status": "unavailable",
              "scope": "Frozen retained bytes after the original call returned, Node drop and Host cleanup. "
                       "SQL observations are not the original failure-time cursor or a recovered Node state.",
              "diagnostic_budget_scope": {
                  "prior_generic_bound_refusal": PRIOR_GENERIC_REFUSAL,
                  "database_member": DB_NAME,
                  "database_exact_budget": EXACT_MAIN_DATABASES[target["id"]],
                  "generic_member_limit_unchanged": MAX_MEMBER,
                  "non_database_selected_limit_unchanged": MAX_SELECTED,
                  "combined_selected_cap": EXACT_MAIN_DATABASES[target["id"]]["bytes"] + MAX_SELECTED,
                  "stream_chunk_max_bytes": STREAM_CHUNK,
                  "original_native_budgets_changed": False,
                  "original_reader_refusal_reclassified": False,
              },
              "original_failure_location": None, "origin": None, "snapshot": None,
              "fixed_database_members": None, "selected_members": [], "unavailable_reasons": [],
              "files_before_query": None, "files_after_query": None,
              "source_tests_executed": False, "archive_code_executed": False,
              "acceptance_granted": False, "production_activation": False}
    metadata = read_json("/actions/artifacts/" + str(target["id"]))
    run = read_json("/actions/runs/" + str(target["run"]))
    job = read_json("/actions/jobs/" + str(target["job"]))
    require(metadata["id"] == target["id"] and metadata["name"] == target["name"], "ARTIFACT_IDENTITY")
    require(metadata["size_in_bytes"] == target["size"] and metadata["digest"] == target["digest"]
            and not metadata["expired"], "ARTIFACT_METADATA")
    require(metadata["workflow_run"]["id"] == run["id"] == job["run_id"] == target["run"], "RUN_IDENTITY")
    require(metadata["workflow_run"]["head_sha"] == run["head_sha"] == job["head_sha"] == target["head"],
            "SOURCE_IDENTITY")
    require(run["run_attempt"] == job["run_attempt"] == 1 and run["event"] == "pull_request",
            "ORIGINAL_RUN_ATTEMPT")
    require(job["id"] == target["job"] and job["status"] == "completed"
            and job["conclusion"] == "failure", "ORIGINAL_FAILED_JOB")
    for name, value in (("metadata.json", metadata), ("run.json", run), ("job.json", job)):
        write_json(output / name, value)
    result["downloaded_zip_bytes"] = archive(target, output / "original.zip")
    result["downloaded_zip_sha256"] = target["digest"].split(":", 1)[1]
    (output / "original.zip").chmod(0o444)
    non_database_selected_bytes = 0
    database_selected_bytes = 0
    raw_text = {}
    paths = {}
    frozen = output / "original-members"
    frozen.mkdir()
    snapshot_dir = frozen / PREFIX.rstrip("/")
    with zipfile.ZipFile(output / "original.zip") as bundle:
        infos = bundle.infolist()
        require(len(infos) <= MAX_MEMBERS, "MEMBER_COUNT")
        require(len(infos) == len({info.filename for info in infos}), "DUPLICATE_MEMBER")
        for info in infos:
            name = info.filename
            parts = PurePosixPath(name).parts
            require(name and not name.startswith("/") and ".." not in parts
                    and "\\" not in name and "\x00" not in name, "MEMBER_PATH")
            mode = (info.external_attr >> 16) & 0xffff
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR), "MEMBER_FILE_TYPE")
            require(not (info.flag_bits & 1), "ENCRYPTED_MEMBER")
        by_name = {info.filename: info for info in infos}
        index = [{"name": info.filename, "bytes": info.file_size,
                  "compressed_bytes": info.compress_size, "crc32": info.CRC,
                  "external_attr": info.external_attr, "create_system": info.create_system}
                 for info in infos]
        result["member_index_sha256"] = write_json(output / "members.json", index)
        result["fixed_database_members"] = [
            {"name": name, "present": name in by_name,
             "bytes": by_name[name].file_size if name in by_name else None,
             "compressed_bytes": by_name[name].compress_size if name in by_name else None}
            for name in DB_MEMBERS]
        unexpected = [info.filename for info in infos
                      if info.filename.startswith(DB_NAME + "-") and info.filename not in DB_MEMBERS]
        if unexpected:
            result["unavailable_reasons"].append("UNRECOGNIZED_DATABASE_SIDECAR")
            result["unrecognized_database_sidecars"] = unexpected
        for name in TEXT_MEMBERS + DB_MEMBERS:
            info = by_name.get(name)
            if info is None:
                if name in TEXT_MEMBERS or name == DB_NAME:
                    result["unavailable_reasons"].append("ABSENT:" + name)
                continue
            if info.is_dir() or stat.S_IFMT((info.external_attr >> 16) & 0xffff) not in (0, stat.S_IFREG):
                result["unavailable_reasons"].append("NOT_REGULAR:" + name)
                continue
            destination = frozen.joinpath(*PurePosixPath(name).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if name == DB_NAME:
                # Identity/source checks precede the large, exact-budget stream.
                if not all(member in raw_text for member in TEXT_MEMBERS):
                    result["unavailable_reasons"].append("DATABASE_SOURCE_BINDING_UNAVAILABLE")
                    continue
                origin = verified_origin(raw_text, target)
                result["origin"] = origin
                result["original_failure_location"] = origin["original_failure_location"]
                observation = stream_fixed_database(bundle, info, destination, target)
                database_selected_bytes += observation["bytes"]
            else:
                if (info.file_size > MAX_MEMBER
                        or non_database_selected_bytes + info.file_size > MAX_SELECTED):
                    result["unavailable_reasons"].append("BOUNDED_SIZE:" + name)
                    continue
                with bundle.open(info) as stream:
                    raw = stream.read(MAX_MEMBER + 1)
                    require(len(raw) == info.file_size and len(raw) <= MAX_MEMBER
                            and stream.read(1) == b"", "MEMBER_SIZE")
                non_database_selected_bytes += len(raw)
                with destination.open("xb") as stream:
                    stream.write(raw)
                destination.chmod(0o444)
                observation = {"member": name, "bytes": len(raw),
                               "sha256": hashlib.sha256(raw).hexdigest(),
                               "budget_scope": "unchanged-generic-member"}
                if name in TEXT_MEMBERS:
                    raw_text[name] = raw
            paths[name] = destination
            result["selected_members"].append(observation)
        if all(name in raw_text for name in TEXT_MEMBERS):
            if result["origin"] is None:
                origin = verified_origin(raw_text, target)
                result["origin"] = origin
                result["original_failure_location"] = origin["original_failure_location"]
        else:
            result["unavailable_reasons"].append("ORIGINAL_BINDING_MEMBERS_UNAVAILABLE")
        wal_present = DB_NAME + "-wal" in by_name
        shm_present = DB_NAME + "-shm" in by_name
        if wal_present != shm_present:
            result["unavailable_reasons"].append("WAL_SHM_SET_INCOMPLETE")
        if DB_NAME + "-journal" in by_name and by_name[DB_NAME + "-journal"].file_size:
            result["unavailable_reasons"].append("NONEMPTY_ROLLBACK_JOURNAL")
        if any(name in by_name and name not in paths for name in DB_MEMBERS):
            result["unavailable_reasons"].append("DATABASE_MEMBER_UNREAD")
    require(database_selected_bytes in (0, EXACT_MAIN_DATABASES[target["id"]]["bytes"]),
            "FIXED_DATABASE_SELECTED_TOTAL")
    require(non_database_selected_bytes <= MAX_SELECTED, "GENERIC_SELECTED_TOTAL")
    result["database_selected_bytes"] = database_selected_bytes
    result["non_database_selected_bytes"] = non_database_selected_bytes
    result["selected_bytes"] = database_selected_bytes + non_database_selected_bytes
    require(result["selected_bytes"] <= EXACT_MAIN_DATABASES[target["id"]]["bytes"] + MAX_SELECTED,
            "COMBINED_SELECTED_TOTAL")
    result["files_before_query"] = {
        name: digest_file(path, retained_limit(name, target)) for name, path in paths.items()}
    for observation in result["selected_members"]:
        require(result["files_before_query"][observation["member"]] == {
            "bytes": observation["bytes"], "sha256": observation["sha256"]},
            "RETAINED_INPUT_CHANGED_BEFORE_QUERY")
    if not result["unavailable_reasons"]:
        with paths[DB_NAME].open("rb") as stream:
            header = stream.read(100)
        if len(header) != 100 or header[:16] != b"SQLite format 3\x00":
            result["unavailable_reasons"].append("SQLITE_HEADER")
        else:
            page_size = int.from_bytes(header[16:18], "big")
            page_size = 65536 if page_size == 1 else page_size
            size = result["files_before_query"][DB_NAME]["bytes"]
            if (page_size < 512 or page_size > 65536 or page_size & (page_size - 1)
                    or size % page_size != 0):
                result["unavailable_reasons"].append("SQLITE_FILE_SIZE")
            if header[18:20] != b"\x02\x02":
                result["unavailable_reasons"].append("EXPECTED_WAL_DATABASE_HEADER")
            wal_path = paths.get(DB_NAME + "-wal")
            if wal_path is not None:
                wal_size = result["files_before_query"][DB_NAME + "-wal"]["bytes"]
                if wal_size:
                    with wal_path.open("rb") as stream:
                        wal_header = stream.read(32)
                    if (len(wal_header) != 32
                            or int.from_bytes(wal_header[0:4], "big") not in (0x377f0682, 0x377f0683)
                            or int.from_bytes(wal_header[4:8], "big") != 3007000
                            or int.from_bytes(wal_header[8:12], "big") != page_size
                            or (wal_size - 32) % (page_size + 24) != 0
                            or result["files_before_query"].get(DB_NAME + "-shm", {}).get("bytes", 0) < 128):
                        result["unavailable_reasons"].append("WAL_SET_STRUCTURE")
    if not result["unavailable_reasons"]:
        snapshot_dir.chmod(0o555)
        before_names = sorted(path.name for path in snapshot_dir.iterdir())
        result["snapshot"] = query_snapshot(paths[DB_NAME], target, result["origin"]["genesis"])
        result["snapshot_directory_entries_before"] = before_names
        result["snapshot_directory_entries_after"] = sorted(path.name for path in snapshot_dir.iterdir())
        result["snapshot_status"] = result["snapshot"]["status"]
        if result["snapshot_status"] != "observed":
            result["unavailable_reasons"].append("SQLITE_READ_UNAVAILABLE")
    result["files_after_query"] = {
        name: digest_file(path, retained_limit(name, target)) for name, path in paths.items()}
    require(result["files_before_query"] == result["files_after_query"], "RETAINED_INPUT_CHANGED")
    require(result.get("snapshot_directory_entries_before") == result.get("snapshot_directory_entries_after"),
            "SNAPSHOT_DIRECTORY_CHANGED")
    result["retained_zip_after_query"] = digest_file(output / "original.zip", target["size"])
    require(result["retained_zip_after_query"] == {
        "bytes": target["size"], "sha256": result["downloaded_zip_sha256"]}, "RETAINED_ZIP_CHANGED")
    result["all_retained_input_digests_unchanged"] = True
    result["reader_status"] = "completed"
    return result


results = []
had_error = False
for target in TARGETS:
    output = ROOT / str(target["id"])
    output.mkdir()
    try:
        result = inspect_one(target, output)
    except Exception as error:
        had_error = True
        result = {"schema": "trnm-retained-history-post-cleanup-snapshot-v2",
                  "target": target, "reader_status": "failed", "snapshot_status": "unavailable",
                  "error_type": type(error).__name__,
                  "reason": str(error)[:500] if isinstance(error, (Refused, sqlite3.Error)) else None,
                  "source_tests_executed": False, "archive_code_executed": False,
                  "acceptance_granted": False, "production_activation": False}
    write_json(output / "readback.json", result)
    rendered = json.dumps(result, sort_keys=True, separators=(",", ":"))
    if len(rendered) > MAX_STDOUT:
        rendered = json.dumps({"target": target, "reader_status": result["reader_status"],
                               "snapshot_status": result["snapshot_status"],
                               "console_truncated": True, "complete_result_retained": True,
                               "source_tests_executed": False, "acceptance_granted": False},
                              sort_keys=True)
    require(len(rendered) <= MAX_STDOUT, "CONSOLE_LIMIT")
    token = uuid.uuid4().hex
    print("::stop-commands::" + token, flush=True)
    print(rendered, flush=True)
    print("::" + token + "::", flush=True)
    results.append(result)
write_json(ROOT / "readback.json", {"schema": "trnm-retained-history-post-cleanup-cohort-v2",
    "planned_archives": 2, "results": results, "source_tests_executed": False,
    "archive_code_executed": False, "acceptance_granted": False, "production_activation": False})
raise SystemExit(1 if had_error else 0)
