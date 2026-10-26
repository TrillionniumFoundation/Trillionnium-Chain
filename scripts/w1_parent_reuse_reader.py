#!/usr/bin/env python3
"""Replay all retained W1 bytes and reconcile the native parent reuse ledger.

Cryptographic relation/signature/wire checks are independently executed here.
Native State execution, task eligibility, clock readings and successful Node
admission remain source-bound local observations; this is not Node attestation.
Original hidden misses are reconstructed after the strategy and earn no credit.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "formal/pon-nakamoto-v1"))
from contract_wire import H, canonical, header_decode, header_encode, read_config, sequence_root, u64, unique
from continuity_oracle import context as continuity_context
import strict_signature
import work_oracle
from read_w1_cost_research import require, uint64, exact

SCHEMA = "pon-w1-parent-reuse-research-v1"
BUDGET_SCHEMA = "pon-w1-parent-reuse-research-v2"
BUDGET_MODE = "budget-final-parent-v2"
LIMIT = 256 * 1024 * 1024
BUDGET_LIMIT = 1024 * 1024 * 1024
PROOF_BYTES = 49188
LABELS = ("continuity-maintenance-v1", "signed-zero-development-v1")
ARMS = ("prepared-generic", "paired-product", "integer-paired-general")
STRATEGIES = ("maintenance-only", "zero-only", "paid-task-screen")
COMMON = {"schema", "sequence", "observed", "kind"}
FIELDS = {
    "start": "options cpu_scope budget_policy bounded_atomic_operations shared_acquisition not_claimed proof_retention noise_reuse sibling_winners_are_not_additive_chainweight",
    "charge": "stage start end budget_poll process_cpu_ns wall_ns detail",
    "task": "task_index label task model_hex input_hex model_sha256 input_sha256 source_scope useful_model_qualification public_network_authority",
    "control": "name expected actual original_node_called accepted expected_rejection",
    "acquisition": "acquisition_id role task_index proof transactions_hex original_search_completed original_make_complete_attempts original_make_failed_attempts winning_proof_retention miss_retention original_search_cpu_paid reconstruction_has_no_new_ticket_credit",
    "admission": "role source_id block_id duplicate_block_id semantic_id unique_all_work_winner admitted native_full_relation_and_parent_qualification admission_completed admission_completed_within_budget duplicate_creates_new_work active_chainweight_added_here",
    "economics": "acquisition_id role receipt",
    "parent": "reason round stats actual_native_activation sibling_chainwork_summed",
    "parent-domain": "round parent height tasks lease_revision shared_templates_paid actual_signed_development_eligibility",
    "screen": "round attempt task_index candidate header_hex challenge score score_definition noise_sha256 noise_hash_calls noise_words selected complete_proof ticket_observed noise_passed_to_producer credited_ticket",
    "selection": "round attempt strategy task_index candidate header_hex challenge score score_reads_ticket screen_candidate_count",
    "attempt": "attempt_id round attempt task_index arm cache proof proof_retention completed native_full_relation_verified native_reference_verified unique_research_semantic complete_proof_within_budget noise_expanded_again_by_producer",
    "revocation-readback": "parent slot mathematical_cache_still_allocated cache_is_not_task_authority",
    "reconstruction": "acquisition_id task_index ordinal proof original_winner provenance original_bytes_observed original_winner_bytes_equal native_full_relation_verified native_reference_verified new_work_credit used_by_selection included_in_strategy_cpu",
}
FULL_END = "status strategy_completed posthoc_start posthoc_end posthoc_process_cpu_ns reconstructed_proofs reconstructed_proofs_new_credit native_admission_scope new_real_training useful_learning hardness_accepted cost_lower_bound_proved production_activation"
FULL_STRATEGY = "status completed rounds_completed context_drop_included controls_completed controls acquisitions original_make_completed_proofs original_make_failed_target_proofs original_make_winning_proofs research_completed_proofs research_unique_complete_semantics research_unique_winners all_work_unique_winners all_work_unique_native_blocks all_work_unique_admitted_within_budget research_unique_admitted_within_budget screened_candidates discarded_screen_candidates hot_preparations cold_preparations renewals transaction_count transaction_fee_total transaction_fee_units fees_not_added_to_cpu final_native_stats final_economy sibling_work_summed_into_chainweight minimum_cost_strategy_claim posthoc_original_miss_reconstruction_excluded"
PROOF_FIELDS = "header_hex parent height timestamp nonce task target challenge trace ticket semantic_id block_id target_hit proof_sha256 proof_bytes proof_hex"
STATS_FIELDS = "network parameters genesis tip height chainwork_hex state_root generation state_keys stored_blocks events authenticated_sessions authenticated_pending authenticated_audit_rows authenticated_outbox_sessions authenticated_outbox_pending production_activation"
NEW_STAGES = {
    "context-open-and-task-source", "native-negative-control", "construct-signed-registration",
    "construct-signed-atomic-renewal", "construct-signed-revocation", "original-node-make",
    "native-activate-and-readback", "arithmetic-prepare", "fixed-task-nonce-selection",
    "paid-noise-screen-and-select", "research-complete-proof",
}
TAIL_STAGES = {"native-admission-and-duplicate-check", "economics-native-state-readback",
               "research-native-full-verifiers", "native-context-drop"}
DETAIL_FIELDS = {
    "context-open-and-task-source":"workers source real_neural_training independent_requester source_acquisition_external_cost_claim initial_native_stats",
    "native-negative-control":"name", "construct-signed-registration":"transaction_count",
    "construct-signed-atomic-renewal":"revision", "construct-signed-revocation":"revision",
    "original-node-make":"role task_index parent max_attempts success",
    "native-activate-and-readback":"reason round", "arithmetic-prepare":"cache task_index arm",
    "fixed-task-nonce-selection":"round attempt task_index", "paid-noise-screen-and-select":"round attempt candidates",
    "research-complete-proof":"round attempt task_index arm",
    "native-admission-and-duplicate-check":"role source_id", "economics-native-state-readback":"acquisition_id",
    "research-native-full-verifiers":"round attempt", "native-context-drop":"includes_temporary_state_cleanup",
}


def hx(value, size, label):
    require(type(value) is str and len(value) == 2 * size and
            all(c in "0123456789abcdef" for c in value), label)
    return bytes.fromhex(value)


def number(value, label, high=(1 << 64) - 1):
    return uint64(value, label, maximum=high)


def flags(record, true=(), false=()):
    for name in true:
        require(record.get(name) is True, "FLAG_TRUE:" + name)
    for name in false:
        require(record.get(name) is False, "FLAG_FALSE:" + name)


def stamp(value):
    exact(value, ("process_cpu_ns", "wall_ns"), "STAMP_FIELDS")
    number(value["process_cpu_ns"], "CPU_STAMP")
    number(value["wall_ns"], "WALL_STAMP")
    return value


def before(left, right, label):
    stamp(left); stamp(right)
    require(all(left[key] <= right[key] for key in left), label)


def options_from_args(argv):
    require(type(argv) is list and len(argv) % 2 == 0 and all(type(v) is str for v in argv), "CLI_PAIRS")
    result = dict(rounds=4, attempts_per_parent=4, seed=1, cache="hot", strategy="paid-task-screen",
                  screen_width=1, arm="integer-paired-general", cpu_budget_ns=None, mode=None, max_final_attempts=None)
    seen = set()
    for key, value in zip(argv[::2], argv[1::2]):
        require(key.startswith("--") and key not in seen, "CLI_DUPLICATE_OR_KEY")
        seen.add(key)
        name = key[2:].replace("-", "_")
        require(name in result and key == "--" + name.replace("_", "-"), "CLI_OPTION")
        if name in ("rounds", "attempts_per_parent", "screen_width", "seed", "cpu_budget_ns", "max_final_attempts"):
            require(value.isascii() and value.isdecimal(), "CLI_INTEGER")
            result[name] = int(value)
        else:
            result[name] = value
    result = {key:value for key,value in result.items() if key not in ("mode", "max_final_attempts") or value is not None}
    return validate_options(result)


def budget_mode(options):
    return options.get("mode") == BUDGET_MODE


def attempt_limit(options, round_id):
    return options["max_final_attempts"] if budget_mode(options) and round_id + 1 == options["rounds"] else options["attempts_per_parent"]


def actual_arm(options, task_index):
    return ("maintenance-limb", "blocked-zero")[task_index] if options["arm"] == "structure-specialized" else options["arm"]


def validate_options(value):
    fields = {"rounds", "attempts_per_parent", "seed", "cache", "strategy", "screen_width", "arm", "cpu_budget_ns"}
    if budget_mode(value): fields |= {"mode", "max_final_attempts"}
    exact(value, fields, "OPTION_FIELDS")
    for key in ("rounds", "attempts_per_parent", "screen_width"):
        uint64(value[key], "OPTION_BOUND:" + key, minimum=1, maximum=8)
    number(value["seed"], "OPTION_SEED")
    require(value["cache"] in ("hot", "cold") and value["strategy"] in STRATEGIES and value["arm"] in (ARMS + (("structure-specialized",) if budget_mode(value) else ())), "OPTION_ENUM")
    if value["cpu_budget_ns"] is not None:
        number(value["cpu_budget_ns"], "OPTION_BUDGET")
    if budget_mode(value):
        require(value["rounds"] >= 2 and value["cpu_budget_ns"] is not None, "BUDGET_MODE_BOUNDS")
        uint64(value["max_final_attempts"], "FINAL_PARENT_CAP", minimum=1, maximum=4096)
    return value


@lru_cache(maxsize=1)
def fixed_context():
    params, _, _ = continuity_context("native-public-evaluation-dev-v1")
    params["genesis_timestamp"] = 1
    params["chain_label"] = "trnm-pon-task-lifecycle-wall-devnet-12-native-public-evaluation-dev-v1-1-evaluation-storage2"
    network = H("network", params["chain_label"].encode())
    parameters = H("parameters", canonical(params), canonical(read_config("config/pon/ledger-v1.json")),
                   canonical(read_config("config/pon/work-profile-v1.json")), canonical(read_config("config/pon/model-family-v1.json")))
    require(params["retarget_interval"] == 16 and params["genesis_funding_units_per_account"] == 10_000_000 and
            params["reward_maturity_blocks"] == 20, "FIXTURE_CONFIGURATION_CHANGED")
    return params, network, parameters


@lru_cache(maxsize=4)
def public(actor):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return Ed25519PrivateKey.from_private_bytes(H("DEV-ONLY-KEY", u64(actor))).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@lru_cache(maxsize=2)
def material(index):
    if index == 0:
        a = [(13 * i + 17) % 257 for i in range(4096)]
        b = [(29 * i + 31) % 263 for i in range(4096)]
    else:
        a, b = [0] * 4096, [0] * 4096
    model, inputs = work_oracle.field_bytes(a), work_oracle.field_bytes(b)
    return model, inputs, H("task", model, inputs)


def statement(lease_hex, signed_hex, revision, options):
    lease = hx(lease_hex, 344, "LEASE_HEX")
    signed = hx(signed_hex, 684, "STATEMENT_HEX")
    _, network, parameters = fixed_context()
    require(lease[:8] == b"QDL2\x02\x00\x01\x01" and lease[-8:] == b"\x01" + bytes(7), "LEASE_ENCODING")
    names = "network parameters demand_id requester source source_record authorization_scope availability_manifest availability_root".split()
    values = {name: lease[8 + 32 * i:40 + 32 * i] for i, name in enumerate(names)}
    generation, actual_revision, not_before, expires, available_until = struct.unpack_from("<5Q", lease, 296)
    require(values["network"] == network and values["parameters"] == parameters and values["source"] == public(0) and
            values["requester"] == public(2) and generation == 2 and actual_revision == revision, "LEASE_CONTEXT")
    require(values["demand_id"] == H("qualified-demand-id-v2", network, parameters, public(2), u64(2)), "LEASE_DEMAND")
    require(expires == options["rounds"] + (12 if revision == 1 else 20) and available_until == expires + 100 and
            1 <= not_before < expires and (revision != 1 or not_before == 1), "LEASE_WINDOW")
    lease_id = H("qualified-demand-lease-v2", lease)
    require(signed[:4] == b"QWA2" and signed[4:36] == lease_id, "STATEMENT_LEASE")
    manifest = signed[36:-64]
    require(manifest[:12] == b"QWT1\x01\x00\x01\x01\x01\x00\x01\x00", "MANIFEST_ENCODING")
    names = "network parameters work_profile source demand_id source_record model layer input recipe matrix_task availability_manifest availability_root authorization_scope withdrawal_head output_meter".split()
    m = {name: manifest[12 + 32 * i:44 + 32 * i] for i, name in enumerate(names)}
    model, inputs, task = material(1)
    expected = {"network":network, "parameters":parameters, "work_profile":H("qualified-task-profile-v1", b"pon-matmul-transcript-64-v1"),
                "source":public(0), "demand_id":values["demand_id"], "source_record":H("qualified-demand-source-record-v2", lease_id, values["source_record"]),
                "model":H("artifact", model), "input":H("qualified-task-input-v1", inputs), "matrix_task":task,
                "recipe":H("qualified-task-recipe-v1", b"canonical-field-matrix64-product-v1"),
                "availability_manifest":values["availability_manifest"], "availability_root":values["availability_root"],
                "authorization_scope":values["authorization_scope"], "withdrawal_head":H("qualified-demand-frontier-v2", lease_id)}
    expected["layer"] = H("qualified-task-layer-v1", expected["model"], b"entire-row-major-field-layer-64x64")
    expected["output_meter"] = H("qualified-task-output-meter-v1", *(expected[k] for k in
        ("network", "parameters", "demand_id", "model", "layer", "input", "recipe", "matrix_task")))
    require(m == expected and struct.unpack_from("<4H", manifest, 524) == (64,64,64,0) and
            struct.unpack_from("<5Q", manifest, 532) == (revision,not_before,expires,available_until,64**3) and
            struct.unpack_from("<3I", manifest, 572) == (16384,16384,0), "MANIFEST_BINDING")
    strict_signature.verify(public(0), signed[-64:], H("qualified-task-source-sign-v2", signed[:-64]))
    return dict(lease=lease, signed=signed, values=values, manifest=m, revision=revision,
                not_before=not_before, expires=expires, statement_id=H("qualified-task-manifest-v2", signed[:-64]).hex())


def transaction(encoded, network):
    require(type(encoded) is str and 318 <= len(encoded) <= 4096, "TRANSACTION_BOUND")
    raw = hx(encoded, len(encoded)//2, "TRANSACTION_HEX")
    require(raw[:4] == b"PNX1" and raw[4:36] == network, "TRANSACTION_NETWORK")
    nonce, expiry, fee_limit = struct.unpack_from("<3Q", raw, 68)
    length = struct.unpack_from("<H", raw, 93)[0]
    require(len(raw) == 159 + length and nonce > 0 and expiry == 1000 and fee_limit == 1_000_000 and raw[92] in (18,20,21,22), "TRANSACTION_ENCODING")
    strict_signature.verify(raw[36:68], raw[-64:], H("tx-sign", raw[:-64]))
    return dict(raw=raw, sender=raw[36:68], nonce=nonce, tag=raw[92], payload=raw[95:-64], fee_limit=fee_limit, id=H("tx-id", raw).hex())


def proof(record, task_index):
    exact(record, PROOF_FIELDS.split(), "PROOF_FIELDS")
    raw_header = hx(record["header_hex"], 318, "HEADER_HEX")
    header = header_decode(raw_header)
    require(header_encode(header) == raw_header, "HEADER_CANONICAL")
    _, network, parameters = fixed_context()
    model, inputs, task = material(task_index)
    require(header["network"] == network and header["parameters"] == parameters and header["miner"] == public(3) and
            header["work_task"] == task and header["target"].hex() == fixed_context()[0]["initial_target_hex"], "HEADER_CONTEXT")
    require(1 <= header["height"] <= 12 and header["timestamp"] == 1 + 10 * header["height"], "HEADER_HEIGHT_TIME")
    raw = hx(record["proof_hex"], PROOF_BYTES, "PROOF_HEX")
    require(raw[:4] == b"PNW1" and raw[4:16388] == model and raw[16388:32772] == inputs, "PROOF_MATERIAL")
    challenge = H("challenge", raw_header)
    trace = raw[-32:]
    ticket = H("ticket", challenge, trace)
    identity = H("w1-cost-game-semantic-ticket-v1", task, challenge, ticket).hex()
    block = H("block", raw_header, trace).hex()
    require(record["proof_bytes"] == PROOF_BYTES and type(record["proof_bytes"]) is int and
            record["proof_sha256"] == hashlib.sha256(raw).hexdigest(), "PROOF_DIGEST")
    expected = dict(parent=header["parent"].hex(), height=header["height"], timestamp=header["timestamp"], nonce=header["nonce"],
                    task=task.hex(), target=header["target"].hex(), challenge=challenge.hex(), trace=trace.hex(), ticket=ticket.hex(),
                    semantic_id=identity, block_id=block, target_hit=bool(header["target"] != bytes(32) and ticket <= header["target"]))
    for key, value in expected.items():
        require(type(record[key]) is type(value) and record[key] == value, "PROOF_BINDING:" + key)
    # No memoization: every retained record, including duplicate winners and
    # reconstructed misses, is independently replayed through the scalar oracle.
    replayed_ticket, _ = work_oracle.verify(challenge, task, b"\xff"*32, raw)
    require(replayed_ticket == ticket, "FULL_PYTHON_REPLAY")
    return dict(header=header, raw_header=raw_header, raw=raw, identity=identity, block=block,
                hit=expected["target_hit"], challenge=challenge, digest=record["proof_sha256"])


def candidate(template, options, round_id, attempt, ordinal):
    value = dict(template)
    value["nonce"] = int.from_bytes(H("w1-parent-reuse-nonce-v1", u64(options["seed"]), u64(round_id), u64(attempt), u64(ordinal))[:8], "little")
    return header_encode(value)


def noise(challenge):
    arrays, calls = [], 0
    for label in range(4):
        words, counter = [], 0
        while len(words) < 512:
            require(counter < 128, "NOISE_BOUND")
            chunk = H("noise", challenge, bytes([label]), struct.pack("<I", counter))
            counter += 1
            words.extend(v for (v,) in struct.iter_unpack("<I", chunk) if v < work_oracle.Q)
        arrays.extend(words[:512]); calls += counter
    return sum(value.bit_count() for value in arrays), calls, hashlib.sha256(work_oracle.field_bytes(arrays)).hexdigest()


def load(path):
    path = Path(path).absolute()
    initial = path.lstat()
    require(stat.S_ISREG(initial.st_mode) and not path.is_symlink() and 0 < initial.st_size <= BUDGET_LIMIT, "RAW_SIZE_OR_SYMLINK")
    rows = []
    digest = hashlib.sha256()
    identity = lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        require(identity(opened) == identity(initial), "RAW_REPLACED_ON_OPEN")
        for line in stream:
            digest.update(line)
            require(len(line) <= 2 * 1024 * 1024 and line.endswith(b"\n"), "RAW_LINE")
            row = json.loads(line, object_pairs_hook=unique)
            require(type(row) is dict and row.get("schema") in (SCHEMA, BUDGET_SCHEMA) and row.get("sequence") == len(rows) and
                    type(row.get("sequence")) is int and type(row.get("kind")) is str, "RAW_RECORD")
            stamp(row.get("observed"))
            if rows:
                require(row["schema"] == rows[0]["schema"], "MIXED_RAW_SCHEMA")
                before(rows[-1]["observed"], row["observed"], "OBSERVATION_ORDER")
            else:
                require(initial.st_size <= (BUDGET_LIMIT if row["schema"] == BUDGET_SCHEMA else LIMIT), "RAW_SIZE_OR_SYMLINK")
            rows.append(row)
            require(len(rows) <= (128000 if row["schema"] == BUDGET_SCHEMA else 6000), "ROW_LIMIT")
        require(identity(os.fstat(stream.fileno())) == identity(opened), "RAW_MUTATED_DURING_READ")
    require(not path.is_symlink() and identity(path.lstat()) == identity(opened), "RAW_PATH_REPLACED_DURING_READ")
    require(len(rows) >= 3 and rows[0]["kind"] == "start" and rows[-1]["kind"] == "end", "RAW_COMPLETENESS")
    return rows, dict(raw_path=str(path), raw_sha256=digest.hexdigest(), raw_bytes=opened.st_size,
                      raw_file_identity_checked=True)


class Reader:
    def __init__(self, rows, expected):
        self.rows = rows
        self.options = validate_options(rows[0]["options"])
        self.budget_mode = budget_mode(self.options)
        require(rows[0]["schema"] == (BUDGET_SCHEMA if self.budget_mode else SCHEMA), "SCHEMA_OPTIONS_BINDING")
        if expected is not None:
            require(self.options == validate_options(expected), "EXPECTED_OPTIONS")
        self.limit = self.options["cpu_budget_ns"]
        self.charges = []
        self.used_charges = set()
        self.charge_cpu = Counter()
        self.last_charge_end = {"process_cpu_ns":0,"wall_ns":0}
        self.tasks = []
        self.statements = {}
        self.acquisitions = []
        self.attempts = []
        self.admissions = {}
        self.blocks = {}
        self.all_winners = set()
        self.budget_winners = set()
        self.research_winners = set()
        self.research_budget_winners = set()
        self.research_semantics = set()
        self.controls = []
        self.parents = []
        self.domains = []
        self.screens = []
        self.selection = None
        self.selections = []
        self.preparations = []
        self.economics = {}
        self.reconstructions = []
        self.proof_replays = 0
        self.initial_stats = None
        self.active = None
        self.active_height = 0
        self.summary = None
        self.summary_sequence = None
        self.final = None
        self.revocation_readback = False
        self.renewal_activation = None
        self.acquisition_roles = ["zero-registration"]
        for round_id in range(self.options["rounds"]):
            if round_id == self.options["rounds"]//2:
                self.acquisition_roles.append("zero-renewal")
            self.acquisition_roles.extend(("parent-template-maintenance", "parent-template-zero"))
        self.acquisition_roles.extend(("zero-revocation", "post-revocation-maintenance"))

    def within(self, time):
        stamp(time)
        return self.limit is None or time["process_cpu_ns"] <= self.limit

    def consume(self, stage, row, **details):
        matches = [r for r in self.charges if r["sequence"] not in self.used_charges and r["stage"] == stage and
                   r["sequence"] < row["sequence"] and all(r["detail"].get(k) == v for k,v in details.items())]
        require(len(matches) == 1, "CHARGE_BINDING:" + stage)
        match = matches[0]
        self.used_charges.add(match["sequence"])
        return match

    def stats(self, value, *, initial=False):
        exact(value, STATS_FIELDS.split(), "STATS_FIELDS")
        _, network, parameters = fixed_context()
        require(value["network"] == network.hex() and value["parameters"] == parameters.hex(), "STATS_NETWORK")
        flags(value, false=("production_activation",))
        for key in ("height","generation","state_keys","stored_blocks","events","authenticated_sessions",
                    "authenticated_pending","authenticated_audit_rows","authenticated_outbox_sessions","authenticated_outbox_pending"):
            number(value[key], "STATS_NUMBER:" + key)
        for key in ("authenticated_sessions","authenticated_pending","authenticated_audit_rows","authenticated_outbox_sessions","authenticated_outbox_pending"):
            require(value[key] == 0, "UNEXPECTED_SESSION")
        root = hx(value["state_root"],32,"STATS_ROOT")
        chainwork = int.from_bytes(hx(value["chainwork_hex"],64,"CHAINWORK_HEX"),"big")
        if initial:
            genesis = H("genesis", network, parameters, root, u64(1)).hex()
            require(value["tip"] == value["genesis"] == genesis and value["height"] == value["generation"] == value["events"] == chainwork == 0 and
                    value["stored_blocks"] == 1, "INITIAL_STATS")
        else:
            require(self.initial_stats is not None and value["genesis"] == self.initial_stats["genesis"] and value["tip"] == self.active and
                    value["height"] == self.active_height and value["generation"] == value["events"] == len(self.parents) and
                    value["stored_blocks"] == len(self.blocks)+1 and chainwork == 2*self.active_height, "NATIVE_CHAIN_STATS")
            if self.active_height:
                require(value["state_root"] == self.blocks[self.active]["header"]["state"].hex(), "NATIVE_STATE_ROOT_BINDING")
            else:
                require(value["state_root"] == self.initial_stats["state_root"], "INITIAL_ROOT_RETAINED")

    def read_charge(self, row):
        require(self.summary is None and row["stage"] in NEW_STAGES | TAIL_STAGES, "CHARGE_STAGE")
        before(self.last_charge_end,row["start"],"CHARGE_OVERLAP")
        before(row["start"],row["end"],"CHARGE_ORDER")
        before(row["end"],row["observed"],"CHARGE_COMPLETION")
        for name in ("process_cpu_ns","wall_ns"):
            number(row[name],"CHARGE_NUMBER")
            require(row[name] == row["end"][name]-row["start"][name],"CHARGE_DELTA")
        exact(row["budget_poll"],("observed","permitted"),"BUDGET_POLL_FIELDS")
        poll=row["budget_poll"]
        before(poll["observed"],row["start"],"BUDGET_POLL_ORDER")
        require(type(poll["permitted"]) is bool and poll["permitted"] == (self.limit is None or poll["observed"]["process_cpu_ns"] < self.limit),"BUDGET_POLL_PREDICATE")
        if row["stage"] in NEW_STAGES:
            require(poll["permitted"],"NEW_WORK_AFTER_FAILED_POLL")
            before(self.rows[row["sequence"]-1]["observed"],poll["observed"],"STALE_BUDGET_POLL")
        require(type(row["detail"]) is dict,"CHARGE_DETAIL")
        exact(row["detail"],DETAIL_FIELDS[row["stage"]].split(),"CHARGE_DETAIL_FIELDS")
        self.last_charge_end=row["end"]
        self.charge_cpu[row["stage"]]+=row["process_cpu_ns"]
        self.charges.append(row)
        stage=row["stage"]
        if stage=="context-open-and-task-source":
            require(self.initial_stats is None and row["sequence"]==1,"CONTEXT_ORDER")
            exact(row["detail"],("workers","source","real_neural_training","independent_requester","source_acquisition_external_cost_claim","initial_native_stats"),"CONTEXT_DETAIL")
            require(row["detail"]["workers"]==1 and row["detail"]["source"]=="disclosed-development-signers" and row["detail"]["source_acquisition_external_cost_claim"] is None,"CONTEXT_SCOPE")
            flags(row["detail"],false=("real_neural_training","independent_requester"))
            self.initial_stats=row["detail"]["initial_native_stats"]
            self.stats(self.initial_stats,initial=True)
            self.active=self.initial_stats["genesis"]
            self.used_charges.add(row["sequence"])
        elif stage=="arithmetic-prepare":
            exact(row["detail"],("cache","task_index","arm"),"PREPARE_DETAIL")
            detail=row["detail"]
            number(detail["task_index"],"PREPARE_TASK",1)
            require(detail["cache"]==self.options["cache"] and detail["arm"]==actual_arm(self.options,detail["task_index"]),"PREPARE_OPTIONS")
            if detail["cache"]=="hot":
                require(detail["task_index"]==len(self.preparations) and not self.domains and len(self.controls)>=2,"HOT_PREPARE_ORDER")
                self.used_charges.add(row["sequence"])
            else:
                require(self.selection is not None and detail["task_index"]==self.selection["task_index"],"COLD_PREPARE_SELECTION")
            self.preparations.append(row)

    def read_task(self,row):
        index=number(row["task_index"],"TASK_INDEX",1)
        require(index==len(self.tasks) and not self.statements and self.initial_stats is not None,"TASK_ORDER")
        model,inputs,task=material(index)
        require(row["label"]==LABELS[index] and row["model_hex"]==model.hex() and row["input_hex"]==inputs.hex() and
                row["task"]==task.hex() and row["model_sha256"]==hashlib.sha256(model).hexdigest() and row["input_sha256"]==hashlib.sha256(inputs).hexdigest(),"TASK_RECIPE")
        require(row["source_scope"]==("immutable-genesis-maintenance" if index==0 else "locally-created-signed-development-zero"),"TASK_SOURCE")
        flags(row,false=("useful_model_qualification","public_network_authority"))
        self.tasks.append(row)

    def read_statement(self,row):
        revision=number(row["revision"],"STATEMENT_REVISION",2)
        require(revision in (1,2) and revision not in self.statements and len(self.tasks)==2,"STATEMENT_ORDER")
        wanted={"revision","lease_hex","statement_hex","registered_in_parent"}
        if revision==2: wanted|={"parent","height"}
        exact(row,COMMON|wanted,"STATEMENT_FIELDS")
        value=statement(row["lease_hex"],row["statement_hex"],revision,self.options)
        if revision==1:
            require(not self.acquisitions and row["registered_in_parent"] is False,"INITIAL_STATEMENT")
        else:
            require(self.renewal_activation==self.active==row["parent"] and row["height"]==self.active_height and row["registered_in_parent"] is True,"RENEWED_STATEMENT_PARENT")
            acquisition=self.acquisitions[-1]
            require(acquisition["role"]=="zero-renewal" and acquisition["transactions"][0]["payload"]==value["lease"]+value["signed"] and value["not_before"]==self.active_height,"RENEWED_TRANSACTION_BINDING")
            first=self.statements[1]
            require(all(value["values"][key]==first["values"][key] for key in value["values"]),"RENEWAL_SOURCE_CHANGED")
        self.statements[revision]=value

    def read_control(self,row):
        expected=[("zero-before-registration","TASK"),("material-mismatch","TASK_MATERIAL"),
                  ("stale-admission-after-renewal","TASK_ADMISSION_CONTEXT"),("zero-after-revocation","TASK")]
        require(len(self.controls)<4 and (row["name"],row["expected"])==expected[len(self.controls)] and row["actual"]==row["expected"],"CONTROL_ORDER_OR_ERROR")
        flags(row,true=("original_node_called","expected_rejection"),false=("accepted",))
        charge=self.consume("native-negative-control",row,name=row["name"])
        exact(charge["detail"],("name",),"CONTROL_CHARGE")
        if len(self.controls)==0: require(not self.acquisitions,"CONTROL_REGISTRATION_ORDER")
        if len(self.controls)==1: require(self.parents[-1]["reason"]=="zero-registration","CONTROL_MATERIAL_ORDER")
        if len(self.controls)==2: require(2 in self.statements and self.renewal_activation==self.active,"CONTROL_RENEWAL_ORDER")
        if len(self.controls)==3: require(self.parents[-1]["reason"]=="zero-revocation","CONTROL_REVOCATION_ORDER")
        self.controls.append(dict(name=row["name"],error=row["actual"],scope="native_reported",cpu_ns=charge["process_cpu_ns"]))

    def read_acquisition(self,row):
        index=number(row["task_index"],"ACQUISITION_TASK",1)
        identifier=number(row["acquisition_id"],"ACQUISITION_ID")
        require(identifier==len(self.acquisitions) and identifier<len(self.acquisition_roles) and row["role"]==self.acquisition_roles[identifier],"ACQUISITION_ORDER")
        role=row["role"]
        require(index==int(role=="parent-template-zero") and self.selection is None,"ACQUISITION_TASK_ROLE")
        if identifier: require(("acquisition",identifier-1) in self.admissions,"ACQUISITION_PREVIOUS_ADMISSION")
        require(1 in self.statements and len(self.controls)>=1,"ACQUISITION_CONTEXT")
        value=proof(row["proof"],index); self.proof_replays+=1
        h=value["header"]
        require(h["parent"].hex()==self.active and h["height"]==self.active_height+1 and value["hit"] and h["nonce"]<64,"ACQUISITION_PARENT_OR_TARGET")
        for field,wanted in (("original_make_complete_attempts",h["nonce"]+1),("original_make_failed_attempts",h["nonce"])):
            require(type(row[field]) is int and row[field]==wanted,"ORIGINAL_SEARCH_DENOMINATOR")
        flags(row,true=("original_search_cpu_paid","reconstruction_has_no_new_ticket_credit"))
        require(row["winning_proof_retention"]=="original-native-returned-bytes" and row["miss_retention"]=="not-exposed-by-native-API; reconstructed-after-strategy-only","ACQUISITION_PROVENANCE")
        charge=self.consume("original-node-make",row,role=role,task_index=index,parent=self.active)
        exact(charge["detail"],("role","task_index","parent","max_attempts","success"),"MAKE_DETAIL")
        require(charge["detail"]["max_attempts"]==64 and charge["detail"]["success"] is True,"MAKE_SCOPE")
        before(charge["start"],row["original_search_completed"],"MAKE_COMPLETION_START")
        before(row["original_search_completed"],charge["end"],"MAKE_COMPLETION_END")
        require(type(row["transactions_hex"]) is list,"TRANSACTIONS_LIST")
        txs=[transaction(encoded,h["network"]) for encoded in row["transactions_hex"]]
        require(sequence_root("transactions",[tx["raw"] for tx in txs])==h["transactions"],"TRANSACTIONS_ROOT")
        if role=="zero-registration":
            require([(t["tag"],t["sender"],t["nonce"]) for t in txs]==[(18,public(2),1),(21,public(0),1)] and
                    txs[0]["payload"]==self.statements[1]["lease"] and txs[1]["payload"]==self.statements[1]["signed"],"REGISTRATION_TRANSACTIONS")
            self.consume("construct-signed-registration",row,transaction_count=2)
        elif role=="zero-renewal":
            require(len(txs)==1 and (txs[0]["tag"],txs[0]["sender"],txs[0]["nonce"])==(22,public(2),2),"RENEWAL_TRANSACTION")
            require(len(txs[0]["payload"])==1028,"RENEWAL_PAYLOAD")
            renew=statement(txs[0]["payload"][:344].hex(),txs[0]["payload"][344:].hex(),2,self.options)
            require(renew["not_before"]==h["height"],"RENEWAL_HEIGHT")
            self.consume("construct-signed-atomic-renewal",row,revision=2)
        elif role=="zero-revocation":
            require(len(txs)==1 and (txs[0]["tag"],txs[0]["sender"],txs[0]["nonce"])==(20,public(2),3),"REVOCATION_TRANSACTION")
            require(2 in self.statements,"REVOCATION_WITHOUT_RENEWAL")
            lease=self.statements[2]
            wanted=b"QDR2\x02\x00\x01\x00"+b"".join(lease["values"][k] for k in ("network","parameters","demand_id","requester"))+u64(2)
            require(txs[0]["payload"]==wanted,"REVOCATION_PAYLOAD")
            self.consume("construct-signed-revocation",row,revision=2)
        else:
            require(not txs,"UNEXPECTED_TASK_TRANSACTIONS")
        if not txs: require(h["receipts"]==sequence_root("receipts",[]),"EMPTY_RECEIPTS_ROOT")
        value.update(id=identifier,task_index=index,role=role,transactions=txs,row=row,producer_charge=charge)
        self.acquisitions.append(value)

    def read_admission(self,row):
        role=row["role"]; identifier=number(row["source_id"],"ADMISSION_ID")
        require(role in ("acquisition","research") and (role,identifier) not in self.admissions,"ADMISSION_DUPLICATE")
        values=self.acquisitions if role=="acquisition" else self.attempts
        require(identifier<len(values),"ADMISSION_SOURCE")
        value=values[identifier]
        require(value["hit"] and row["block_id"]==row["duplicate_block_id"]==value["block"] and row["semantic_id"]==value["identity"],"ADMISSION_BINDING")
        flags(row,true=("admitted","native_full_relation_and_parent_qualification"),false=("duplicate_creates_new_work","active_chainweight_added_here"))
        require(type(row["unique_all_work_winner"]) is bool and row["unique_all_work_winner"]==(value["identity"] not in self.all_winners),"ADMISSION_SEMANTIC_DEDUP")
        charge=self.consume("native-admission-and-duplicate-check",row,role=role,source_id=identifier)
        require(charge["budget_poll"]==value["producer_charge"]["budget_poll"],"ADMISSION_ATOMIC_TAIL_POLL")
        exact(charge["detail"],("role","source_id"),"ADMISSION_CHARGE")
        before(charge["start"],row["admission_completed"],"ADMISSION_START")
        before(row["admission_completed"],charge["end"],"ADMISSION_END")
        source_time=value["row"]["original_search_completed" if role=="acquisition" else "completed"]
        before(source_time,charge["start"],"ADMISSION_AFTER_PRODUCTION")
        require(type(row["admission_completed_within_budget"]) is bool and row["admission_completed_within_budget"]==self.within(row["admission_completed"]),"ADMISSION_BUDGET")
        self.admissions[role,identifier]=row
        self.all_winners.add(value["identity"]); self.blocks[value["block"]]=value
        if self.within(row["admission_completed"]): self.budget_winners.add(value["identity"])
        if role=="research":
            self.research_winners.add(value["identity"])
            if self.within(row["admission_completed"]): self.research_budget_winners.add(value["identity"])

    def read_economics(self,row):
        identifier=number(row["acquisition_id"],"ECONOMICS_ID")
        require(identifier<len(self.acquisitions) and identifier not in self.economics and ("acquisition",identifier) in self.admissions,"ECONOMICS_ORDER")
        value=self.acquisitions[identifier]
        require(row["role"]==value["role"] and value["transactions"],"ECONOMICS_ROLE")
        economics_charge=self.consume("economics-native-state-readback",row,acquisition_id=identifier)
        require(economics_charge["budget_poll"]==value["producer_charge"]["budget_poll"],"ECONOMICS_ATOMIC_TAIL_POLL")
        receipt=row["receipt"]
        exact(receipt,("transactions","fee_total","receipt_root_matches_original_node_header","before","after","fee_units","cpu_units_separate"),"ECONOMICS_FIELDS")
        flags(receipt,true=("receipt_root_matches_original_node_header","cpu_units_separate"))
        require(receipt["fee_units"]=="native-development-token-integer" and type(receipt["transactions"]) is list and len(receipt["transactions"])==len(value["transactions"]),"FEE_SCOPE")
        account_keys={"account:"+public(a).hex() for a in (0,2,3)}
        for state in (receipt["before"],receipt["after"]):
            exact(state,("accounts","escrow_rows"),"ECONOMIC_STATE_FIELDS")
            require(type(state["accounts"]) is dict and set(state["accounts"])==account_keys and state["escrow_rows"]=={},"ECONOMIC_STATE_SCOPE")
            for account in state["accounts"].values():
                exact(account,("balance","nonce"),"ECONOMIC_ACCOUNT")
                number(account["balance"],"ACCOUNT_BALANCE");number(account["nonce"],"ACCOUNT_NONCE")
        expected_before=self.economics[max(self.economics)]["after"] if self.economics else dict(accounts={k:dict(balance=10_000_000,nonce=0) for k in account_keys},escrow_rows={})
        require(receipt["before"]==expected_before,"ECONOMIC_STATE_CHAIN")
        expected_accounts={key:dict(v) for key,v in receipt["before"]["accounts"].items()}
        encoded=[];total=0
        for tx,record in zip(value["transactions"],receipt["transactions"]):
            exact(record,("transaction_id","tag","sender","nonce","fee","fee_limit","before_balance","after_balance"),"FEE_RECORD_FIELDS")
            fee=number(record["fee"],"FEE_AMOUNT")
            key="account:"+tx["sender"].hex(); account=expected_accounts[key]
            require(record["transaction_id"]==tx["id"] and record["tag"]==tx["tag"] and record["sender"]==tx["sender"].hex() and
                    record["nonce"]==tx["nonce"]==account["nonce"]+1 and record["fee_limit"]==tx["fee_limit"] and
                    0<fee<=tx["fee_limit"] and record["before_balance"]==account["balance"] and record["after_balance"]==account["balance"]-fee,"FEE_RECORD_BINDING")
            account.update(balance=account["balance"]-fee,nonce=tx["nonce"])
            encoded.append(canonical(dict(tx=tx["id"],fee=fee,status="applied")));total+=fee
        require(receipt["after"]["accounts"]==expected_accounts and receipt["fee_total"]==total and
                sequence_root("receipts",encoded)==value["header"]["receipts"],"FEE_RECEIPT_ROOT")
        self.economics[identifier]=receipt

    def read_parent(self,row):
        flags(row,true=("actual_native_activation",),false=("sibling_chainwork_summed",))
        require(type(row["stats"]) is dict,"PARENT_STATS")
        block=row["stats"].get("tip")
        require(block in self.blocks,"ACTIVATION_NOT_ADMITTED")
        value=self.blocks[block]
        require(value["header"]["parent"].hex()==self.active,"ACTIVATION_PARENT")
        reason=row["reason"]
        if row["round"] is None:
            require(reason in ("zero-registration","zero-renewal","zero-revocation","post-revocation-maintenance") and
                    self.acquisitions[-1]["block"]==block and self.acquisitions[-1]["role"]==reason,"ACTIVATION_AUXILIARY")
            if reason!="post-revocation-maintenance": require(self.acquisitions[-1]["id"] in self.economics,"ACTIVATION_MISSING_ECONOMICS")
            if reason=="zero-renewal": self.renewal_activation=block
            if reason=="post-revocation-maintenance": require(self.revocation_readback,"RECOVERY_BEFORE_REVOCATION_CONTROL")
        else:
            round_id=number(row["round"],"ACTIVATION_ROUND",self.options["rounds"]-1)
            require(not self.budget_mode or round_id + 1 < self.options["rounds"], "FINAL_PARENT_MUST_REMAIN_FIXED")
            require(len(self.domains)==round_id+1 and self.domains[-1]["parent"]==self.active,"ACTIVATION_ROUND_DOMAIN")
            attempts=[a for a in self.attempts if a["row"]["round"]==round_id]
            require(len(attempts)==attempt_limit(self.options,round_id) and self.selection is None,"ACTIVATION_MISSING_ATTEMPTS")
            winners=[a for a in attempts if a["hit"]]
            wanted=winners[0]["block"] if winners else self.domains[-1]["templates"][0]["block"]
            require(block==wanted and reason==("first-research-winner" if winners else "paid-original-template-fallback"),"ACTIVATION_POLICY")
        self.consume("native-activate-and-readback",row,reason=reason,round=row["round"])
        self.active=block;self.active_height=value["header"]["height"]
        self.parents.append(row)
        self.stats(row["stats"])

    def read_domain(self,row):
        round_id=number(row["round"],"DOMAIN_ROUND",self.options["rounds"]-1)
        require(round_id==len(self.domains) and row["parent"]==self.active and row["height"]==self.active_height and len(self.acquisitions)>=2,"DOMAIN_ORDER")
        previous_rounds=[p for p in self.parents if p["round"] is not None]
        require(len(previous_rounds)==round_id,"DOMAIN_PREVIOUS_ACTIVATION")
        templates=self.acquisitions[-2:]
        require([a["role"] for a in templates]==["parent-template-maintenance","parent-template-zero"] and
                all(a["header"]["parent"].hex()==self.active and ("acquisition",a["id"]) in self.admissions for a in templates),"DOMAIN_TEMPLATES")
        revision=1 if round_id<self.options["rounds"]//2 else 2
        require(row["lease_revision"]==revision and revision in self.statements and
                row["tasks"]==[material(i)[2].hex() for i in range(2)],"DOMAIN_TASKS")
        lease=self.statements[revision]
        require(lease["not_before"]<=self.active_height+1<=lease["expires"],"DOMAIN_LEASE_WINDOW")
        flags(row,true=("shared_templates_paid","actual_signed_development_eligibility"))
        self.domains.append(dict(row,templates=templates))

    def expected_candidate(self,row):
        round_id=number(row["round"],"SELECTION_ROUND",self.options["rounds"]-1)
        attempt=number(row["attempt"],"SELECTION_ATTEMPT",attempt_limit(self.options,round_id)-1)
        index=number(row["task_index"],"SELECTION_TASK",1)
        ordinal=number(row["candidate"],"SELECTION_CANDIDATE",self.options["screen_width"]-1)
        require(len(self.domains)==round_id+1 and self.domains[-1]["parent"]==self.active,"SELECTION_DOMAIN")
        preceding=[a for a in self.attempts if a["row"]["round"]==round_id]
        require(attempt==len(preceding) and self.selection is None,"SELECTION_ORDER")
        template=self.domains[-1]["templates"][index]["header"]
        wanted=candidate(template,self.options,round_id,attempt,ordinal)
        require(row["header_hex"]==wanted.hex() and row["challenge"]==H("challenge",wanted).hex(),"SELECTION_HEADER_BINDING")
        return round_id,attempt,index,ordinal,wanted

    def read_screen(self,row):
        require(self.options["strategy"]=="paid-task-screen","UNEXPECTED_SCREEN")
        round_id,attempt,index,ordinal,raw=self.expected_candidate(row)
        pending=[r for r in self.screens if (r["round"],r["attempt"])==(round_id,attempt)]
        require((index,ordinal)==divmod(len(pending),self.options["screen_width"]),"SCREEN_GRID_ORDER")
        expected=noise(H("challenge",raw))
        require(row["score"]==expected[0] and type(row["score"]) is int and row["noise_hash_calls"]==expected[1] and
                row["noise_sha256"]==expected[2] and row["noise_words"]==2048 and row["score_definition"]=="sum-popcount-of-four-canonical-noise-arrays","SCREEN_NOISE_REPLAY")
        require(type(row["selected"]) is bool,"SCREEN_SELECTED_TYPE")
        flags(row,false=("complete_proof","ticket_observed","noise_passed_to_producer","credited_ticket"))
        self.screens.append(row)

    def read_selection(self,row):
        round_id,attempt,index,ordinal,_=self.expected_candidate(row)
        require(row["strategy"]==self.options["strategy"] and row["score_reads_ticket"] is False,"SELECTION_POLICY")
        screens=[r for r in self.screens if (r["round"],r["attempt"])==(round_id,attempt)]
        if self.options["strategy"]=="paid-task-screen":
            require(len(screens)==2*self.options["screen_width"] and row["screen_candidate_count"]==len(screens),"SCREEN_DENOMINATOR")
            best=min(screens,key=lambda r:(r["score"],r["task_index"],r["candidate"]))
            require((index,ordinal,row["score"])==(best["task_index"],best["candidate"],best["score"]) and
                    all(r["selected"] is (r is best) for r in screens),"SCREEN_MINIMUM")
            self.consume("paid-noise-screen-and-select",row,round=round_id,attempt=attempt,candidates=len(screens))
        else:
            require(index==int(self.options["strategy"]=="zero-only") and ordinal==0 and row["score"] is None and
                    row["screen_candidate_count"]==0 and not screens,"FIXED_SELECTION")
            self.consume("fixed-task-nonce-selection",row,round=round_id,attempt=attempt,task_index=index)
        self.selection=row;self.selections.append(row)

    def read_attempt(self,row):
        require(self.selection is not None and row["attempt_id"]==len(self.attempts) and type(row["attempt_id"]) is int,"ATTEMPT_ORDER")
        selection=self.selection
        require(all(row[k]==selection[k] for k in ("round","attempt","task_index")) and row["arm"]==actual_arm(self.options,row["task_index"]) and row["cache"]==self.options["cache"],"ATTEMPT_SELECTION")
        value=proof(row["proof"],row["task_index"]);self.proof_replays+=1
        require(value["raw_header"].hex()==selection["header_hex"] and value["header"]["transactions"]==sequence_root("transactions",[]) and
                value["header"]["receipts"]==sequence_root("receipts",[]),"ATTEMPT_HEADER")
        flags(row,true=("native_full_relation_verified","native_reference_verified"))
        require(row["proof_retention"]=="original-research-producer-returned-bytes" and row["noise_expanded_again_by_producer"] is (self.options["strategy"]=="paid-task-screen"),"ATTEMPT_PROVENANCE")
        require(type(row["unique_research_semantic"]) is bool and row["unique_research_semantic"]==(value["identity"] not in self.research_semantics),"RESEARCH_DEDUP")
        generation=self.consume("research-complete-proof",row,round=row["round"],attempt=row["attempt"],task_index=row["task_index"],arm=row["arm"])
        require(row["completed"]==generation["end"] and type(row["complete_proof_within_budget"]) is bool and
                row["complete_proof_within_budget"]==self.within(row["completed"]),"RESEARCH_COMPLETION_BUDGET")
        verify=self.consume("research-native-full-verifiers",row,round=row["round"],attempt=row["attempt"])
        require(verify["budget_poll"]==generation["budget_poll"],"VERIFICATION_ATOMIC_TAIL_POLL")
        before(generation["end"],verify["start"],"VERIFICATION_BEFORE_GENERATION")
        if self.options["cache"]=="cold": self.consume("arithmetic-prepare",row,cache="cold",task_index=row["task_index"],arm=row["arm"])
        else: require(len(self.preparations)==2,"MISSING_HOT_PREPARATION")
        self.research_semantics.add(value["identity"])
        value.update(row=row,task_index=row["task_index"],id=row["attempt_id"],producer_charge=generation)
        self.attempts.append(value);self.selection=None

    def read_revocation(self,row):
        require(not self.revocation_readback and len(self.controls)==4 and self.parents[-1]["reason"]=="zero-revocation" and row["parent"]==self.active,"REVOCATION_READBACK_ORDER")
        flags(row,true=("cache_is_not_task_authority",))
        require(row["mathematical_cache_still_allocated"] is (self.options["cache"]=="hot"),"REVOCATION_CACHE_SCOPE")
        slot=row["slot"];require(type(slot) is dict,"REVOCATION_SLOT")
        source=self.statements[2]
        require(slot.get("schema")=="qualified-demand-slot-record-v2" and slot.get("status")=="revoked" and
                slot.get("lease")==source["lease"].hex() and slot.get("statement")==source["signed"].hex() and slot.get("statement_id")==source["statement_id"] and
                slot.get("bound_task")==material(1)[2].hex() and slot.get("output_count")==0 and slot.get("output_product") is None and
                slot.get("output_height") is None and slot.get("revoked_height")==self.active_height,"REVOCATION_NATIVE_STATE_BINDING")
        self.revocation_readback=True

    def read_summary(self,row):
        require(self.summary is None,"MULTIPLE_STRATEGY_END")
        if self.initial_stats is None:
            exact(row,COMMON|set("status completed all_work_unique_winners research_unique_winners acquisitions research_completed_proofs rounds_completed context_drop_included controls_completed".split())|({"termination_budget_poll"} if self.budget_mode else set()),"EARLY_STRATEGY_FIELDS")
            require(row["sequence"]==1 and row["status"]=="process-cpu-budget-stopped-before-context" and self.limit is not None and row["completed"]["process_cpu_ns"]>=self.limit,"EARLY_BUDGET_STOP")
            require(all(type(row[k]) is int and row[k]==0 for k in ("all_work_unique_winners","research_unique_winners","acquisitions","research_completed_proofs","rounds_completed")),"EARLY_COUNTS")
            flags(row,true=("context_drop_included",),false=("controls_completed",))
        else:
            exact(row,COMMON|set(FULL_STRATEGY.split())|({"termination_budget_poll"} if self.budget_mode else set()),"STRATEGY_FIELDS")
            require(len(self.tasks)==2 and 1 in self.statements,"INCOMPLETE_CONTEXT")
            cleanup=self.consume("native-context-drop",row)
            exact(cleanup["detail"],("includes_temporary_state_cleanup",),"DROP_DETAIL")
            flags(cleanup["detail"],true=("includes_temporary_state_cleanup",))
            before(cleanup["end"],row["completed"],"STRATEGY_DROP_TIMELINE")
            complete=row["status"]=="planned-rounds-complete"
            capped=row["status"]=="safety-cap-censored"
            require((complete and not self.budget_mode) or row["status"]=="process-cpu-budget-stopped" or (capped and self.budget_mode),"STRATEGY_STATUS")
            if not complete and not capped:
                require(self.limit is not None and row["completed"]["process_cpu_ns"]>=self.limit,"FALSE_BUDGET_STOP")
            if capped:
                last=[a for a in self.attempts if a["row"]["round"]==self.options["rounds"]-1]
                require(len(self.domains)==self.options["rounds"] and len(last)==self.options["max_final_attempts"] and
                        row["rounds_completed"]==self.options["rounds"]-1 and self.selection is None and not self.revocation_readback,
                        "FALSE_SAFETY_CAP_STOP")
            rounds=sum(p["round"] is not None for p in self.parents)
            all_counts={
                "rounds_completed":rounds,"controls":len(self.controls),"acquisitions":len(self.acquisitions),
                "original_make_completed_proofs":sum(a["header"]["nonce"]+1 for a in self.acquisitions),
                "original_make_failed_target_proofs":sum(a["header"]["nonce"] for a in self.acquisitions),
                "original_make_winning_proofs":len(self.acquisitions),"research_completed_proofs":len(self.attempts),
                "research_unique_complete_semantics":len(self.research_semantics),"research_unique_winners":len(self.research_winners),
                "all_work_unique_winners":len(self.all_winners),"all_work_unique_native_blocks":len(self.blocks),
                "all_work_unique_admitted_within_budget":len(self.budget_winners),"research_unique_admitted_within_budget":len(self.research_budget_winners),
                "screened_candidates":len(self.screens),"discarded_screen_candidates":len(self.screens)-sum(r["selected"] for r in self.screens),
                "hot_preparations":sum(p["detail"]["cache"]=="hot" for p in self.preparations),
                "cold_preparations":sum(p["detail"]["cache"]=="cold" for p in self.preparations),
                "renewals":int(self.renewal_activation is not None),"transaction_count":sum(len(a["transactions"]) for a in self.acquisitions),
                "transaction_fee_total":sum(v["fee_total"] for v in self.economics.values()),
            }
            for key,wanted in all_counts.items(): require(type(row[key]) is int and row[key]==wanted,"SUMMARY_COUNT:"+key)
            for a in self.acquisitions:
                require(("acquisition",a["id"]) in self.admissions,"MISSING_ACQUISITION_ADMISSION")
                if a["transactions"]: require(a["id"] in self.economics,"MISSING_TRANSACTION_ECONOMICS")
            for a in self.attempts:
                require((("research",a["id"]) in self.admissions)==a["hit"],"MISSING_RESEARCH_WINNER_ADMISSION")
            require(row["controls_completed"] is (self.revocation_readback and self.parents[-1]["reason"]=="post-revocation-maintenance"),"CONTROL_COMPLETION")
            if complete:
                require(rounds==self.options["rounds"] and len(self.attempts)==self.options["rounds"]*self.options["attempts_per_parent"] and
                        len(self.acquisitions)==len(self.acquisition_roles) and len(self.controls)==4 and row["controls_completed"] is True and self.selection is None,"INCOMPLETE_PLANNED_STRATEGY")
            flags(row,true=("context_drop_included","fees_not_added_to_cpu","posthoc_original_miss_reconstruction_excluded"),false=("sibling_work_summed_into_chainweight","minimum_cost_strategy_claim"))
            require(row["transaction_fee_units"]=="native-development-token-integer","FEE_UNITS")
            self.stats(row["final_native_stats"])
            expected_economy=self.economics[max(self.economics)]["after"] if self.economics else dict(accounts={"account:"+public(a).hex():dict(balance=10_000_000,nonce=0) for a in (0,2,3)},escrow_rows={})
            require(row["final_economy"]==expected_economy,"FINAL_ECONOMY")
            # Only one begun construction/preparation may remain at a budget fence.
            leftovers=[c for c in self.charges if c["sequence"] not in self.used_charges]
            require(not leftovers or (not complete and len(leftovers)==1 and leftovers[0]["stage"] in
                    ("construct-signed-registration","construct-signed-atomic-renewal","construct-signed-revocation","arithmetic-prepare")),"UNCONSUMED_CHARGE")
            if leftovers:
                require(leftovers[0]["end"]["process_cpu_ns"]<=row["completed"]["process_cpu_ns"],"UNFINISHED_STAGE_TIME")
            require(sum(self.charge_cpu.values())<=row["completed"]["process_cpu_ns"],"PHASE_SUM_EXCEEDS_PROCESS")
        if self.budget_mode:
            poll=row["termination_budget_poll"]
            exact(poll,("observed","permitted"),"TERMINATION_POLL_FIELDS")
            before(poll["observed"],row["completed"],"TERMINATION_POLL_TIME")
            require(type(poll["permitted"]) is bool and poll["permitted"] == (poll["observed"]["process_cpu_ns"] < self.limit),
                    "TERMINATION_POLL_PREDICATE")
            require(poll["permitted"] is (row["status"]=="safety-cap-censored"),"TERMINATION_REASON_BINDING")
            if self.initial_stats is not None:
                require(poll==cleanup["budget_poll"],"TERMINATION_CLEANUP_POLL")
        before(row["completed"],row["observed"],"STRATEGY_COMPLETION_OBSERVED")
        self.summary=row;self.summary_sequence=row["sequence"]

    def read_reconstruction(self,row):
        require(self.summary is not None,"RECONSTRUCTION_BEFORE_STRATEGY_END")
        identifier=number(row["acquisition_id"],"RECONSTRUCTION_ID")
        require(identifier<len(self.acquisitions),"RECONSTRUCTION_SOURCE")
        original=self.acquisitions[identifier]
        wanted=[(a["id"],n) for a in self.acquisitions for n in range(a["header"]["nonce"]+1)]
        require(len(self.reconstructions)<len(wanted) and (identifier,row["ordinal"])==wanted[len(self.reconstructions)] and row["task_index"]==original["task_index"],"RECONSTRUCTION_GRID")
        value=proof(row["proof"],row["task_index"]);self.proof_replays+=1
        header=dict(original["header"]);header["nonce"]=row["ordinal"]
        last=row["ordinal"]==original["header"]["nonce"]
        require(value["raw_header"]==header_encode(header) and value["hit"] is last and row["original_winner"] is last and
                row["original_bytes_observed"] is last and row["original_winner_bytes_equal"]==(True if last else None),"RECONSTRUCTION_BINDING")
        if last: require(value["raw"]==original["raw"],"ORIGINAL_WINNER_BYTES_CHANGED")
        flags(row,true=("native_full_relation_verified","native_reference_verified"),false=("new_work_credit","used_by_selection","included_in_strategy_cpu"))
        require(row["provenance"]=="reconstructed-after-run","RECONSTRUCTION_PROVENANCE")
        self.reconstructions.append(row)

    def read_final(self,row):
        require(self.summary is not None and self.final is None and row is self.rows[-1] and row["status"]=="complete","END_ORDER")
        if self.initial_stats is None:
            exact(row,COMMON|set("status reconstructed_proofs native_admission_scope useful_learning hardness_accepted".split()),"EARLY_END_FIELDS")
            require(len(self.rows)==3 and type(row["reconstructed_proofs"]) is int and row["reconstructed_proofs"]==0 and row["native_admission_scope"]=="none","EARLY_END_SCOPE")
            flags(row,false=("useful_learning","hardness_accepted"))
        else:
            exact(row,COMMON|set(FULL_END.split()),"END_FIELDS")
            require(row["strategy_completed"]==self.summary["completed"] and row["reconstructed_proofs"]==len(self.reconstructions)==sum(a["header"]["nonce"]+1 for a in self.acquisitions) and
                    type(row["reconstructed_proofs_new_credit"]) is int and row["reconstructed_proofs_new_credit"]==0,"END_DENOMINATOR")
            before(self.summary["observed"],row["posthoc_start"],"POSTHOC_START")
            before(row["posthoc_start"],row["posthoc_end"],"POSTHOC_END")
            before(row["posthoc_end"],row["observed"],"END_OBSERVED")
            for record in self.reconstructions:
                before(row["posthoc_start"],record["observed"],"RECONSTRUCTION_POSTHOC_START")
                before(record["observed"],row["posthoc_end"],"RECONSTRUCTION_POSTHOC_END")
            require(row["posthoc_process_cpu_ns"]==row["posthoc_end"]["process_cpu_ns"]-row["posthoc_start"]["process_cpu_ns"] and
                    row["native_admission_scope"]=="original-Node-isolated-continuity-development","POSTHOC_SCOPE")
            flags(row,false=("new_real_training","useful_learning","hardness_accepted","cost_lower_bound_proved","production_activation"))
        self.final=row

    def run(self):
        for row in self.rows:
            kind=row["kind"]
            if kind in FIELDS: exact(row,COMMON|set(FIELDS[kind].split()),"ROW_FIELDS:"+kind)
            require(self.summary is None or kind in ("reconstruction","end"),"WORK_AFTER_STRATEGY_END")
            if kind=="start":
                require(row["sequence"]==0,"START_ORDER")
                flags(row,true=("sibling_winners_are_not_additive_chainweight",))
                require(row["cpu_scope"]=="whole-process-through-strategy-context-drop; posthoc-reconstruction-separate" and
                        row["shared_acquisition"]=="all strategies pay for both native task templates and zero registration" and
                        row["noise_reuse"]=="screening expands real noise; Producer API expands it again; both costs paid" and
                        row["proof_retention"]=="all research proofs and original native winners; original misses reconstructed only after strategy end","START_SCOPE")
                require(row["not_claimed"]==["minimum-strategy-cost","physical-cost-lower-bound","public-network-task-authority","Hepta-training","useful-learning","production-readiness","free-task-acquisition"],"START_LIMITS")
                require(row["budget_policy"]=="poll-before-new-acquisition-selection-preparation-proof-and-activation; bounded-stage overshoot retained; admission-completed-by-budget for credited winners" and
                        row["bounded_atomic_operations"]==["native context creation","one native make search up to 64 complete proofs plus mandatory admission/readback","one selected proof plus mandatory relation/admission observers","one complete noise-screen grid","one preparation","one source transaction construction","one activation/readback","one negative control"],"START_BUDGET")
            else:
                handlers={"charge":self.read_charge,"task":self.read_task,"task-statement":self.read_statement,"control":self.read_control,
                          "acquisition":self.read_acquisition,"admission":self.read_admission,"economics":self.read_economics,"parent":self.read_parent,
                          "parent-domain":self.read_domain,"screen":self.read_screen,"selection":self.read_selection,"attempt":self.read_attempt,
                          "revocation-readback":self.read_revocation,"strategy-end":self.read_summary,"reconstruction":self.read_reconstruction,"end":self.read_final}
                require(kind in handlers,"UNKNOWN_RECORD_KIND")
                handlers[kind](row)
        require(self.final is not None,"MISSING_END")
        compact=lambda value:dict(id=value["id"],task_index=value["task_index"],parent=value["header"]["parent"].hex(),height=value["header"]["height"],
                                 challenge=value["challenge"].hex(),proof_sha256=value["digest"],semantic_id=value["identity"],block_id=value["block"],target_hit=value["hit"])
        count_keys=("rounds_completed","acquisitions","original_make_completed_proofs","original_make_failed_target_proofs","research_completed_proofs",
                    "research_unique_complete_semantics","research_unique_winners","all_work_unique_winners","all_work_unique_native_blocks",
                    "all_work_unique_admitted_within_budget","research_unique_admitted_within_budget","screened_candidates","discarded_screen_candidates",
                    "hot_preparations","cold_preparations","transaction_count","transaction_fee_total")
        result = dict(schema="pon-w1-parent-reuse-readback-v2" if self.budget_mode else "pon-w1-parent-reuse-readback-v1",
                    options=self.options,status=self.summary["status"],
                    counts={key:self.summary.get(key,0) for key in count_keys},strategy_cpu_ns=self.summary["completed"]["process_cpu_ns"],
                    charge_cpu_ns_by_stage=dict(self.charge_cpu),unattributed_strategy_cpu_ns=self.summary["completed"]["process_cpu_ns"]-sum(self.charge_cpu.values()),
                    posthoc_process_cpu_ns=self.final.get("posthoc_process_cpu_ns",0),final_stats=self.summary.get("final_native_stats"),
                    controls=self.controls,controls_completed=self.summary["controls_completed"],retained_proof_records_replayed=self.proof_replays,
                    python_replayed=dict(full_relation_records=self.proof_replays,acquisition_winners=len(self.acquisitions),research_proofs=len(self.attempts),
                                         posthoc_reconstruction_records=len(self.reconstructions),noise_screen_candidates=len(self.screens),
                                         transaction_signatures=sum(len(a["transactions"]) for a in self.acquisitions),source_statement_records=len(self.statements)),
                    native_reported=dict(parent_eligible_admitted_blocks=len(self.blocks),state_execution_replayed_by_python=False,clock_attested=False,
                                         process_cpu_includes_native_observers_and_context_drop=True,task_scope="isolated-development-signers-and-continuity-maintenance"),
                    attempts=[dict(compact(a),round=a["row"]["round"],attempt=a["row"]["attempt"],completed=a["row"]["completed"],
                                   admission_completed=self.admissions.get(("research",a["id"]),{}).get("admission_completed")) for a in self.attempts],
                    acquisitions=[dict(compact(a),role=a["role"],original_make_complete_attempts=a["header"]["nonce"]+1,
                                       original_search_completed=a["row"]["original_search_completed"],admission_completed=self.admissions["acquisition",a["id"]]["admission_completed"]) for a in self.acquisitions],
                    limits=["No independent native State execution or task-qualification proof", "CPU and native admissions are source-bound local observations",
                            "Original hidden miss bytes are reconstructed after selection, never raw original retention", "Shared acquisition is not each strategy's theoretical minimum cost",
                            "No new Hepta training, utility or physical-cost lower bound"])
        if self.budget_mode:
            final_round=self.options["rounds"]-1
            final=[a for a in self.attempts if a["row"]["round"]==final_round]
            prefix=[a for a in self.attempts if a["row"]["round"]<final_round]
            credited=lambda values:len({a["identity"] for a in values if ("research",a["id"]) in self.admissions and
                                       self.within(self.admissions["research",a["id"]]["admission_completed"])})
            complete=lambda values:len({a["identity"] for a in values if self.within(a["row"]["completed"])})
            result["budget_experiment"] = dict(
                mode=BUDGET_MODE,measurement_scope="paid-advancing-prefix-then-fixed-final-parent-native-admissions",
                termination_budget_poll=self.summary["termination_budget_poll"],
                prefix_round_limit=final_round,prefix_attempt_limit_per_parent=self.options["attempts_per_parent"],
                final_parent_attempt_cap=self.options["max_final_attempts"],
                planned_research_attempt_cap=final_round*self.options["attempts_per_parent"]+self.options["max_final_attempts"],
                reached_final_parent=len(self.domains)==self.options["rounds"],
                final_parent=self.domains[-1]["parent"] if len(self.domains)==self.options["rounds"] else None,
                prefix_research_attempts=len(prefix),final_parent_research_attempts=len(final),
                prefix_unique_complete_within_budget=complete(prefix),final_parent_unique_complete_within_budget=complete(final),
                prefix_unique_admitted_within_budget=credited(prefix),final_parent_unique_admitted_within_budget=credited(final),
                safety_cap_reached=len(final)==self.options["max_final_attempts"],
                stopped_on_safety_cap=self.summary["status"]=="safety-cap-censored",
                stopped_on_budget=self.summary["status"].startswith("process-cpu-budget-stopped"),
                effective_arm_by_task=[actual_arm(self.options,index) for index in range(2)],
                continuous_chain_growth_throughput=False,maximum_adversarial_yield_proved=False)
            result["limits"].extend(("The final parent stays fixed; distinct admitted siblings are not serial chain growth",
                                     "Only budget-stopped jobs beyond the registered cap controls measure the complete B interval; late admissions receive no credit",
                                     "The declared structure-specialized arm map is not a fastest-known or globally optimal policy claim"))
        return result


def read_parent(path, expected_options=None):
    rows, metadata = load(path)
    return dict(Reader(rows,expected_options).run(), **metadata)
