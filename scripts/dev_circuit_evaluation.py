"""Prepare and execute the paired Circuit evaluation used by the isolated native ledger test."""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import time

ATTEMPT_FILE = "EVALUATION_ATTEMPT.json"
ATTEMPT_SCHEMA_V1 = "trnm-evaluation-child-attempt-v1"
ATTEMPT_SCHEMA = "trnm-evaluation-child-attempt-v2"
INTENT_FILE = "EVALUATION_STARTED.json"
INTENT_SCHEMA_V1 = "trnm-evaluation-child-intent-v1"
INTENT_SCHEMA = "trnm-evaluation-child-intent-v2"
CPU_SCOPE_V1 = "getrusage RUSAGE_CHILDREN delta; concurrent children are not isolated"
CPU_SCOPE = "wait4 owned PID; child plus descendants it reaped; excludes detached or unreaped descendants"
COST_SCHEMAS_V3 = {f"trnm-isolated-{kind}-evaluation-cost-v3" for kind in
                   ("circuit", "plain-paired", "historical")}
COST_SCHEMAS_V2 = {f"trnm-isolated-{kind}-evaluation-cost-v2" for kind in
                   ("circuit", "plain-paired", "historical")}
COST_SCHEMAS_V1 = {schema.removesuffix("v2") + "v1" for schema in COST_SCHEMAS_V2}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha(canonical(value))


def read(path):
    return json.loads(path.read_bytes())


def record(path, value):
    data = canonical(value) + b"\n"
    with path.open("xb") as handle:
        handle.write(data)
    return sha(data)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def source_files(root):
    entries = []
    for p in sorted(root.rglob("*.py")):
        require(not p.is_symlink(), "symlinked evaluator source")
        entries.append(dict(path=p.relative_to(root).as_posix(), sha256=sha(p.read_bytes())))
    require(any(e["path"] == "paired_cold.py" for e in entries), "missing paired evaluator")
    return entries


def check_inputs(materials, pins, *, request_path=None, frozen_path=None, circuit=True):
    frozen = read(frozen_path or materials / "FROZEN.json")
    request = read(request_path or materials / "paired.json")
    require(frozen["schema"] == "hepta.paired-cold.freeze.v1" and
            request["schema"] == "hepta.paired-cold.request.v1", "incorrect evaluation schema")
    for key in ("candidate", "parent", "retention", "timeout_seconds"):
        require(frozen[key] == request[key], "frozen evaluation fields changed")
    actual = dict(freeze=digest(frozen), request=digest(request), candidate=digest(request["candidate"]))
    require(actual == pins, "evaluation admission pins differ")
    schema = "hepta.frozen-circuit-bundle.v1" if circuit else "hepta.experimental-model.v1"
    require(all(request[arm]["schema"] == schema for arm in ("parent", "candidate")) and
            request["future"] and request["retention"], "unsupported model or empty evaluation")
    return request


def prepare(job, materials, source, pins, *, intake=None, request_path=None, frozen_path=None, inspect_only=False,
            loop_identity=None, expected_loop=None):
    import dev_intake_evaluation as plain

    require((loop_identity is None) == (expected_loop is None), "both loop identity and retained pin required")
    if loop_identity is not None:
        require(intake is not None and not inspect_only, "bound loop needs an original intake release")
    plain_model = intake is not None or inspect_only
    request_path = request_path or materials / "paired.json"
    frozen_path = frozen_path or materials / "FROZEN.json"
    retention_pin = None
    if intake is not None and plain.requires_retention(intake, read(frozen_path)["candidate"]):
        retention_pin = intake["source_retention_sha256"]
        source_report = Path(os.environ.get("TRNM_DEV_SOURCE_RETENTION_FILE", frozen_path.with_name("RETENTION.json")))
        record(job / "SOURCE_RETENTION.json", plain.original_retention(source_report, retention_pin))
    request = check_inputs(materials, pins, request_path=request_path, frozen_path=frozen_path, circuit=not plain_model)
    if plain_model:
        require(len(request["future"]) == 1, "single release requires one future record")
        retained = job / "PAIRED_INPUT.json"
        record(retained, request)
        request_path = retained
    with (job / "FROZEN.json").open("xb") as handle:
        handle.write(frozen_path.read_bytes())
    require(digest(read(job / "FROZEN.json")) == pins["freeze"], "freeze changed during staging")
    # A private copy fixes the Python source used by both workers, even if the source checkout changes.
    original = source / "scripts" / "cell_experiments"
    entries = source_files(original)
    snapshot = job / "runtime" / "cell_experiments"
    for entry in entries:
        target = snapshot / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original / entry["path"], target)
    require(entries == source_files(snapshot), "source snapshot changed while copying")
    listing = entries if not plain_model else dict(package=entries, catalog=plain.catalog_snapshot(job, source, pins["freeze"]))
    source_hash = record(job / "SOURCE.json", listing)
    if loop_identity is not None:
        import dev_loop_identity as bound

        bound.validate(loop_identity, expected_loop, intake, request, read(job / "FROZEN.json"),
                       runtime=bound.observed_runtime(entries, loop_identity))
    if plain_model:
        plain.check_catalog(job, listing["catalog"], pins["freeze"])
        plain.preflight(job, materials, pins["request"], retention_pin)
    if inspect_only:
        result = dict(schema="trnm-plain-evaluation-input-preflight-v1", pins=pins,
                      source_listing_sha256=source_hash, catalog=listing["catalog"])
        record(job / "PREFLIGHT.json", result)
        return result
    terms = dict(schema="trnm-isolated-circuit-evaluation-request-v1", job_id=secrets.token_hex(16),
                 pins=pins, parent=digest(request["parent"]), source_listing_sha256=source_hash,
                 freeze_file_sha256=sha((job / "FROZEN.json").read_bytes()),
                 request_file_sha256=sha(request_path.read_bytes()),
                 runtime=dict(python=sys.version.split()[0],
                              packages={n: importlib.metadata.version(n) for n in ("torch", "transformers", "peft")}),
                 cpu_limit_ns=1_000_000_000_000, evaluated_examples=2 * (len(request["future"]) + len(request["retention"])),
                 output_schema="trnm-isolated-circuit-evaluation-delivery-v1")
    if intake is not None:
        terms.update(schema=plain.ADMISSION, output_schema=plain.DELIVERY, job_id=intake["admission_sha256"],
                     intake_release=intake, intake_release_sha256=digest(intake))
        if retention_pin is not None:
            terms["source_retention_sha256"] = retention_pin
    if loop_identity is not None:
        bound_admission, bound_delivery = bound.schemas(loop_identity)
        terms.update(schema=bound_admission, output_schema=bound_delivery,
                     loop_identity=loop_identity, loop_identity_sha256=expected_loop,
                     chain_evaluator_sources=bound.chain_sources(loop_identity))
    record(job / "ADMISSION.json", terms)


def valid_timeout(value):
    return value is None or (type(value) in (int, float) and 0 < value <= 86400)


def measure(job, command, env, *, timeout_seconds=None):
    """Retain measured child attempts, including failures; never infer full cost.

    A killed recorder may leave no receipt. Absence remains unknown, not zero.
    Receipt persistence and earlier/later pipeline stages are outside this clock.
    Optional wall timeout is at most one day; None retains the caller's existing
    supervision policy. It is not a CPU limit or a complete process-tree meter.
    """
    require(callable(getattr(os, "wait4", None)), "owned child CPU accounting requires wait4")
    require(valid_timeout(timeout_seconds), "invalid evaluation wall timeout")
    require(not os.path.lexists(job / ATTEMPT_FILE), "evaluation attempt already recorded")
    require(not any(os.path.lexists(job / name) for name in ("evaluation.stdout", "evaluation.stderr")),
            "evaluation logs already exist")
    request = sha((job / "ADMISSION.json").read_bytes())
    # The exclusive launch gate and output reservations are outside the terminal
    # recorder. A losing/colliding caller must not write another owner's outcome.
    intent = record(job / INTENT_FILE, dict(schema=INTENT_SCHEMA, request_sha256=request,
        command_sha256=digest(command), attempt_nonce=secrets.token_hex(16),
        wall_timeout_seconds=timeout_seconds, execution_authority=False))
    with (job / "evaluation.stdout").open("x+b") as stdout, (job / "evaluation.stderr").open("x+b") as stderr:
        return _measure_owned(job, command, env, request, intent, stdout, stderr, timeout_seconds)


def _wait_owned(child, deadline=None):
    """Only this owner reaps this PID; Popen.wait/poll must not run in parallel."""
    while True:
        pid, status, usage = os.wait4(child.pid, 0 if deadline is None else os.WNOHANG)
        if pid:
            require(pid == child.pid, "wait4 returned a different child")
            # Avoid a second waitpid in Popen cleanup. No process-global CPU
            # delta can attribute other evaluation jobs to this receipt.
            child.returncode = os.waitstatus_to_exitcode(status)
            return usage
        remaining = deadline - time.monotonic_ns()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(child.args, 0)
        time.sleep(min(remaining / 1_000_000_000, 0.01))


def _measure_owned(job, command, env, request, intent, stdout, stderr, timeout_seconds):
    start = time.monotonic_ns()
    deadline = None if timeout_seconds is None else start + int(timeout_seconds * 1_000_000_000)
    child, usage = None, None
    status, returncode, error_type, failure = "unknown", None, None, None
    try:
        child = subprocess.Popen(command, cwd=job, env=env, stdout=stdout, stderr=stderr,
                                 start_new_session=True)
        try:
            usage = _wait_owned(child, deadline)
        except subprocess.TimeoutExpired:
            raise subprocess.TimeoutExpired(command, timeout_seconds) from None
        returncode = child.returncode
        status = "succeeded" if returncode == 0 else "failed"
        if deadline is not None and time.monotonic_ns() > deadline:
            raise subprocess.TimeoutExpired(command, timeout_seconds)
        if returncode:
            raise subprocess.CalledProcessError(returncode, command)
    except BaseException as error:
        error_type = type(error).__name__
        failure = error
        if child is not None and child.returncode is None and not isinstance(error, ChildProcessError):
            try:
                # The unreaped session leader still owns this process-group ID.
                # Terminate its remaining group before reaping; do not signal a
                # possibly reused PID after a successful terminal wait4.
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                usage = _wait_owned(child)
                returncode, status = child.returncode, "failed"
            except BaseException as cleanup_error:
                error.add_note("evaluation child cleanup could not be completed: " + type(cleanup_error).__name__)
        raise
    finally:
        wall_ns = time.monotonic_ns() - start
        cpu_ns = None if usage is None else round((usage.ru_utime + usage.ru_stime) * 1_000_000_000)
        try:
            require(sha((job / INTENT_FILE).read_bytes()) == intent, "evaluation launch intent changed")
            logs = {}
            for name, stream in (("evaluation.stdout", stdout), ("evaluation.stderr", stderr)):
                stream.flush()
                stream.seek(0)
                logs[name] = hashlib.file_digest(stream, "sha256").hexdigest()
            record(job / ATTEMPT_FILE, dict(schema=ATTEMPT_SCHEMA, request_sha256=request,
                intent_sha256=intent,
                command_sha256=digest(command), child_status=status, returncode=returncode,
                error_type=error_type, cpu_ns=cpu_ns, wall_ns=wall_ns, cpu_scope=CPU_SCOPE,
                logs=logs, cost_completeness_verified=False, execution_authority=False))
        except Exception as receipt_error:
            # Preserve the original execution failure if recording also fails.
            if error_type is None:
                raise
            failure.add_note("evaluation attempt receipt could not be persisted: " + type(receipt_error).__name__)
    return cpu_ns, wall_ns


def attempt_cost_fields(job):
    return dict(evaluation_attempt_sha256=sha((job / ATTEMPT_FILE).read_bytes()),
                cpu_scope=CPU_SCOPE, cost_completeness_verified=False)


def verify_attempt_cost(job, cost, *, admission=None):
    """Verify retained child-cost statements; this is not execution authentication."""
    schema = cost.get("schema")
    require(schema in COST_SCHEMAS_V1 | COST_SCHEMAS_V2 | COST_SCHEMAS_V3, "unknown evaluation cost schema")
    if admission is not None:
        import dev_intake_evaluation as plain

        request_schema = admission.get("schema")
        if request_schema == "trnm-isolated-historical-evaluation-request-v1":
            family = "historical"
        elif request_schema in plain.ADMISSIONS:
            family = "plain-paired"
        else:
            require(request_schema == "trnm-isolated-circuit-evaluation-request-v1", "unknown cost admission schema")
            family = "circuit"
        version = "v3" if schema in COST_SCHEMAS_V3 else "v2" if schema in COST_SCHEMAS_V2 else "v1"
        require(schema == f"trnm-isolated-{family}-evaluation-cost-{version}", "cost family differs from admission")
        if request_schema == plain.ARTIFACT_ADMISSION:
            require(schema in COST_SCHEMAS_V2 | COST_SCHEMAS_V3, "artifact-bound admission requires cost v2 or v3")
    if schema in COST_SCHEMAS_V1:
        require("evaluation_attempt_sha256" not in cost, "attempt pin requires cost v2 or v3")
        require(cost.get("cost_completeness_verified", False) is False, "historical cost completeness differs")
        return dict(scope="historical_evaluation_only", attempt_receipt_bound=False,
                    cost_completeness_verified=False)
    isolated = schema in COST_SCHEMAS_V3
    cpu_scope = CPU_SCOPE if isolated else CPU_SCOPE_V1
    attempt_schema = ATTEMPT_SCHEMA if isolated else ATTEMPT_SCHEMA_V1
    intent_schema = INTENT_SCHEMA if isolated else INTENT_SCHEMA_V1
    require(cost.get("cpu_scope") == cpu_scope and cost.get("cost_completeness_verified") is False,
            "evaluation cost scope differs")
    raw = (job / ATTEMPT_FILE).read_bytes()
    require(sha(raw) == cost.get("evaluation_attempt_sha256"), "evaluation attempt pin differs")
    attempt = read(job / ATTEMPT_FILE)
    require(set(attempt) == {"schema", "request_sha256", "command_sha256", "intent_sha256", "child_status", "returncode",
                            "error_type", "cpu_ns", "wall_ns", "cpu_scope", "logs",
                            "cost_completeness_verified", "execution_authority"}
            and attempt["schema"] == attempt_schema
            and attempt["request_sha256"] == sha((job / "ADMISSION.json").read_bytes())
            and attempt["child_status"] == "succeeded" and type(attempt["returncode"]) is int
            and attempt["returncode"] == 0 and attempt["error_type"] is None
            and attempt["cost_completeness_verified"] is False and attempt["execution_authority"] is False
            and attempt["cpu_scope"] == cpu_scope, "evaluation attempt scope or request differs")
    for key in ("cpu_ns", "wall_ns"):
        require(type(attempt[key]) is int and 0 <= attempt[key] < 2**64
                and type(cost.get(key)) is int and cost[key] == attempt[key], "evaluation attempt counters differ")
    require(attempt["wall_ns"] > 0 and isinstance(attempt["command_sha256"], str)
            and len(attempt["command_sha256"]) == 64
            and all(c in "0123456789abcdef" for c in attempt["command_sha256"]), "invalid attempt identity")
    intent_raw = (job / INTENT_FILE).read_bytes()
    require(sha(intent_raw) == attempt["intent_sha256"], "evaluation launch intent pin differs")
    intent = read(job / INTENT_FILE)
    intent_fields = {"schema", "request_sha256", "command_sha256", "attempt_nonce", "execution_authority"}
    if isolated:
        intent_fields.add("wall_timeout_seconds")
        require(valid_timeout(intent.get("wall_timeout_seconds")), "evaluation launch timeout differs")
    require(set(intent) == intent_fields
            and intent["schema"] == intent_schema and intent["execution_authority"] is False
            and intent["request_sha256"] == attempt["request_sha256"]
            and intent["command_sha256"] == attempt["command_sha256"]
            and isinstance(intent["attempt_nonce"], str) and len(intent["attempt_nonce"]) == 32
            and all(c in "0123456789abcdef" for c in intent["attempt_nonce"]), "evaluation launch intent differs")
    logs = {name: sha((job / name).read_bytes()) for name in ("evaluation.stdout", "evaluation.stderr")}
    require(attempt["logs"] == logs, "evaluation attempt logs differ")
    return dict(scope="owned_child_and_reaped_descendants" if isolated else "historical_process_children_delta",
                concurrent_child_cpu_isolation_declared=isolated, attempt_receipt_bound=True,
                cost_completeness_verified=False, execution_authenticated=False)


def execute(job, materials):
    import dev_intake_evaluation as plain

    terms = read(job / "ADMISSION.json")
    reservation = read(job / "RESERVATION.json")
    require(reservation["request"] == sha((job / "ADMISSION.json").read_bytes()), "reservation request mismatch")
    plain_model = terms["schema"] in plain.ADMISSIONS
    request_path = job / "PAIRED_INPUT.json" if plain_model else materials / "paired.json"
    request = check_inputs(materials, terms["pins"], request_path=request_path, frozen_path=job / "FROZEN.json",
                           circuit=not plain_model)
    listing = read(job / "SOURCE.json")
    if plain_model:
        require(sha(request_path.read_bytes()) == terms["request_file_sha256"], "original paired request bytes differ")
        plain.check_retention_record(job, terms)
        plain.check_catalog(job, listing["catalog"], terms["pins"]["freeze"])
        if terms["schema"] in plain.BOUND_ADMISSIONS:
            import dev_loop_identity as bound

            bound.check_terms(job, terms, live=True)
    snapshot = job / "runtime" / "cell_experiments"
    before = source_files(snapshot)
    require(sha((job / "SOURCE.json").read_bytes()) == terms["source_listing_sha256"]
            and before == (listing["package"] if plain_model else listing), "evaluator snapshot mismatch")
    output = job / "evaluation"
    require(not output.exists(), "evaluation output exists")
    env = dict(os.environ, PYTHONPATH=str(snapshot.parent), PYTHONDONTWRITEBYTECODE="1",
               HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", TOKENIZERS_PARALLELISM="false")
    command = ["unshare", "-Urn", "--", sys.executable, "-B", "-m", "cell_experiments.paired_cold",
               str(request_path), terms["pins"]["request"], str(materials), str(output)]
    cpu_ns, wall_ns = measure(job, command, env)
    require(0 < cpu_ns <= terms["cpu_limit_ns"] and source_files(snapshot) == before, "CPU cap or evaluator changed")
    require(check_inputs(materials, terms["pins"], request_path=request_path, frozen_path=job / "FROZEN.json",
                           circuit=not plain_model) == request, "input changed after execution")
    result = read(output / "RESULT.json")
    if plain_model:
        plain.check_catalog(job, listing["catalog"], terms["pins"]["freeze"])
        plain.check_plain_result(result, terms)
        if terms["schema"] in plain.BOUND_ADMISSIONS:
            bound.check_terms(job, terms, live=True)
    require(result["schema"] == "hepta.paired-cold.result.v1" and result["circuit_loaded"] is (not plain_model)
            and result["external_teacher_calls_by_runner"] == 0 and result["request_sha256"] == terms["pins"]["request"],
            "wrong cold result")
    receipts = result["cold_receipts"]
    require([r["arm"] for r in receipts] == ["parent", "candidate"] and receipts[0]["pid"] != receipts[1]["pid"]
            and [r["model_digest"] for r in receipts] == [terms["parent"], terms["pins"]["candidate"]]
            and all(r["request_sha256"] == terms["pins"]["request"] for r in receipts),
            "wrong reloaded model or request")
    evaluated = sum(len(r["row_hashes"]) for r in receipts)
    require(evaluated == terms["evaluated_examples"], "incomplete paired rows")
    cost = dict(schema="trnm-isolated-circuit-evaluation-cost-v3", evaluated_examples=evaluated,
                cpu_ns=cpu_ns, wall_ns=wall_ns, **attempt_cost_fields(job))
    if plain_model:
        cost.update(schema="trnm-isolated-plain-paired-evaluation-cost-v3")
    else:
        cost["circuit_work"] = result["measured_circuit_work"]
    cost_hash = record(job / "COST.json", cost)
    files = {p.relative_to(output).as_posix(): sha(p.read_bytes()) for p in sorted(output.rglob("*")) if p.is_file()}
    record(job / "DELIVERY.json", dict(schema=terms["output_schema"], request=reservation["request"],
        task=reservation["task"], reservation_sha256=sha((job / "RESERVATION.json").read_bytes()),
        model=terms["pins"]["candidate"], paired_request=terms["pins"]["request"], result_sha256=files["RESULT.json"],
        cost_sha256=cost_hash, raw_evaluation_files=files))


def score_receipt(task, prediction, outcome, source_hashes):
    from cell_adoption_readback import decode

    spec = task["task"]["verifier"]
    name = [spec["name"], spec["version"]]
    answer = prediction["answer"].encode()
    success = outcome["result"]["success"]
    receipt = {key: value for key, value in outcome.items() if key not in ("success", "receipt_sha256")}
    require(outcome["schema"] == "hepta.cell-experiments.semantic-receipt.v1"
            and outcome["record_id"] == task["record_id"] and outcome["verifier"] == name
            and outcome["verifier_source_sha256"] in source_hashes
            and outcome["parameters_sha256"] == digest(spec["parameters"])
            and outcome["input_sha256"] == prediction["input_sha256"] == sha(task["task"]["input"].encode())
            and outcome["answer_sha256"] == sha(answer) and outcome["receipt_sha256"] == digest(receipt)
            and type(success) is bool and outcome["success"] is success, "semantic receipt differs from original task")
    if name != ["json_artifact", "1"]:
        return success, False
    require(set(spec["parameters"]) == {"expected"} and len(answer) <= 65536, "invalid JSON task or answer")
    try:
        matched = canonical(decode(answer, 65536)) == canonical(spec["parameters"]["expected"])
        reason = "structure_equal" if matched else "structure_mismatch"
    except (ValueError, TypeError):
        matched, reason = False, "invalid_json"
    require(outcome["result"] == {"success": matched, "reason": reason}, "semantic answer replay differs")
    return success, True


def paired_performance(job, admission, request, result):
    panels = ("future", "retention")
    arms = ("parent", "candidate")
    models = dict(parent=admission["parent"], candidate=admission["pins"]["candidate"])
    output = job / "evaluation"
    listing = read(job / "SOURCE.json")
    source_hashes = {entry["sha256"] for entry in (listing if isinstance(listing, list) else listing["package"])}
    tasks = [(panel, task) for panel in panels for task in request[panel]]
    receipts = [read(output / arm / "END.json") for arm in arms]
    require(result["schema"] == "hepta.paired-cold.result.v1" and result["evaluation_order"] == list(panels)
            and result["circuit_loaded"] is (request["parent"]["schema"] == "hepta.frozen-circuit-bundle.v1")
            and result["external_teacher_calls_by_runner"] == 0
            and all(result[field] is False for field in ("authenticated_users_established",
                    "prospective_arrival_authenticated", "production_adoption", "settlement"))
            and result["request_sha256"] == admission["pins"]["request"]
            and receipts == result["cold_receipts"] and receipts[0]["pid"] != receipts[1]["pid"]
            and 2 * len(tasks) == admission["evaluated_examples"], "paired evaluation scope or cold processes differ")
    for arm, receipt in zip(arms, receipts):
        require(receipt["arm"] == arm and receipt["model_digest"] == models[arm]
                and receipt["request_sha256"] == result["request_sha256"]
                and len(receipt["row_hashes"]) == len(tasks), "cold arm or row count differs")

    categories = {(False, False): "neither", (True, False): "parent_only",
                  (False, True): "candidate_only", (True, True): "both"}
    counts = {panel: dict.fromkeys(categories.values(), 0) for panel in panels}
    rows = []
    for index, (panel, task) in enumerate(tasks):
        task_hash = digest(task)
        inputs, scores, replayed = [], [], []
        for arm, receipt in zip(arms, receipts):
            row = read(output / arm / f"{index:04d}.json")
            prediction = row["prediction"]
            require(row["panel"] == panel and row["task_id"] == task["task_id"] and row["task_sha256"] == task_hash
                    and prediction["pid"] == receipt["pid"] and prediction["loaded_model_digest"] == models[arm]
                    and digest(row) == receipt["row_hashes"][index], "cold row differs from model, task, or receipt")
            inputs.append((row["input_ids_sha256"], prediction["rendered_input_sha256"], prediction["input_tokens"]))
            score, independent = score_receipt(task, prediction, row["outcome"], source_hashes)
            scores.append(score)
            replayed.append(independent)
        require(inputs[0] == inputs[1], "paired effective inputs differ")
        category = categories[tuple(scores)]
        counts[panel][category] += 1
        rows.append(dict(panel=panel, task_sha256=task_hash, outcome=category, answers_regraded=all(replayed)))
    delta = counts["future"]["candidate_only"] - counts["future"]["parent_only"]
    retained = counts["retention"]["both"] > 0 and counts["retention"]["parent_only"] == 0
    require(canonical(counts) == canonical(result["counts"]) and type(result["future_success_count_delta"]) is int
            and delta == result["future_success_count_delta"] and retained is result["old_parent_successes_preserved"],
            "paired aggregate differs from cold rows")
    return dict(parent_sha256=models["parent"], candidate_sha256=models["candidate"],
                request_sha256=result["request_sha256"], rows=rows, counts=counts,
                future_success_count_delta=delta, old_parent_successes_preserved=retained,
                prospective_arrival_authenticated=False, actual_consumer_use_verified=False,
                production_adoption=False, learning_improvement_bonus=False)


def verify(job, *, expected_release=None):
    """Read the retained byte and operation commitments without modifying the capture."""
    import cell_learning_business_economics as economics
    import dev_intake_evaluation as plain

    a, r, c, d, n = (read(job / (name + ".json")) for name in
                      ("ADMISSION", "RESERVATION", "COST", "DELIVERY", "CURRENT"))
    request = sha((job / "ADMISSION.json").read_bytes())
    output = sha((job / "DELIVERY.json").read_bytes())
    evidence = sha((job / "evaluation/RESULT.json").read_bytes())
    charge = sha((job / "COST.json").read_bytes())
    cost_scope = verify_attempt_cost(job, c, admission=a)
    historical = a["schema"] == "trnm-isolated-historical-evaluation-request-v1"
    if expected_release is not None:
        require(a["schema"] in plain.ADMISSIONS and a["intake_release_sha256"] == expected_release,
                "independently retained release differs")
    if a["schema"] in plain.ADMISSIONS:
        spec, input_key = plain.ADMISSIONS[a["schema"]], "paired_request"
        retained = job / "PAIRED_INPUT.json"
        require(sha(retained.read_bytes()) == a["request_file_sha256"] and
                digest(read(retained)) == a["pins"]["request"], "original paired request bytes differ")
        plain.check_retention_record(job, a)
        plain.check_catalog(job, read(job / "SOURCE.json")["catalog"], a["pins"]["freeze"])
        plain.check_plain_result(read(job / "evaluation/RESULT.json"), a)
        if a["schema"] in plain.BOUND_ADMISSIONS:
            import dev_loop_identity as bound

            bound.check_terms(job, a)
    elif historical:
        scope = "retrospective_historical_A_and_authored_retention"
        spec = "trnm-isolated-historical-evaluation-delivery-v1"
        input_key = "retrospective_request"
    else:
        require(a["schema"] == "trnm-isolated-circuit-evaluation-request-v1", "wrong admission schema")
        spec = "trnm-isolated-circuit-evaluation-delivery-v1"
        input_key = "paired_request"
    require(d["schema"] == a["output_schema"] == spec and n["schema"] == "pon-native-task-operation-current-v3",
            "wrong capture schema")
    require(sha((job / "SOURCE.json").read_bytes()) == a["source_listing_sha256"], "source pin mismatch")
    frozen = read(job / "FROZEN.json")
    require(sha((job / "FROZEN.json").read_bytes()) == a["freeze_file_sha256"] and
            digest(frozen) == a["pins"]["freeze"] and digest(frozen["parent"]) == a["parent"]
            and digest(frozen["candidate"]) == a["pins"]["candidate"], "freeze pin mismatch")
    submitted = read(job / "evaluation/REQUEST.json")
    require(digest(submitted) == a["pins"]["request"], "evaluation request differs")
    if historical:
        history = read(job / "evaluation/RESULT.json")
        require(submitted == a["historical_work"] and history["scope"] == submitted["scope"] == scope
                and history["future_records"] == history["prospective_arrivals"] == history["certified_hepta_users"] == 0
                and history["request_sha256"] == a["pins"]["request"] and history["external_teachers_used"] == 0
                and history["weight_updates"] == 0 and history["adoption"] is False and
                history["arms"]["parent"]["model_sha256"] == a["parent"] and
                history["arms"]["candidate"]["model_sha256"] == a["pins"]["candidate"] and
                all(set(history["arms"][arm]["outcomes"]) == {"historical_training_A", "old_capability"}
                    and sha((job / "evaluation" / (arm + "-cold.json")).read_bytes()) ==
                    history["arms"][arm]["raw_file_sha256"] for arm in ("parent", "candidate")),
                "historical replay scope differs")
    else:
        require(digest(submitted["candidate"]) == a["pins"]["candidate"] and
                digest(submitted["parent"]) == a["parent"], "paired input mismatch")
    require(r["terms"] == n["original_full_contract"]["terms"] and
            r["request"] == request == d["request"] == bytes(r["terms"]["request"]).hex() and
            bytes(r["terms"]["model"]).hex() == a["pins"]["candidate"] == d["model"] and
            bytes(r["terms"]["input"]).hex() == a["pins"]["request"] == d[input_key], "funded terms mismatch")
    require(d["reservation_sha256"] == sha((job / "RESERVATION.json").read_bytes()) and
            r["task"] == d["task"] == n["task"] and n["output"] == output and
            evidence == d["result_sha256"] == n["target_receipt_commitment"] and
            charge == d["cost_sha256"] == n["declared_costs"]["measurement_receipt"] and
            n["declared_costs"]["evaluation_units"] == c["cpu_ns"], "delivery or measured cost mismatch")
    files = {p.relative_to(job / "evaluation").as_posix(): sha(p.read_bytes())
             for p in sorted((job / "evaluation").rglob("*")) if p.is_file()}
    require(files == d["raw_evaluation_files"], "raw evaluation bytes differ")
    effects = read(job / "SIGNED_EFFECTS.json")
    for key, expected in (("signed_delivery", n["original_delivery_operation"]),
                          ("signed_arbitration", n["current_payment"]["operation"])):
        require(economics._native_hash(b"tx-id", bytes.fromhex(effects[key])) == expected, "signed operation differs")
    payment = n["current_payment"]
    require(n["native_status"] == "settled" and n["remaining_native_escrow"] == 0 and
            n["current_branch_payment_membership"] is True and payment["subject"] == output and
            r["reserved_units"] == r["terms"]["budget"] == payment["beneficiary_credit"] == payment["gross_escrow_debit"]
            and n["actual_consumer_use_verified"] is False and n["learning_improvement_bonus"] is False and
            n["chainwork_awarded"] == 0, "native development fee or scope mismatch")
    verified = dict(task=n["task"], output=output, result=evidence, measurement_receipt=charge,
                    payment_operation=payment["operation"], development_units=payment["beneficiary_credit"],
                    checked_evaluation_files=len(files), cost_scope=cost_scope)
    if not historical:
        verified["paired_performance"] = paired_performance(job, a, submitted, read(job / "evaluation/RESULT.json"))
    return verified


def public_verification_summary(job, *, expected_release=None):
    """Verify all retained material, then expose only the public CLI contract.

    ``verify`` remains the internal ledger readback API. Its payment identifiers,
    amount, receipt commitments and nested evidence must not enter console logs.
    New internal fields do not automatically become public output fields.
    """
    verified = verify(job, expected_release=expected_release)
    return dict(schema="trnm.development-evaluation-public-summary.v1",
                status="VERIFIED", scope="archived_development_evaluation",
                evaluation_mode="paired" if "paired_performance" in verified else "historical",
                checked_evaluation_files=verified["checked_evaluation_files"],
                native_development_fee_verified=True,
                actual_consumer_use_verified=False, learning_improvement_bonus=False,
                settlement_authorized=False, consensus_credit_authorized=False)


if __name__ == "__main__":
    if len(sys.argv) in (3, 4) and sys.argv[1] == "verify":
        expected = sys.argv[3] if len(sys.argv) == 4 else None
        print(json.dumps(public_verification_summary(Path(sys.argv[2]).resolve(strict=True),
                                                   expected_release=expected), sort_keys=True))
        sys.exit(0)
    mode, job_path, material_path, *extra = sys.argv[1:]
    job, materials = Path(job_path).resolve(strict=True), Path(material_path).resolve(strict=True)
    if mode == "prepare":
        source, freeze, request, candidate = extra
        prepare(job, materials, Path(source).resolve(strict=True), dict(freeze=freeze, request=request, candidate=candidate))
    elif mode == "execute" and not extra:
        execute(job, materials)
    else:
        raise ValueError("expected prepare or execute")
