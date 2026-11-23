"""Prepare and execute the paired Circuit evaluation used by the isolated native ledger test."""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import resource
import secrets
import shutil
import subprocess
import sys
import time


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


def check_inputs(materials, pins, *, request_path=None, circuit=True):
    frozen = read(materials / "FROZEN.json")
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


def prepare(job, materials, source, pins, *, intake=None, request_path=None):
    import dev_intake_evaluation as plain

    request_path = request_path or materials / "paired.json"
    request = check_inputs(materials, pins, request_path=request_path, circuit=intake is None)
    if intake is not None:
        require(len(request["future"]) == 1, "single release requires one future record")
        retained = job / "PAIRED_INPUT.json"
        record(retained, request)
        request_path = retained
    with (job / "FROZEN.json").open("xb") as handle:
        handle.write((materials / "FROZEN.json").read_bytes())
    # A private copy fixes the Python source used by both workers, even if the source checkout changes.
    original = source / "scripts" / "cell_experiments"
    entries = source_files(original)
    snapshot = job / "runtime" / "cell_experiments"
    for entry in entries:
        target = snapshot / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original / entry["path"], target)
    require(entries == source_files(snapshot), "source snapshot changed while copying")
    listing = entries if intake is None else dict(package=entries, catalog=plain.catalog_snapshot(job, source, pins["freeze"]))
    source_hash = record(job / "SOURCE.json", listing)
    terms = dict(schema="trnm-isolated-circuit-evaluation-request-v1", job_id=secrets.token_hex(16),
                 pins=pins, parent=digest(request["parent"]), source_listing_sha256=source_hash,
                 freeze_file_sha256=sha((materials / "FROZEN.json").read_bytes()),
                 request_file_sha256=sha(request_path.read_bytes()),
                 runtime=dict(python=sys.version.split()[0],
                              packages={n: importlib.metadata.version(n) for n in ("torch", "transformers", "peft")}),
                 cpu_limit_ns=1_000_000_000_000, evaluated_examples=2 * (len(request["future"]) + len(request["retention"])),
                 output_schema="trnm-isolated-circuit-evaluation-delivery-v1")
    if intake is not None:
        plain.preflight(job, materials, pins["request"])
        terms.update(schema=plain.ADMISSION, output_schema=plain.DELIVERY, job_id=intake["admission_sha256"],
                     intake_release=intake, intake_release_sha256=digest(intake))
    record(job / "ADMISSION.json", terms)


def measure(job, command, env):
    cpu0, start = resource.getrusage(resource.RUSAGE_CHILDREN), time.monotonic_ns()
    with (job / "evaluation.stdout").open("xb") as stdout, (job / "evaluation.stderr").open("xb") as stderr:
        subprocess.run(command, check=True, cwd=job, env=env, stdout=stdout, stderr=stderr)
    wall_ns = time.monotonic_ns() - start
    cpu1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu_ns = round(((cpu1.ru_utime - cpu0.ru_utime) + (cpu1.ru_stime - cpu0.ru_stime)) * 1_000_000_000)
    return cpu_ns, wall_ns


def execute(job, materials):
    import dev_intake_evaluation as plain

    terms = read(job / "ADMISSION.json")
    reservation = read(job / "RESERVATION.json")
    require(reservation["request"] == sha((job / "ADMISSION.json").read_bytes()), "reservation request mismatch")
    plain_model = terms["schema"] == plain.ADMISSION
    request_path = job / "PAIRED_INPUT.json" if plain_model else materials / "paired.json"
    request = check_inputs(materials, terms["pins"], request_path=request_path, circuit=not plain_model)
    listing = read(job / "SOURCE.json")
    if plain_model:
        require(sha(request_path.read_bytes()) == terms["request_file_sha256"], "original paired request bytes differ")
        plain.check_release(terms["intake_release"], terms["intake_release_sha256"], terms["pins"])
        plain.check_catalog(job, listing["catalog"], terms["pins"]["freeze"])
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
    require(check_inputs(materials, terms["pins"], request_path=request_path, circuit=not plain_model) == request, "input changed after execution")
    result = read(output / "RESULT.json")
    if plain_model:
        plain.check_catalog(job, listing["catalog"], terms["pins"]["freeze"])
        plain.check_plain_result(result, terms)
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
    cost = dict(schema="trnm-isolated-circuit-evaluation-cost-v1", evaluated_examples=evaluated,
                cpu_ns=cpu_ns, cpu_scope="getrusage waited child process group and reaped descendants",
                wall_ns=wall_ns)
    if plain_model:
        cost.update(schema="trnm-isolated-plain-paired-evaluation-cost-v1")
    else:
        cost["circuit_work"] = result["measured_circuit_work"]
    cost_hash = record(job / "COST.json", cost)
    files = {p.relative_to(output).as_posix(): sha(p.read_bytes()) for p in sorted(output.rglob("*")) if p.is_file()}
    record(job / "DELIVERY.json", dict(schema=terms["output_schema"], request=reservation["request"],
        task=reservation["task"], reservation_sha256=sha((job / "RESERVATION.json").read_bytes()),
        model=terms["pins"]["candidate"], paired_request=terms["pins"]["request"], result_sha256=files["RESULT.json"],
        cost_sha256=cost_hash, raw_evaluation_files=files))


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
    historical = a["schema"] == "trnm-isolated-historical-evaluation-request-v1"
    if expected_release is not None:
        require(a["schema"] == plain.ADMISSION and a["intake_release_sha256"] == expected_release,
                "independently retained release differs")
    if a["schema"] == plain.ADMISSION:
        spec, input_key = plain.DELIVERY, "paired_request"
        retained = job / "PAIRED_INPUT.json"
        require(sha(retained.read_bytes()) == a["request_file_sha256"] and
                digest(read(retained)) == a["pins"]["request"], "original paired request bytes differ")
        plain.check_release(a["intake_release"], a["intake_release_sha256"], a["pins"])
        plain.check_catalog(job, read(job / "SOURCE.json")["catalog"], a["pins"]["freeze"])
        plain.check_plain_result(read(job / "evaluation/RESULT.json"), a)
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
    return dict(task=n["task"], output=output, result=evidence, measurement_receipt=charge,
                payment_operation=payment["operation"], development_units=payment["beneficiary_credit"],
                checked_evaluation_files=len(files))


if __name__ == "__main__":
    if len(sys.argv) in (3, 4) and sys.argv[1] == "verify":
        expected = sys.argv[3] if len(sys.argv) == 4 else None
        print(json.dumps(verify(Path(sys.argv[2]).resolve(strict=True), expected_release=expected), sort_keys=True))
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
