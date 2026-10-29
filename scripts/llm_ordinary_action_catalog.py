"""Query-independent ordinary catalogue/configuration producer; no authority.

Freeze the complete action map before candidate profile/evaluation. The hash is
content identity, not an independent timestamp or acceptance receipt. The real
Hepta selector/CURRENT owner must admit that exact profile before model loading.
"""
import json
from pathlib import Path
import re

import llm_cell_release as release

SCHEMA = "hepta-smollm-ordinary-memory-action-catalog-v1"
CONTENT_SCHEMA = "hepta-smollm-ordinary-cell-content-v2"
CONTENT_SCOPE = "qualified-host-preregistered-catalog-content-only"
MAXIMUM = release.MAX_SIDECAR


def canonical(value):
    # Match serde_json UTF-8 for the existing executable-profile commitment.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def catalog(value):
    if (type(value) is not dict or set(value) != {"schema", "records"} or value["schema"] != SCHEMA
            or type(value["records"]) is not list or not 1 <= len(value["records"]) <= 128):
        raise ValueError("ordinary catalogue schema/count")
    records, ids, labels = [], set(), set()
    for row in value["records"]:
        if (type(row) is not dict or set(row) != {"memory_id", "revision", "content_sha256", "completion"}
                or type(row["memory_id"]) is not str or re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", row["memory_id"]) is None
                or type(row["revision"]) is not int or not 1 <= row["revision"] < 1 << 64
                or not sha256(row["content_sha256"]) or row["content_sha256"] == "0" * 64
                or type(row["completion"]) is not str or not 1 <= len(row["completion"].encode()) <= 64):
            raise ValueError("ordinary catalogue record")
        memory = row["memory_id"].encode()
        # Exact cognitive_action_id commitment, not a caller-provided action ID.
        action = "memory-" + release.digest(len(memory).to_bytes(8, "big") + memory
            + row["revision"].to_bytes(8, "big") + row["content_sha256"].encode("ascii"))
        if action in ids or row["completion"] in labels:
            raise ValueError("ordinary catalogue duplicate action/label")
        ids.add(action)
        labels.add(row["completion"])
        records.append((action, row))
    records.sort(key=lambda item: item[0])
    fixed = dict(schema=SCHEMA, records=[row for _, row in records])
    actions = [dict(action_id=action, completion=row["completion"]) for action, row in records]
    if len(canonical(fixed)) > MAXIMUM:
        raise ValueError("ordinary catalogue byte bound")
    return fixed, actions


def pinned(path, expected, maximum=MAXIMUM):
    if (not path.is_absolute() or path.resolve(strict=True) != path or not sha256(expected)):
        raise ValueError("ordinary catalogue requires canonical pinned input")
    raw = release.read_regular(path, maximum)
    if release.digest(raw) != expected:
        raise ValueError("ordinary catalogue input digest mismatch")
    return raw


def new_directory(path):
    if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
        raise ValueError("ordinary catalogue output requires a canonical parent")
    path.mkdir(mode=0o700)


def freeze_catalog(args):
    if not args.catalog_input.is_absolute() or args.catalog_input.resolve(strict=True) != args.catalog_input:
        raise ValueError("ordinary catalogue input path")
    value = json.loads(release.read_regular(args.catalog_input, MAXIMUM), object_pairs_hook=release.runtime.unique)
    fixed, _ = catalog(value)
    raw = canonical(fixed)
    new_directory(args.output)
    path = args.output / "ordinary-memory-action-catalog-v1.json"
    release._write_protected_new(path, raw)
    digest = release.digest(raw)
    release._write_protected_new(args.output / "catalog-sha256.txt", (digest + "\n").encode("ascii"))
    return dict(path=str(path), sha256=digest, bytes=len(raw),
                scope="fixed-profile-input-only-no-chronology-evaluation-install-or-use-authority")


def prepare_ordinary_host_config_v3(args):
    raw_catalog = pinned(args.catalog, args.catalog_sha256)
    fixed, actions = catalog(json.loads(raw_catalog, object_pairs_hook=release.runtime.unique))
    if canonical(fixed) != raw_catalog:
        raise ValueError("ordinary catalogue must be the frozen canonical input")
    sidecar = json.loads(pinned(args.sidecar, args.sidecar_sha256), object_pairs_hook=release.runtime.unique)
    host = json.loads(pinned(args.host_config, args.host_config_sha256), object_pairs_hook=release.runtime.unique)
    fields = set("schema scope profile operation_id generation family_id family_file_sha256 model revision "
        "artifact_sha256 adapter_digest contract_digest backbone_digest tokenizer_digest "
        "execution_profile_sha256 sources actions tcr1_hex tcr1_id members".split())
    if (type(sidecar) is not dict or set(sidecar) != fields or sidecar["schema"] != release.SCHEMA
            or sidecar["scope"] != "controlled-native-load-only" or sidecar["profile"] != release.PROFILE
            or sidecar["actions"] != release.ACTIONS or type(sidecar["members"]) is not list
            or [m["name"] for m in sidecar["members"]] != release.ROSTER
            or type(host) is not dict or host.get("schema") != "hepta-smollm-cognitive-host-v1"):
        raise ValueError("ordinary catalogue requires original byte declarations/host")
    operation = sidecar["operation_id"]
    if type(operation) is not str or not 1 <= len(operation) <= 128 or not all(33 <= ord(c) <= 126 for c in operation):
        raise ValueError("ordinary catalogue operation identity")
    if set(host) != set("schema descriptor worker worker_id resource_grant inference_journal inference_journal_capacity final_use_authorizer_config".split()):
        raise ValueError("ordinary catalogue host fields")
    worker = host["worker"]
    if (type(worker) is not dict or set(worker) != set("python script materials run_directory source_pins target_contract wrapped_adapter contract_digest adapter_digest backbone_digest tokenizer_digest action_completions".split())
            or type(worker["source_pins"]) is not dict):
        raise ValueError("ordinary catalogue worker fields")
    if worker["action_completions"] != {a["action_id"]: a["completion"] for a in actions}:
        raise ValueError("ordinary catalogue differs from independently pinned host action map")
    sources = {}
    for name, expected in worker["source_pins"].items():
        path = Path(name)
        if path.name in sources:
            raise ValueError("ordinary catalogue duplicate source basename")
        pinned(path, expected, 2 * 1024 * 1024)
        sources[path.name] = expected
    sources = dict(sorted(sources.items()))
    if (set(sources) != {Path(name).name for name in release.SOURCE_PATHS}
            or sidecar["sources"] != [dict(name=k, sha256=v) for k, v in sources.items()]):
        raise ValueError("ordinary catalogue executable source pins")
    for field in ("contract_digest", "adapter_digest", "backbone_digest", "tokenizer_digest"):
        if not sha256(worker[field]) or worker[field] != sidecar[field]:
            raise ValueError("ordinary catalogue actual model contract differs")
    target = worker["target_contract"]
    wrapped = worker["wrapped_adapter"]
    if any(type(value) is not dict or set(value) != {"path", "sha256"} for value in (target, wrapped)):
        raise ValueError("ordinary catalogue contract file fields")
    target_raw = pinned(Path(target["path"]), target["sha256"], 1024 * 1024)
    wrapped_raw = pinned(Path(wrapped["path"]), wrapped["sha256"], 1024 * 1024)
    execution = ["hepta-smollm-single-token-action-score-v1", sources, actions,
        worker["contract_digest"], worker["adapter_digest"], release.digest(target_raw), release.digest(wrapped_raw),
        worker["backbone_digest"], worker["tokenizer_digest"], 4]
    profile = release.digest(canonical(execution))
    # Only ordinary content is produced. The input controlled declaration/native
    # receipt is neither modified nor promoted into product-use authority.
    content = canonical(dict(sidecar, schema=CONTENT_SCHEMA, scope=CONTENT_SCOPE,
        actions=actions, execution_profile_sha256=profile))
    if len(content) > MAXIMUM:
        raise ValueError("ordinary catalogue content bound")
    new_directory(args.output)
    path = args.output / "ordinary-cell-content-v2.json"
    release._write_protected_new(path, content)
    config = canonical(dict(schema="hepta-smollm-cognitive-cell-host-v3",
        host=dict(path=str(args.host_config), sha256=args.host_config_sha256),
        cell_content=dict(path=str(path), sha256=release.digest(content)),
        action_catalog=dict(path=str(args.catalog), sha256=args.catalog_sha256), operation_id=operation))
    if len(config) > MAXIMUM:
        raise ValueError("ordinary catalogue host bound")
    host_path = args.output / "ordinary-cell-host-v3.json"
    release._write_protected_new(host_path, config)
    return dict(path=str(host_path), sha256=release.digest(config), bytes=len(config),
        execution_profile_sha256=profile, catalog_sha256=args.catalog_sha256,
        scope="configuration-and-content-only-no-qualification-or-installation")
