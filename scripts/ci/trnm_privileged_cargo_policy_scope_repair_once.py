from pathlib import Path

SCRIPT = Path("scripts/ci/trnm_privileged_cargo_policy_scope_repair_once.py")
POLICY = Path("scripts/check_privileged_cargo_offline_policy.sh")
text = POLICY.read_text(encoding="utf-8")


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"privileged Cargo policy marker drift: expected one, found {count}: {old[:100]!r}"
        )
    text = text.replace(old, new, 1)


expanded_roots = (
    "'trillionnium/Cargo.toml:trillionnium/Cargo.lock "
    "trillionnium/crates/trnm-consensus-app/Cargo.toml:"
    "trillionnium/crates/trnm-consensus-app/Cargo.lock "
    "trillionnium/crates/trnm-node/Cargo.toml:"
    "trillionnium/crates/trnm-node/Cargo.lock'"
)
replace_once(
    "register trnm-cometbft-spike.yml:cometbft-four-validator required 1.95.0 \\\n"
    "  trillionnium/Cargo.toml:trillionnium/Cargo.lock\n",
    "register trnm-cometbft-spike.yml:cometbft-four-validator required 1.95.0 \\\n"
    f"  {expanded_roots}\n",
)
replace_once(
    "register trnm-cometbft-spike.yml:cometbft-partition-matrix required 1.95.0 \\\n"
    "  trillionnium/Cargo.toml:trillionnium/Cargo.lock\n",
    "register trnm-cometbft-spike.yml:cometbft-partition-matrix required 1.95.0 \\\n"
    f"  {expanded_roots}\n",
)

replace_once(
    "mapfile -t workflows < <(list_workflows)\n",
    "# This checker freezes privileged/self-hosted and product-adjacent workflow\n"
    "# Cargo authority. Actor-independent GitHub-hosted truth workflows are\n"
    "# validated by their own exact-source gates and do not share the offline\n"
    "# runner cache authority.\n"
    "mapfile -t workflows < <(\n"
    "  list_workflows | grep -Ev '^trnm-(required-baseline|documentation-truth)\\.ya?ml$'\n"
    ")\n",
)

POLICY.write_text(text, encoding="utf-8")
SCRIPT.unlink()
print("privileged_cargo_policy_scope_repair=prepared")
