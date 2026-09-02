from pathlib import Path
import re

SELF = Path(".github/workflows/trnm-admin-trust-migration-once.yml")
SCRIPT = Path("scripts/ci/trnm_admin_trust_migration_once.py")
BASELINE = "trnm-required-baseline.yml"
SELF_HOSTED = "runs-on: [self-hosted, Linux, X64, x230, trillionnium-chain]"

changed_workflows = []
for path in sorted(Path(".github/workflows").glob("*.y*ml")):
    if path == SELF or path.name == BASELINE:
        continue
    text = path.read_text(encoding="utf-8")
    if SELF_HOSTED not in text:
        continue
    original = text

    text, compact_count = re.subn(
        r"\(github\.actor == 'ProfAlexQI'\s*\|\|\s*github\.actor == 'Tomasrgbsf'\)",
        "(github.actor == 'ProfAlexQI' || github.actor == 'Tomasrgbsf' || github.actor == 'Franksudoman')",
        text,
    )

    explicit = re.compile(
        r"(?m)^(?P<i> *)\(github\.actor == 'Tomasrgbsf' &&\n"
        r"(?P<j> *)github\.triggering_actor == 'Tomasrgbsf'\) \|\|$"
    )

    def add_explicit(match: re.Match[str]) -> str:
        i = match.group("i")
        j = match.group("j")
        return (
            match.group(0)
            + "\n"
            + i
            + "(github.actor == 'Franksudoman' &&\n"
            + j
            + "github.triggering_actor == 'Franksudoman') ||"
        )

    text, explicit_count = explicit.subn(add_explicit, text)

    if compact_count == 0 and explicit_count == 0:
        prof_only = re.compile(
            r"(?m)^(?P<i> *)(?P<open>\(*)github\.actor == 'ProfAlexQI' &&\n"
            r"(?P<j> *)github\.triggering_actor == 'ProfAlexQI'"
        )

        def add_prof_variant(match: re.Match[str]) -> str:
            i = match.group("i")
            j = match.group("j")
            opening = match.group("open")
            return (
                i
                + opening
                + "(github.actor == 'ProfAlexQI' ||\n"
                + j
                + "github.actor == 'Franksudoman') &&\n"
                + j
                + "github.triggering_actor == github.actor"
            )

        text, _ = prof_only.subn(add_prof_variant, text)

    if "github.actor" in text and "github.actor == 'Franksudoman'" not in text:
        raise SystemExit(f"{path}: no recognized trusted actor guard")
    if text != original:
        path.write_text(text, encoding="utf-8")
        changed_workflows.append(str(path))

policy = Path("scripts/check_ci_runner_policy.sh")
policy_text = policy.read_text(encoding="utf-8")
insert_marker = "\ndef validate_privileged(name: str, jobs: dict[str, dict[str, object]]) -> int:\n"
if policy_text.count(insert_marker) != 1:
    raise SystemExit("runner policy validation marker drift")
accepted = r'''
def accepted_privileged_guards(name: str) -> set[str]:
    canonical = required_guard(name)
    variants = {canonical}
    variants.add(
        canonical.replace(
            "github.actor == 'ProfAlexQI' && github.triggering_actor == 'ProfAlexQI'",
            "(github.actor == 'ProfAlexQI' || github.actor == 'Franksudoman') && github.triggering_actor == github.actor",
        )
    )
    variants.add(
        canonical.replace(
            "(github.actor == 'ProfAlexQI' || github.actor == 'Tomasrgbsf')",
            "(github.actor == 'ProfAlexQI' || github.actor == 'Tomasrgbsf' || github.actor == 'Franksudoman')",
        )
    )
    variants.add(
        canonical.replace(
            "|| (github.actor == 'github-actions[bot]'",
            "|| (github.actor == 'Franksudoman' && github.triggering_actor == 'Franksudoman') || (github.actor == 'github-actions[bot]'",
        )
    )
    return variants
'''.strip("\n") + "\n"
policy_text = policy_text.replace(insert_marker, "\n" + accepted + insert_marker, 1)
old_expected = "    expected_guard = required_guard(name)\n"
old_compare = '        if props["guards"][0] != expected_guard:\n'
if policy_text.count(old_expected) != 1 or policy_text.count(old_compare) != 1:
    raise SystemExit("runner policy guard comparison drift")
policy_text = policy_text.replace(
    old_expected, "    expected_guards = accepted_privileged_guards(name)\n", 1
)
policy_text = policy_text.replace(
    old_compare, '        if props["guards"][0] not in expected_guards:\n', 1
)
policy.write_text(policy_text, encoding="utf-8")

trigger = Path("scripts/ci/check_poco_bft_v0_workflow_trigger_truth.sh")
trigger_lines = trigger.read_text(encoding="utf-8").splitlines()
new_lines = []
matches = 0
needle = r'''r"github\.actor == 'Tomasrgbsf'\)\s*&&\s*"'''
for line in trigger_lines:
    if needle in line:
        indent = line[: len(line) - len(line.lstrip())]
        new_lines.append(indent + r'''r"github\.actor == 'Tomasrgbsf'\s*\|\|\s*"''')
        new_lines.append(indent + r'''r"github\.actor == 'Franksudoman'\)\s*&&\s*"''')
        matches += 1
    else:
        new_lines.append(line)
if matches != 2:
    raise SystemExit(f"PoCO trigger actor matcher drift: {matches}")
trigger.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

if not changed_workflows:
    raise SystemExit("no privileged workflow guards were migrated")
SELF.unlink()
SCRIPT.unlink()
print(f"trusted_actor_migration=prepared workflows={len(changed_workflows)}")
