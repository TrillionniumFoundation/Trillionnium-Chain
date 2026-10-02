"""Small, independent fixtures for source-binding tests, not evidence replay.

Copy all source and the exact declared evidence metadata. Artifact bodies are not
inputs to validate_contract/check_invariants/check_applicability; campaign tests
keep their own complete evidence fixtures and are deliberately not routed here.
"""
import json
import shutil
from pathlib import Path


def copy_source_bindings(root: Path, destination: Path) -> None:
    def ignore(directory, names):
        excluded = {'.git', 'target', '__pycache__', '.pytest_cache', 'node_modules'}
        if Path(directory) == root:
            excluded.add('evidence')
        return excluded.intersection(names)

    shutil.copytree(root, destination, ignore=ignore)
    maturity = json.loads((root / 'config/pon/module-maturity-v1.json').read_text())
    for package in maturity['evidence_packages'].values():
        manifest = Path(package['manifest'])
        paths = [manifest]
        if package['qualification'] is not None:
            paths.append(manifest.parent / package['qualification'])
        for relative in paths:
            if relative.is_absolute() or '..' in relative.parts:
                raise ValueError('noncanonical evidence metadata: ' + str(relative))
            source = (root / relative).resolve()
            if not source.is_relative_to(root.resolve()) or not source.is_file():
                raise ValueError('missing/escaping evidence metadata: ' + str(relative))
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
