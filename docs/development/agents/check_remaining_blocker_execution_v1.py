#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MATRIX = ROOT / 'docs/development/agents/REMAINING_BLOCKER_EXECUTION_MATRIX_V1.json'
REVIEW = ROOT / 'docs/development/agents/INDEPENDENT_PACKAGE_REVIEW_DECISION_V1.json'
MATRIX_DOC = ROOT / 'docs/development/agents/REMAINING_BLOCKER_EXECUTION_MATRIX_V1.md'
REVIEW_DOC = ROOT / 'docs/development/agents/INDEPENDENT_PACKAGE_REVIEW_PROTOCOL_V1.md'


def load_unique(path: Path) -> object:
    def pairs(rows: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in rows:
            if key in value:
                raise ValueError(f'duplicate-key:{path}:{key}')
            value[key] = item
        return value
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=pairs)


def main() -> int:
    matrix = load_unique(MATRIX)
    review = load_unique(REVIEW)
    assert MATRIX_DOC.is_file()
    assert REVIEW_DOC.is_file()

    assert matrix['schema'] == 'trnm-remaining-blocker-execution-matrix-v1'
    assert matrix['classification'] == 'candidate-non-normative'
    assert matrix['owner'] == 'A00'
    assert matrix['package_id'] == 'AGENT_CONTROL_PLANE_V1'
    assert matrix['status'] == 'BLOCKED_UPSTREAM'
    truth = matrix['global_truth']
    for key, value in truth.items():
        assert value is False, key
    rules = matrix['evidence_rules']
    assert rules['exact_head_completed_success_required'] is True
    for key, value in rules.items():
        if key != 'exact_head_completed_success_required':
            assert value is False, key
    blockers = matrix['blockers']
    expected = {
        'EXT-REVIEW-001', 'EXT-G1-CAMPAIGN-001', 'EXT-ANCHOR-HSM-001',
        'EXT-POWERLOSS-001', 'EXT-AUDIT-001', 'EXT-SOAK-ACTIVATION-001',
    }
    ids = [row['id'] for row in blockers]
    assert set(ids) == expected
    assert len(ids) == len(set(ids))
    for row in blockers:
        assert row['severity'] == 'P0'
        assert row['status'] == 'BLOCKED_UPSTREAM'
        assert row['owner'] in {'A00', 'A05', 'A06', 'A07', 'A17'}
        for key in ('required_inputs', 'required_outputs', 'acceptance', 'invalidation'):
            assert isinstance(row[key], list) and row[key], (row['id'], key)

    assert review['schema'] == 'trnm-independent-package-review-decision-v1'
    assert review['classification'] == 'candidate-non-normative'
    assert review['decision_id'] == 'UNASSIGNED'
    assert review['status'] == 'NOT_REVIEWED'
    assert review['replay']['exact_head_completed_success'] is False
    assert review['mutants']['all_p0_replayed'] is False
    for key, value in review['decision'].items():
        if key in {'reason', 'decision_root'}:
            assert value is None, key
        else:
            assert value is False, key
    assert review['signatures'] == []
    assert len(review['reopen_on']) >= 8
    assert len(review['notes']) >= 4
    print('remaining blocker and independent-review templates: fail-closed contract ok')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
