"""Simulation-only PoN confirmation risk, including *both* native policy guards.

Counts a losing branch's already policy-confirmed transactions/blocks before a
simulated heavier fork displaces that branch. This module NEVER authenticates
PNW1, actual transaction membership, node State, independent client receipts,
network timestamps or historical source authority. All inputs are assumed to
be already validated by an external test harness, not verified here.
"""
from dataclasses import dataclass

UINT256 = 1 << 256


class RiskError(ValueError):
    pass


def _integer(value, name, *, minimum=0, maximum=(1 << 512) - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise RiskError(name)
    return value


def required_work(target):
    _integer(target, 'TARGET', minimum=1, maximum=UINT256 - 1)
    return UINT256 // (target + 1)


def _path(rows, tip, max_reads):
    _integer(max_reads, 'READ_BUDGET', minimum=1, maximum=65536)
    _integer(tip, 'TIP', maximum=(1 << 64) - 1)
    ordered = []
    seen = set()
    cursor = tip
    for _ in range(max_reads):
        if cursor in seen: raise RiskError('CYCLE')
        seen.add(cursor)
        row = rows.get(cursor)
        if row is None: raise RiskError('MISSING_ANCESTRY')
        if row.key != cursor: raise RiskError('ROW_ID')
        _integer(row.height, 'HEIGHT', maximum=(1 << 64) - 1)
        _integer(row.chainwork, 'WORK')
        required_work(row.target)
        ordered.append(row)
        if row.parent is None:
            if row.height != 0 or row.chainwork != 0:
                raise RiskError('GENESIS')
            return ordered
        _integer(row.parent, 'PARENT', maximum=(1 << 64) - 1)
        parent = rows.get(row.parent)
        if parent is None: raise RiskError('MISSING_ANCESTRY')
        if row.height != parent.height + 1:
            raise RiskError('HEIGHT_LINK')
        if row.chainwork != parent.chainwork + required_work(row.target):
            raise RiskError('WORK_LINK')
        cursor = row.parent
    raise RiskError('ANCESTRY_BUDGET')


@dataclass(frozen=True)
class ForkRisk:
    loser_tip: int
    winner_tip: int
    losing_blocks: int
    depth_only_removed: int
    depth_and_work_confirmed_removed: int
    depth_satisfied_work_insufficient: int
    required_depth: int
    required_work_multiplier: int


def fork_risk(rows, winner_tip, loser_tip, *, depth=6, multiplier=6,
              max_reads=4096):
    """Recompute PoN depth+required-work from losing branch's *own* tip.

    A header with six newer descendants is NOT policy-confirmed until the
    *cumulative required work added after it* reaches 6 * its own required
    block work. The winning branch is evaluated only for ancestor exclusion;
    there is no claim that omitted transactions were in that block.
    """
    _integer(depth, 'DEPTH', minimum=1, maximum=4096)
    _integer(multiplier, 'WORK_MULTIPLIER', minimum=1, maximum=4096)
    winning=_path(rows,winner_tip,max_reads)
    losing=_path(rows,loser_tip,max_reads)
    if winning[-1].key!=losing[-1].key:
        raise RiskError('DIFFERENT_GENESIS')
    if winning[0].chainwork < losing[0].chainwork:
        raise RiskError('NOT_HEAVIER')
    active = {x.key for x in winning}
    orphaned = [x for x in losing if x.key not in active]
    losing_tip_row=losing[0]
    depth_only=0
    confirmed=0
    under_work=0
    for row in orphaned:
        distance=losing_tip_row.height - row.height
        if distance < depth:continue
        depth_only+=1
        earned=losing_tip_row.chainwork - row.chainwork
        needed=required_work(row.target)*multiplier
        if earned >= needed:confirmed+=1
        else:under_work+=1
    return ForkRisk(loser_tip,winner_tip,len(orphaned),depth_only,
                    confirmed,under_work,depth,multiplier)
