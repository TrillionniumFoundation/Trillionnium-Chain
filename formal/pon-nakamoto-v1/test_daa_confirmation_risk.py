"""Negative controls: depth-only is not the installed PoN client policy."""
import unittest
from dataclasses import dataclass
from daa_confirmation_risk import fork_risk, required_work, RiskError

@dataclass(frozen=True)
class Row:
    key: int
    parent: int | None
    height: int
    target: int
    chainwork: int


def extend(rows, parent_key, target, new_key):
    p=rows[parent_key]
    h=Row(new_key,parent_key,p.height+1,target,
          p.chainwork+required_work(target))
    rows[new_key]=h
    return new_key


def fixtures():
    high=(1<<255)-1
    rows={0:Row(0,None,0,high,0)}
    # Losing branch has a hard block 1, followed by six very easy blocks.
    # Its early block meets depth six, but not six of ITS OWN work units.
    loser=extend(rows,0,1,1)
    for i in range(2,8):loser=extend(rows,loser,high,i)
    winner=0
    for i in range(101,105):winner=extend(rows,winner,1,i)
    return rows,winner,loser


class RiskControls(unittest.TestCase):
    def test_six_blocks_not_six_units_of_inclusion_work(self):
        rows,winner,loser=fixtures()
        x=fork_risk(rows,winner,loser)
        self.assertEqual(x.depth_only_removed,1)
        self.assertEqual(x.depth_and_work_confirmed_removed,0)
        self.assertEqual(x.depth_satisfied_work_insufficient,1)
        self.assertEqual(x.losing_blocks,7)

    def test_constant_target_meets_both_installed_predicates(self):
        high=(1<<255)-1
        rows={0:Row(0,None,0,high,0)}
        loser=0
        for i in range(1,9):loser=extend(rows,loser,high,i)
        winner=0
        for i in range(101,111):winner=extend(rows,winner,high,i)
        risk=fork_risk(rows,winner,loser)
        self.assertEqual(risk.depth_only_removed,2)
        self.assertEqual(risk.depth_and_work_confirmed_removed,2)
        self.assertEqual(risk.depth_satisfied_work_insufficient,0)

    def test_shared_prefix_is_not_orphaned(self):
        high=(1<<255)-1
        rows={0:Row(0,None,0,high,0)}
        shared=extend(rows,0,high,1)
        shared=extend(rows,shared,high,2)
        loser=shared;winner=shared
        for i in range(3,12):loser=extend(rows,loser,high,i)
        for i in range(100,110):winner=extend(rows,winner,high,i)
        out=fork_risk(rows,winner,loser)
        self.assertEqual(out.losing_blocks,9)
        self.assertEqual(out.depth_only_removed,3)
        self.assertEqual(out.depth_and_work_confirmed_removed,3)

    def test_bad_work_and_bad_ancestry_fail_closed(self):
        rows,winner,loser=fixtures()
        for damaged in (Row(2,1,2,(1<<255)-1,0),
                        Row(2,500,2,(1<<255)-1,0)):
            copy=dict(rows);copy[2]=damaged
            with self.assertRaises(RiskError):fork_risk(copy,winner,loser)
        with self.assertRaisesRegex(RiskError,'NOT_HEAVIER'):
            fork_risk(rows,loser,winner)
        with self.assertRaisesRegex(RiskError,'ANCESTRY_BUDGET'):
            fork_risk(rows,winner,loser,max_reads=2)
        with self.assertRaises(RiskError):required_work(0)
        with self.assertRaises(RiskError):fork_risk(rows,winner,loser,multiplier=0)

    def test_zero_reorg_when_same_tip(self):
        rows,winner,_=fixtures()
        out=fork_risk(rows,winner,winner)
        self.assertEqual(out.losing_blocks,0)
        self.assertEqual(out.depth_and_work_confirmed_removed,0)


if __name__=='__main__':unittest.main(verbosity=2)
