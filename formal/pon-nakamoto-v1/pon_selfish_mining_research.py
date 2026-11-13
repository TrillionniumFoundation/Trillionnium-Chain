"""Non-activated two-miner withholding/source-outage PoN sensitivity toy.

No W1 proof, signatures, transport, DAA, actual timestamps or consensus authority.
One discovery is an assumed valid *equal-work* block. Selfish mining uses an
instantaneous idealized tie settlement (gamma), not actual network propagation.
Unpublished/losing work is never counted as accepted public chainwork.
"""
from dataclasses import dataclass, asdict
from pathlib import Path
import argparse, hashlib, json, math, random

SCHEMA = 'trnm-pon-withholding-outage-research-v1'

@dataclass(frozen=True)
class Settings:
    seed: int = 20261026
    discoveries: int = 20000
    outage_at: int = 10000
    attacker_share: float = .30
    attacker_maintenance: float = .85
    honest_maintenance: float = .35
    attacker_legal_speedup: float = 1.0
    gamma: float = .5

    def validate(self):
        if type(self.seed) is not int or not 0 <= self.seed < 2**64:
            raise ValueError('SEED')
        if type(self.discoveries) is not int or not 1 <= self.discoveries <= 100000:
            raise ValueError('DISCOVERIES')
        if type(self.outage_at) is not int or not 0 <= self.outage_at <= self.discoveries:
            raise ValueError('OUTAGE')
        for name, value, lo, hi in (
            ('SHARE', self.attacker_share, 0, 1),
            ('ATTACKER_MAINTENANCE', self.attacker_maintenance, 0, 1),
            ('HONEST_MAINTENANCE', self.honest_maintenance, 0, 1),
            ('SPEEDUP', self.attacker_legal_speedup, 1, 64),
            ('GAMMA', self.gamma, 0, 1),
        ):
            if type(value) not in (int,float) or not math.isfinite(value) or not lo <= value <= hi:
                raise ValueError(name)

def capacities(p, event):
    h, a = 1 - p.attacker_share, p.attacker_share * p.attacker_legal_speedup
    if event >= p.outage_at:
        h *= p.honest_maintenance
        a *= p.attacker_maintenance
    return h, a

def effective_attacker_share(p, event):
    p.validate()
    h, a = capacities(p,event)
    return a/(a+h) if a+h else None

def simulate(p=Settings()):
    p.validate()
    rng = random.Random(p.seed)
    fh=fa=ah=aa=oh=oa=lead=ties=max_lead=0
    race = False
    terminal = None
    completed = 0
    for event in range(p.discoveries):
        h,a=capacities(p,event)
        if a+h == 0:
            terminal='no_available_work_capacity'
            break
        attacker = rng.random() * (a+h) < a
        completed+=1
        if attacker: fa+=1
        else: fh+=1
        if race:
            # One attacker sibling and one honest sibling are pending.
            if attacker: aa+=2; oh+=1
            elif rng.random() < p.gamma: aa+=1; ah+=1; oh+=1
            else: ah+=2; oa+=1
            race=False
            continue
        if attacker:
            lead+=1
            max_lead=max(max_lead,lead)
        elif lead==0: ah+=1
        elif lead==1: lead=0; race=True; ties+=1
        elif lead==2: aa+=2; oh+=1; lead=0
        else: aa+=1; oh+=1; lead-=1
    pending=2 if race else lead
    public=ah+aa
    assert fh+fa==completed==public+oh+oa+pending
    return dict(schema=SCHEMA, settings=asdict(p), discoveries=completed,
        honest_discoveries=fh, attacker_discoveries=fa,
        public_honest=ah, public_attacker=aa, orphan_honest=oh,
        orphan_attacker=oa, unpublished=pending, private_lead=lead,
        unresolved_race=race, ties=ties, max_private_lead=max_lead,
        accepted_public_blocks=public,
        public_growth_fraction=public/completed if completed else None,
        unpublished_fraction=pending/completed if completed else None,
        attacker_fraction_of_accepted=aa/public if public else None,
        source_outage_reached=(completed>p.outage_at or terminal=='no_available_work_capacity'),
        terminal_reason=terminal,
        pre_outage_effective_share=effective_attacker_share(p,0),
        post_outage_effective_share=effective_attacker_share(p,p.outage_at),
        conservation_pass=True, actual_w1_proofs=0, actual_daa_steps=0,
        actual_wan_transmissions=0, independent_operators=0,
        work_security_qualified=False, production_activated=False)

def campaign():
    rows=[]
    for seed in (0,1,20261026):
        for speed in (1.,1.5,3.):
            for gamma in (0.,.5,1.):
                for outage in (False,True):
                    rows.append(simulate(Settings(seed=seed, discoveries=8000,
                        outage_at=4000 if outage else 8000,
                        attacker_legal_speedup=speed, gamma=gamma)))
    raw=json.dumps(rows, sort_keys=True, separators=(',', ':'), allow_nan=False)
    return dict(schema='trnm-pon-withholding-outage-campaign-v1',
                cases=len(rows), cases_sha256=hashlib.sha256(raw.encode()).hexdigest(),
                rows=rows, qualification=dict(real_w1=False, real_daa=False,
                    independent_operator=False, permissionless_security=False))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args=parser.parse_args()
    report=campaign()
    with args.output.open('x',encoding='utf8') as f:
        json.dump(report,f,sort_keys=True,indent=2,allow_nan=False)
        f.write('\n')
    print(json.dumps({k:report[k] for k in ('schema','cases','cases_sha256')}))
