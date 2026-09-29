"""Preregistered strongest-control, cluster-level evaluation. No synthetic future acceptance."""
from __future__ import annotations
from fractions import Fraction
import math
from contract_wire import canonical,H

CONTROL_ORDER=('current','best_single','mean_merge','pooled')

def select_reference(calibration,controls):
    if set(controls)!=set(CONTROL_ORDER):raise ValueError('CONTROL_SET')
    labels=[r['label']for r in calibration]
    if not labels or any(len(v)!=len(labels)for v in controls.values()):raise ValueError('CALIBRATION')
    # Stable tie rule is declared before observations; data are calibration-only.
    scored={name:sum(a==b for a,b in zip(pred,labels))for name,pred in controls.items()}
    name=max(CONTROL_ORDER,key=lambda k:(scored[k],-CONTROL_ORDER.index(k)))
    return name,H('reference-lock',canonical({'tasks':calibration,'controls':controls,'selected':name})).hex()

def assess(rows,candidate,reference,*,comparisons=4,minimum_clusters=20,future_window=False):
    if type(comparisons)is not int or comparisons<1:raise ValueError('MULTIPLICITY')
    if len(rows)!=len(candidate)or len(rows)!=len(reference):raise ValueError('SAMPLE_ALIGNMENT')
    groups={};seen=set()
    for r,a,b in zip(rows,candidate,reference):
        if r['id']in seen:raise ValueError('DUPLICATE_TASK')
        seen.add(r['id']);key=r['source_group']
        if not isinstance(key,str)or not key:raise ValueError('SOURCE_GROUP')
        gain,count=groups.get(key,(0,0));groups[key]=(gain+int(a==r['label'])-int(b==r['label']),count+1)
    differences=[Fraction(g,n)for g,n in groups.values()]
    wins=sum(d>0 for d in differences);losses=sum(d<0 for d in differences);m=wins+losses
    enough=len(groups)>=minimum_clusters
    passes=bool(enough and wins>losses and 20*comparisons*sum(math.comb(m,k)for k in range(wins,m+1))<=1<<m)
    mean=sum(differences,Fraction(0))/len(differences)if differences else Fraction(0)
    # This local function cannot authenticate a future time or independent operators.
    return {'clusters':len(groups),'wins':wins,'losses':losses,'comparisons':comparisons,'cluster_gate':passes,'mean_gain_numerator':mean.numerator,'mean_gain_denominator':mean.denominator,'exploratory_score':max(0,int(mean*1000000))if passes else 0,'future_window_observed':bool(future_window),'public_reward_eligible':False,'reason':'independent time/source-owner receipts must be verified by the accepting owner'}

def freeze_plan(*,source,train_ids,calibration_ids,eligible_future_after,model_hash):
    if set(train_ids)&set(calibration_ids):raise ValueError('PARTITION_OVERLAP')
    if not source or not model_hash or type(eligible_future_after)is not int:raise ValueError('PLAN')
    return {'schema':'pon-strong-reference-plan-v2','source':source,'train_ids':sorted(train_ids),'calibration_ids':sorted(calibration_ids),'eligible_future_after':eligible_future_after,'candidate':model_hash,'controls':list(CONTROL_ORDER),'minimum_clusters':20,'comparisons':4,'statistical_unit':'authorized-source-group','adaptation_after_plan_forbidden':True}
