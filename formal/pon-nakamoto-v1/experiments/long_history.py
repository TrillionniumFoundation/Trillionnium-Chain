"""Real work-verified >4096 history and shallow fork; explicitly logical chain time.

Native work/application components may be selected explicitly. SQLite persists each
accepted block/delta; no fabricated chain rows substitute for this campaign.
"""
from __future__ import annotations
import argparse,json,os,resource,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ledger import *

def run(out,height):
    require(type(height)is int and 4106<=height<=10000,'CAMPAIGN_HEIGHT')
    out=Path(out);out.mkdir(parents=True,exist_ok=False);started=time.monotonic()
    ledger=Ledger(out/'chain');effects=EffectJournal(out/'effects.sqlite');tip=GENESIS;nonce=0;points=[];fork_parent=None;transactions=0
    logical_now=PARAMS['genesis_timestamp']+1000000
    try:
        for n in range(1,height+1):
            txs=[]
            if n==1 or n%512==0:
                nonce+=1;txs=[sign(key(0),nonce,'transfer',dict(recipient=public(key(1)),amount=1),expiry=height+1000)];transactions+=1
            header,body,proof=ledger.make(tip,txs)
            tip=ledger.admit(header,body,proof,logical_now);ledger.activate(tip)
            if n==height-7:fork_parent=tip
            if n%512==0 or n==height:
                point={'height':n,'elapsed_ns':int((time.monotonic()-started)*1e9),
                       'kv_rows':ledger.db.execute('SELECT count(*) FROM kv').fetchone()[0],
                       'state_slots':ledger.db.execute('SELECT count(DISTINCT generation) FROM kv').fetchone()[0],
                       'checkpoints':ledger.db.execute('SELECT count(*) FROM snapshots').fetchone()[0]}
                points.append(point);print(json.dumps(point),flush=True)
        op=H('long-history-local-effect');effects.enter(op,H('local-no-real-world-dispatch'),ledger.active()[1]);old_tip=tip
        assert fork_parent is not None
        recovered_parent=ledger.state_at(fork_parent);parent_root=state_root(recovered_parent)
        require(parent_root==ledger.block(fork_parent)[6],'SHALLOW_PARENT_ROOT')
        fork=fork_parent
        for _ in range(8):
            header,body,proof=ledger.make(fork,[],miner=public(key(2)),timestamp=ledger.ancestor_headers(fork)[0]['timestamp']+11)
            fork=ledger.admit(header,body,proof,logical_now)
        require(ledger.block(fork)[2]>ledger.block(old_tip)[2],'FORK_WORK')
        ledger.activate(fork);root=ledger.read_active()[2];root_digest=state_root(root).hex();ledger.close();ledger=None
        ledger=Ledger(out/'chain');require(ledger.recover()==fork and state_root(ledger.read_active()[2]).hex()==root_digest,'REOPEN_ROOT')
        try:effects.enter(op,H('local-no-real-world-dispatch'),ledger.active()[1]);raise AssertionError('effect replay accepted')
        except ValueError as error:require(str(error)=='OPERATION_ALREADY_ENTERED','EFFECT_REPLAY')
        report={'schema':'pon-actual-long-history-v3','canonical_height_before_fork':height,'fork_parent_height':height-7,'final_height':ledger.block(fork)[1],
                'actual_mined_and_verified_blocks':height+8,'signed_transfers':transactions,'used_inserted_history_fixtures':False,
                'native_work':bool(os.environ.get('TRNM_NATIVE_WORK')),'native_application':bool(os.environ.get('TRNM_NATIVE_EXECUTOR')),
                'clock':'fixed logical timestamps; no real-time block-spacing claim','max_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                'elapsed_ns':int((time.monotonic()-started)*1e9),'progress':points,'shallow_fork_verified':True,'reopen_root':root_digest,'effects_preserved':True,
                'database_bytes':sum(p.stat().st_size for p in (out/'chain').glob('ledger.sqlite*')if p.is_file()),
                'physical_power_loss':False,'public_network_security_accepted':False,'production_activation':False}
        (out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)
    finally:
        if ledger is not None:ledger.close()
        effects.db.close()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);p.add_argument('--height',type=int,default=4106);a=p.parse_args();run(a.out,a.height)
