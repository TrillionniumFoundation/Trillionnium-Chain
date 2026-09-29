"""Explicit vector update for a new genesis revision; NEVER invoked by tests."""
import json,tempfile
from pathlib import Path
from ledger import *
D=Path(__file__).parent/'vectors/accepted-block'
def main():
    D.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='pon-vector-')as path:
        ledger=Ledger(path)
        try:
            tx=sign(key(0),1,'transfer',dict(recipient=public(key(1)),amount=123))
            header,txs,proof=ledger.make(GENESIS,[tx]);observed=PARAMS['genesis_timestamp']+10000
            bid=ledger.admit(header,txs,proof,observed);ledger.activate(bid);state=ledger.read_active()[2]
            h=header_decode(header);challenge=H('challenge',header)
            expected={'scope':'revision3-accepted-block-vector-not-security-acceptance','genesis':GENESIS.hex(),'genesis_state_root':state_root(genesis_state()).hex(),'post_state_root':state_root(state).hex(),'header_challenge':challenge.hex(),'tx_id':H('tx-id',tx).hex(),'work_task':h['work_task'].hex(),'target':h['target'].hex(),'ticket':H('ticket',challenge,proof[-32:]).hex(),'block_id':bid.hex(),'observed_logical_time':observed}
            for filename,data in [('header.bin',header),('transaction.bin',tx),('work.bin',proof)]: (D/filename).write_bytes(data)
            for filename,values in [('genesis-state.json',genesis_state()),('post-state.json',state)]:
                (D/filename).write_text(json.dumps([[k.encode().hex(),canonical(v).hex()]for k,v in values.items()])+'\n')
            (D/'expected.json').write_text(json.dumps(expected,indent=2)+'\n')
        finally:ledger.close()
    print(json.dumps(expected))
if __name__=='__main__':main()
