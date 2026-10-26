"""Read-only W1/W2-E valid and invalid evidence, never protocol activation."""
import argparse
import json
import platform
import struct
import work_oracle as W
import w2e_batched_polynomial as E
import w2d_late_tile_attack as L


def report(seeds=(1,2,3,4), cap=128):
    if not 1<=len(seeds)<=16 or len(set(seeds))!=len(seeds):
        raise ValueError('SEEDS')
    if type(cap) is not int or not 1<=cap<=4096:
        raise ValueError('CAP')
    challenge=bytes(range(32))
    a=[(i*11)%97 for i in range(W.CELLS)]
    b=[(i*17)%101 for i in range(W.CELLS)]
    cases=(('dense',a,b),('zero',[0]*W.CELLS,[0]*W.CELLS),
           ('sparse',[x if i%17==0 else 0 for i,x in enumerate(a)],
                     [x if i%19==0 else 0 for i,x in enumerate(b)]))
    honest=[]
    for label,left,right in cases:
        result=E.costs(challenge,left,right)
        result['material']=label
        honest.append(result)
    invalid=[L.campaign(seed,cap,verifier=E.verify,
                        expected_error='BATCHED_TILE_RELATION')for seed in seeds]
    return {'schema':'w2e-batched-matched-cpu-v0','challenge':challenge.hex(),
            'platform':platform.platform(),'python':platform.python_version(),
            'target':'all-ff synthetic for honest; 7f-ff initial for invalid',
            'original_w1_proof_changed':False,'actual_native_verifier':False,
            'gpu_rate_measured':False,'independent_operators':False,
            'random_oracle_assumption_not_a_security_certificate':True,
            'full_verified_work':False,'production_activation':False,
            'honest_rows':honest,'invalid_rows':invalid}


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--seeds',type=int,nargs='+',default=[1,2,3,4])
    p.add_argument('--cap',type=int,default=128)
    p.add_argument('--out')
    opts=p.parse_args()
    result=report(tuple(opts.seeds),opts.cap)
    text=json.dumps(result,indent=2,sort_keys=True)+'\n'
    if opts.out:
        with open(opts.out,'x',encoding='utf-8') as destination:
            destination.write(text)
    else:print(text,end='')

if __name__=='__main__':main()
