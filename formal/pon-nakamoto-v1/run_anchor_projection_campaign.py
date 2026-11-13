"""Exact, synthetic >4096-height ASERT local-projection feasibility receipt."""
import argparse
import hashlib
import json

from daa_anchor_projection import ForkLocalAnchorProjection, ProjectedAsertContext, VerifiedHeaderObservation


def run(height=12000):
    if type(height) is not int or not 4100 <= height <= 100000:
        raise ValueError('height range')
    outputs = {}
    for clock in ('raw', 'mtp11'):
        ctx = ProjectedAsertContext(*(hashlib.sha256(tag).digest() for tag in (
            b'projected-net', b'projected-parameters', b'projected-genesis', b'projected-rule')),
            1700000000, 16, 10, 7200, (1 << 250) - 1, clock)
        ledger = ForkLocalAnchorProjection(ctx)
        parent = ctx.genesis
        corpus = hashlib.sha256()
        for h in range(1, height + 1):
            ts = ctx.genesis_timestamp + h * 10
            block_id = hashlib.sha256(parent + h.to_bytes(8, 'big') + ts.to_bytes(8, 'big')).digest()
            row = ledger.observe_assumed_validated(VerifiedHeaderObservation(
                block_id, parent, ctx.network, ctx.parameters, h, ts, 1 << 220))
            corpus.update(row.commitment)
            parent = block_id
        outputs[clock] = {
            'parent': parent.hex(),
            'projection_commitments_digest': corpus.hexdigest(),
            'shadow_target': hex(ledger.expected_shadow_target(parent)),
            'last_height': ledger.read_local(parent).height,
            'local_projection_integrity': ledger.validate_local_chain(parent),
            'observed_work_proofs': 0,
            'verified_network_actors': 0,
        }
    return {
        'schema':'trnm-daa-anchor-projection-synthetic-v1',
        'research_only':True,
        'no_legacy_daa_change':True,
        'no_production_activation':True,
        'fully_validated_native_work_packets':False,
        'height':height,
        'clock_modes':outputs,
    }


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--height',type=int,default=12000)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    report=run(args.height)
    data=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
    with open(args.output,'xb') as file:
        file.write(data)
    print(json.dumps({'output':args.output,'sha256':hashlib.sha256(data).hexdigest(),
                      'heights':args.height,'modes':list(report['clock_modes'])},sort_keys=True))
