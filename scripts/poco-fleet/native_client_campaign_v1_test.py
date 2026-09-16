#!/usr/bin/env python3
"""Structural rejection tests; cryptographic verification requires real evidence."""
import copy
import hashlib
import pathlib
import tempfile
import native_client_campaign_v1 as c
import run_network_smoke_fleet as base


def main():
    native={"public_files":[{"path":"public/native-client-profile.json"}]}
    legacy={"public_files":[{"path":"public/workload.corpus"},{"path":"public/workload-policy.json"}]}
    assert c.application_selection(native,pathlib.Path('/candidate/keys'),1)
    assert not c.application_selection(legacy,None,1)
    rejected=0
    def reject(fn):
        nonlocal rejected
        try:fn()
        except (RuntimeError,ValueError,KeyError,TypeError,SystemExit):rejected+=1
        else:raise AssertionError('accepted invalid candidate evidence')
    reject(lambda:c.application_selection(native,None,1))
    reject(lambda:c.application_selection(legacy,pathlib.Path('/keys'),1))
    reject(lambda:c.application_selection(native,pathlib.Path('/keys'),17))
    records=[]
    for i in range(2):
        h=f'{i+1:064x}'
        response={"ok":True,"profile_sha256":"22"*32,"candidate_only":True,"data":{"native_tx_hash":h,"receive_sequence":str(i),"status":"pending"}}
        outer=b'{}'
        records.append({"kind":"funding" if i==0 else "transfer","native_tx_hash":h,"outer_hex":outer.hex(),"outer_sha256":hashlib.sha256(outer).hexdigest(),"submitted_monotonic_ns":10+i*10,"ack_monotonic_ns":11+i*10,"verified_monotonic_ns":12+i*10,"ack":response,"retry_ack":copy.deepcopy(response),"proof_response":copy.deepcopy(response),"mac_verification":{"candidate_only":True,"m05_intent_binding":False,"native_tx_hash":h,"proof_verified_by_client":True,"height":"4","index":i}})
    document={"schema":c.PROFILE,"run_id":"candidate","coordinator_manifest_sha256":"11"*32,"profile_sha256":"22"*32,"submit_validator_id":"33"*32,"signing_host":"mac","verification_host":"mac","transport":"ssh-private-unix-ipc","started_monotonic_ns":1,"completed_monotonic_ns":30,"business_transfer_count":1,"business_window_ns":2,"business_goodput_per_second":500000000.0,"records":records,"candidate_only":True,"m05_intent_binding":False,"fault_matrix_completed":False,"performance_acceptance":False,"host_attestation":False,"production_activation":False}
    def validate(d):c.validate_document(d,run_id='candidate',anchor='11'*32,validator_ids={'33'*32})
    validate(document) # Metadata only. These dummy bytes are never a crypto-positive.
    for field,value in [('schema','fake'),('run_id','other'),('coordinator_manifest_sha256','44'*32),('submit_validator_id','55'*32),('signing_host','local'),('transport','public-http'),('business_transfer_count',2),('business_window_ns',1),('business_goodput_per_second',1),('completed_monotonic_ns',1),('started_monotonic_ns',False),('candidate_only',False),('production_activation',True),('performance_acceptance',True),('host_attestation',True),('m05_intent_binding',True),('fault_matrix_completed',True)]:
        d=copy.deepcopy(document);d[field]=value;reject(lambda:validate(d))
    for mutate in [lambda d:d['records'][1].update(native_tx_hash=d['records'][0]['native_tx_hash']),lambda d:d['records'][0].update(outer_sha256='00'*32),lambda d:d['records'][0].update(ack_monotonic_ns=0),lambda d:d['records'][0]['retry_ack']['data'].update(receive_sequence='99'),lambda d:d['records'][0]['ack'].update(ok=False),lambda d:d['records'][0]['mac_verification'].update(proof_verified_by_client=False),lambda d:d['records'][0].update(kind='transfer')]:
        d=copy.deepcopy(document);mutate(d);reject(lambda:validate(d))
    with tempfile.TemporaryDirectory() as temporary:
        root=pathlib.Path(temporary);keys=root/'keys';keys.mkdir(mode=0o700);profile=b'candidate';coordinator=root/'coordinator';deployments=root/'deployments';coordinator.mkdir();deployments.mkdir()
        for name in ('operator.key','client.key'):base.write_new(keys/name,b'a'*64)
        base.write_new(keys/'native-client-profile.json',profile)
        assert c.key_namespace(keys,coordinator,deployments,profile)==keys
        reject(lambda:c.key_namespace(keys,root,deployments,profile))
        reject(lambda:c.key_namespace(keys,coordinator,deployments,b'other'))
        (keys/'client.key').chmod(0o644);reject(lambda:c.key_namespace(keys,coordinator,deployments,profile));(keys/'client.key').chmod(0o600)
        (keys/'client.key').unlink();(keys/'client.key').symlink_to(keys/'operator.key');reject(lambda:c.key_namespace(keys,coordinator,deployments,profile))
    print(f'native_campaign_structural_tests=passed negatives={rejected} cryptographic_success_claim=false real_campaign_required=true')

if __name__=='__main__':main()
