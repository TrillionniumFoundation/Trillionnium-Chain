"""Prepare only the previously frozen candidate/X/output; never fit or read labels."""
import base64
import hashlib
import json
from pathlib import Path
import struct
import sys
import zlib

BASE = Path('/tmp/hepta-chain-6523704f97df')
OUT = BASE / 'native-f64-private-observation-inputs'
OUT.mkdir(mode=0o700, exist_ok=False)
script = BASE / 'reference-repo/scripts/pft_candidate_readback.py'
assert hashlib.sha256(script.read_bytes()).hexdigest() == '8ed1008234333b09310662bbcae6921fd2b2c01d5dedbd744b474f731b8e627b'
sys.path.insert(0, str(script.parent))
import pft_candidate_readback as identity

paths = {
    'candidate': (Path('/tmp/hepta-learning-6523704f97df/runs/attempt-1/historical/n8-s17011/forward-candidate.json'), '001f322da2ac470f83a9e502971b79e47c0dca3baa9211fc4abd10ba10b115ae'),
    'features': (BASE / 'reference-private-inputs/FEATURE_INPUT.json', '26456299b8fc9ac79914f8ac5762280329ebf3ced28c3e2d4420f7e95d1dd9e0'),
    'expected': (BASE / 'reference-private-inputs/NORMAL_EXPECTED.json', '55caff98a3fd6d23db730a6032bbb0b24547d37124d805041d314356dd5aee2a'),
    'reference': (BASE / 'reference-private-run-attempt-1/PRIVATE_RECEIPT.json', '2447ff96b36f2023961acc36032790ac9269c2ee3bcf6bffee9fc8cf73d8628e'),
}
raw = {name: identity.read_bounded(path, identity.MAX_BYTES) for name, (path, _) in paths.items()}
for name, (_, pin) in paths.items():
    assert identity.sha(raw[name]) == pin
objects = {name: identity.decode(value) for name, value in raw.items()}
review = identity.review_candidate(raw['candidate'], objects['expected']['candidate'])
candidate, features, reference = (objects[k] for k in ['candidate', 'features', 'reference'])
contract = candidate['contract']
assert candidate['weight_shape'] == [41, 3] and reference['prediction_shape'] == [4, 3]
assert len(features['features']) == 4 and all(len(row) == 41 for row in features['features'])
for field in ['contract_sha256', 'feature_program_sha256', 'normalization_sha256', 'time_semantics_sha256']:
    assert features[field] == (candidate[field] if field == 'contract_sha256' else contract[field])
assert features['request_id'] == reference['request_id'] == '8f58fa50c17a83ee7c523cc61c3fd84c111e182acc838b877fa16175df6d22ab'
assert features['source_sha256'] == 'e1370cae11b8ad905fed061a348ecf9898bd3da8640f5cbc512c126b4e69c81f'
assert identity.sha(identity.canonical(features['row_ids'])) == reference['row_ids_sha256'] == 'fc9b11abe87a55f3622c3d09e816be5f0a6c2389e718b1c35de8fd721e368169'

def binary(matrix):
    return b''.join(struct.pack('<d', identity.real(value)) for row in matrix for value in row)

w, x, yhat = binary(candidate['weight']), binary(features['features']), binary(reference['prediction'])
assert identity.sha(w) == candidate['weight_sha256'] == '3ec311f81f5323c74e114e6433813b5dbc8ea90a3dc3d191bde48f42fa42f022'
assert identity.sha(yhat) == reference['prediction_sha256'] == 'a254e8385df48372e9cc35ef307521976c3eca5f77e7c65b503018a626364285'
files = {name: value for name, value in [('weight.actual.le', w), ('weight.expected.le', w), ('features.actual.le', x), ('features.expected.le', x), ('reference-output.le', yhat)]}
for name, value in files.items():
    (OUT / name).write_bytes(value)
    (OUT / name).chmod(0o400)

model_fields = {k: (paths['candidate'][1] if k == 'candidate_sha256' else candidate[k] if k in candidate else contract[k]) for k in ['candidate_sha256', 'contract_sha256', 'head', 'weight_sha256', 'feature_program_sha256', 'normalization_sha256', 'time_semantics_sha256']}
input_fields = {k: (model_fields[k] if k in model_fields else reference['row_ids_sha256'] if k == 'row_ids_sha256' else paths['features'][1] if k == 'feature_packet_sha256' else features[k]) for k in ['candidate_sha256', 'weight_sha256', 'contract_sha256', 'feature_program_sha256', 'normalization_sha256', 'time_semantics_sha256', 'request_id', 'source_sha256', 'row_ids_sha256', 'feature_packet_sha256']}
harness = '''//! One fixed historical byte observation; private matrices are compile-time inputs.
//! Caller-side SHA verification is separate; this is not original-owner authority.
#[allow(dead_code)]
#[path = "../../trillionnium/crates/trnm-pon-node/src/pft_readout_f64_v1.rs"]
mod pft;
use pft::*;
use std::io::Write;

fn pin(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&hex[i*2..i*2+2], 16).unwrap())
}

fn main() {
    let model = PftModelDescriptorV1 {
        schema: MODEL_SCHEMA.into(), family: FAMILY.into(), numeric_profile: PROFILE.into(),
'''
harness += ''.join(f'        {k}: pin("{v}"),\n' for k, v in model_fields.items())
harness += '        dimension: 41, outputs: 3,\n    };\n    let input = PftInputDescriptorV1 {\n        schema: INPUT_SCHEMA.into(),\n'
harness += ''.join(f'        {k}: pin("{v}"),\n' for k, v in input_fields.items())
harness += '''        rows: 4, dimension: 41,
    };
    let prepared = PreparedPftReadoutV1::prepare(&model,
        include_bytes!(env!("TRNM_PFT_ACTUAL_WEIGHT_FILE")), &model,
        include_bytes!(env!("TRNM_PFT_EXPECTED_WEIGHT_FILE"))).expect("model comparison");
    let input = prepared.prepare_input(&input,
        include_bytes!(env!("TRNM_PFT_ACTUAL_FEATURE_FILE")), &input,
        include_bytes!(env!("TRNM_PFT_EXPECTED_FEATURE_FILE"))).expect("feature comparison");
    let prediction = prepared.predict(&input).expect("bounded typed readout");
    assert_eq!(prediction.shape(), [4, 3]);
    let bytes = prediction.to_le_bytes();
    assert!(bytes.as_slice() == include_bytes!(env!("TRNM_PFT_REFERENCE_OUTPUT_FILE")),
        "output differs from previously retained reference bytes");
    std::io::stdout().lock().write_all(&bytes).unwrap();
}
'''
(OUT / 'historical_harness.rs').write_text(harness)
files['historical_harness.rs'] = harness.encode()
manifest = dict(schema='trnm-pft-fixed-historical-native-preparation-v1', input_sha256={name: pin for name, (_, pin) in paths.items()}, model=model_fields, input=input_fields, shapes={'weight':[41,3], 'features':[4,41], 'prediction':[4,3]}, files={name: {'sha256': identity.sha(value), 'bytes':len(value)} for name,value in files.items()}, normal_equation_reexecuted=False, features_reexecuted=False, labels_read=False, dev_read=False, final_read=False, xw_executed=False, source_authentication=False)
(OUT / 'FROZEN_BEFORE_NATIVE.json').write_text(json.dumps(manifest, indent=2))
payload = json.dumps({'manifest':manifest, 'files':{name:base64.b64encode(value).decode() for name,value in files.items()}}, separators=(',', ':')).encode()
(OUT / 'PRIVATE_TRANSFER.json').write_text(json.dumps({'sha256':identity.sha(payload),'payload':base64.b64encode(zlib.compress(payload)).decode()}))
assert all(identity.sha(identity.read_bounded(path, identity.MAX_BYTES)) == pin for path,pin in paths.values())
print(json.dumps(manifest))
