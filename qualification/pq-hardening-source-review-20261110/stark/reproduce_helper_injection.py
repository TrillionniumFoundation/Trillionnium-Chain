from copy import deepcopy
from pathlib import Path
from types import ModuleType
from unittest.mock import patch
import sys
import json

root = Path(__file__).resolve().parent / 'original'
sys.path.insert(0, str(root / 'scripts'))
import w1_stark_route_audit as audit
import w1_stark_field_certificates as field

registry = audit.strict_json((root / audit.REGISTRY_PATH).read_bytes())
honest = audit.audit(root, registry)
fake = deepcopy(field.build_report(root))
# X^2 is reducible. No source bytes or source pins are changed.
fake['fields']['plonky3_goldilocks_fp2']['extension_polynomial_low_to_high'] = ['0', '0', '1']
for route in registry['routes'][1:]:
    route['field']['extension_polynomial_low_to_high'] = ['0', '0', '1']
poisoned = ModuleType('w1_stark_field_certificates')
poisoned.build_report = lambda _root: deepcopy(fake)
with patch.dict(sys.modules, {'w1_stark_field_certificates': poisoned}):
    forged = audit.audit(root, registry)
print(json.dumps({
    'baseline_status': honest['status'],
    'source_pin_set_unchanged': registry['source_inputs'],
    'forged_status': forged['status'],
    'forged_field_certificate_status': forged['field_certificate_status'],
    'forged_goldilocks_polynomial': forged['routes'][1]['field']['extension_polynomial_low_to_high'],
    'source_mapping_reproduced': forged['source_mapping_reproduced'],
    'production_qualified': forged['qualification']['production_qualified'],
    'scope': 'helper execution provenance bypass; no production or cryptographic security qualification granted',
}, indent=2, sort_keys=True))
