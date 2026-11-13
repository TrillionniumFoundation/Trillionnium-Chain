"""Run retained numerical controls; hosted/source-Git receipts are excluded."""
from pathlib import Path
import importlib
import json
import sys
import unittest

source = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(source))
suite = unittest.TestSuite()
selection = {
    "test_quantum_oracle_resources": None,
    "test_quantum_candidate_check_clock": None,
    "test_quantum_adversarial_search": ("FiniteDomainControls", "BoundedPolicyControls"),
    "test_quantum_daa_model": ("IntegerRulesTests", "ConditionalScheduleTests"),
    "test_quantum_resource_clock": ("ResourceClockControls",),
}
excluded = {
    "test_campaign_rederives_clocks_and_replays_trace",
    "test_campaign_source_head_cannot_be_invented",
    "test_construction_mode_replaces_forged_circuit_inputs_and_replays",
}
def flatten(group):
    for item in group:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item
for name, classes in selection.items():
    module = importlib.import_module(name)
    groups = ([unittest.defaultTestLoader.loadTestsFromModule(module)] if classes is None else
              [unittest.defaultTestLoader.loadTestsFromTestCase(getattr(module, cls)) for cls in classes])
    for group in groups:
        for test in flatten(group):
            if test._testMethodName not in excluded:
                suite.addTest(test)
methods = [test.id() for test in flatten(suite)]
result = unittest.TextTestRunner(verbosity=2).run(suite)
print(json.dumps({"source": str(source), "tests": result.testsRun,
                  "failures": len(result.failures), "errors": len(result.errors),
                  "successful": result.wasSuccessful(), "methods": methods,
                  "scope": "extracted-file numerical controls only; repository Git/campaign identity suites excluded"}))
raise SystemExit(0 if result.wasSuccessful() else 1)
