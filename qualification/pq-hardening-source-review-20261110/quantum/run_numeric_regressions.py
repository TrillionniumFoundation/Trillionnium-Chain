from pathlib import Path
import importlib.util
import json
import sys
import unittest

root = Path(__file__).resolve().parent
source = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root / "current"))
sys.path.insert(0, str(source))
suite = unittest.TestSuite()
selected = {
    "test_quantum_adversarial_search": {
        "BoundedPolicyControls": (
            "test_finite_subnormal_costs_cannot_emit_infinite_throughput",
            "test_representable_tiny_costs_and_zero_success_remain_valid",
        )
    },
    "test_quantum_daa_model": {
        "IntegerRulesTests": (
            "test_decimal_cost_inputs_reject_numeric_type_coercion",
            "test_decimal_cost_input_size_and_extreme_exponents_fail_before_execution",
        )
    },
}
for name, classes in selected.items():
    spec = importlib.util.spec_from_file_location(name, root / "patches/formal/pon-nakamoto-v1" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for cls, methods in classes.items():
        for method in methods:
            suite.addTest(getattr(module, cls)(method))
result = unittest.TextTestRunner(verbosity=2).run(suite)
print(json.dumps({"source": str(source), "tests": result.testsRun,
                  "failures": len(result.failures), "errors": len(result.errors),
                  "successful": result.wasSuccessful()}))
raise SystemExit(0 if result.wasSuccessful() else 1)
