"""Native HIA API regressions with explicitly synthetic syscall acknowledgements."""
from pathlib import Path
import tempfile
import unittest

from hia.platform.reactor.build import Build
from hia.platform.reactor.contracts import Contracts


class ReactorPolicyContractTests(unittest.TestCase):
    def test_native_policy_contracts(self):
        with tempfile.TemporaryDirectory(prefix="trnm-reactor-contracts-") as directory:
            root = Path(directory)
            build = Build(root / "build")
            build.build_api_fixture()
            report = Contracts(root / "contracts", build.api_executable).run()
            for row in report["controls"]:
                with self.subTest(contract=row["case"]):
                    self.assertTrue(row["passed"], row.get("exception"))
                    self.assertFalse(row["actual_os_fault_injection"])
            build.check_pin()


if __name__ == "__main__":
    unittest.main()
