"""Structural negative controls for original oracle provisioning."""
import json
import tomllib
import unittest

from scripts.ci.prepare_original_m06_m09_oracles import LOCK, SHA_LOCK, cargo_artifacts, locked_projection


class OriginalOracleProvisioning(unittest.TestCase):
    def test_projected_ordinary_sha2_binds_every_real_checksum(self):
        original=tomllib.loads(LOCK.read_text())["package"]
        projected=tomllib.loads(locked_projection(original).decode())["package"]
        for row in projected:
            if row["name"] not in SHA_LOCK:
                self.assertEqual(row["dependencies"],["sha2"])
                continue
            [old]=[o for o in original if o["name"]==row["name"] and o["version"]==row["version"]]
            self.assertEqual((row["source"],row["checksum"]),(old["source"],old["checksum"]))
        [sha2]=[row for row in projected if row["name"]=="sha2"]
        self.assertEqual(sha2["dependencies"],["cfg-if","cpufeatures","digest"])
        changed=[dict(o,dependencies=["cfg-if"]) if (o["name"],o["version"])==("sha2","0.10.9") else o
                 for o in original]
        with self.assertRaisesRegex(ValueError,"ordinary lock edges"):
            locked_projection(changed)

    def test_missing_unsuccessful_and_ambiguous_cargo_events_cannot_provision(self):
        def raw(*events):
            return b"\n".join(json.dumps(o).encode() for o in events)
        good={"reason":"build-finished","success":True}
        failed={"reason":"build-finished","success":False}
        msg={"reason":"compiler-artifact","target":{"name":"serde_json"}}
        self.assertEqual(cargo_artifacts(raw(msg,good)),[msg])
        for s in (raw(msg),raw(msg,failed),raw(msg,good,good),raw(good,msg),b"--fake"):
            with self.subTest(s=s),self.assertRaises(ValueError):
                cargo_artifacts(s)
