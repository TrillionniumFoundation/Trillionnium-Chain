#!/usr/bin/env python3
"""Adversarial controls for denominators, never actual WAN observations."""
import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pon_wan_evidence as W


def fixture():
    start = 1_800_000_000_000
    manifest = dict(schema="trnm-wan-preregistration-v1", start_unix_ms=start,
        end_unix_ms=start+72*3600*1000, confirmation_depth=6,
        chain_source_sha256="1"*64, hepta_source_sha256="2"*64, threat_model_sha256="3"*64,
        operators=[dict(id=f"o{i}",administrator=f"admin{i}",failure_domain=f"zone{i}",endpoint=f"TEST_ONLY:{i}",external_attestation_sha256="4"*64) for i in range(3)],
        cohorts=[dict(id="hostile",max_confirmation_ms=5000,minimum_samples_per_operator=2,minimum_timely_ppm=900000)], schedule=[])
    rows = []
    for i in range(3):
        for j in range(2):
            row=dict(id=f"o{i}-r{j}",operator=f"o{i}",cohort="hostile",operation_sha256=f"{i*2+j:064x}",scheduled_unix_ms=start+j*10000)
            manifest["schedule"].append(row)
            rows.append({k:v for k,v in row.items() if k != "scheduled_unix_ms"} | dict(outcome="confirmed",elapsed_ms=1000,cpu_ns=1000000,peak_rss_bytes=1000000,rx_bytes=100,tx_bytes=100,raw_receipt_sha256="a"*64,block_id="b"*64,confirmed_depth=6,observed_chainwork_delta=10))
    return manifest, rows


class Accounting(unittest.TestCase):
    def test_synthetic_success_never_grants_independence_or_wan_acceptance(self):
        report=W.evaluate(*fixture())
        self.assertTrue(report["all_cohort_arithmetic_slos_met"])
        for field in ("independent_accepted","public_network_ready","physical_wan_duration_verified","raw_receipts_cryptographically_verified"):
            self.assertFalse(report[field])

    def test_dropped_timeout_stays_in_original_denominator(self):
        manifest,rows=fixture(); rows.pop()
        report=W.evaluate(manifest,rows)
        self.assertEqual((report["scheduled"],report["recorded"],report["missing"]),(6,5,1))
        self.assertEqual(report["cohorts"][-1]["timely_ppm"],500000)
        self.assertFalse(report["all_cohort_arithmetic_slos_met"])

    def test_every_failure_outcome_reduces_service_without_dropping_resources(self):
        for outcome in W.OUTCOMES-{"confirmed"}:
            manifest,rows=fixture(); rows[-1]["outcome"]=outcome
            report=W.evaluate(manifest,rows)
            self.assertEqual(report["cohorts"][-1]["timely_ppm"],500000)
            self.assertEqual(report["cohorts"][-1]["resources"]["cpu_ns"],2000000)
            self.assertFalse(report["all_cohort_arithmetic_slos_met"])

    def test_late_success_is_not_timely_success(self):
        manifest,rows=fixture(); rows[-1]["elapsed_ms"]=5001
        self.assertFalse(W.evaluate(manifest,rows)["all_cohort_arithmetic_slos_met"])

    def test_duplicates_unknown_ids_and_original_operation_swaps_reject(self):
        manifest,rows=fixture()
        for mode in ("duplicate","unknown","operation"):
            bad=copy.deepcopy(rows)
            if mode=="duplicate": bad.append(bad[0])
            elif mode=="unknown": bad[0]["id"]="new-id"
            else: bad[0]["operation_sha256"]="f"*64
            with self.assertRaises(ValueError):W.evaluate(manifest,bad)

    def test_short_campaign_same_admin_and_missing_operator_cohort_reject(self):
        manifest,rows=fixture()
        for mode in ("short","same-admin","empty-cohort"):
            bad=copy.deepcopy(manifest)
            if mode=="short":bad["end_unix_ms"]-=1
            elif mode=="same-admin":bad["operators"][0]["administrator"]="admin1"
            else:bad["schedule"]=bad["schedule"][:-2]
            with self.assertRaises(ValueError):W.evaluate(bad,rows)

    def test_negative_nonfinite_and_duplicate_json_cannot_supply_costs(self):
        manifest,rows=fixture();rows[0]["cpu_ns"]=-1
        with self.assertRaises(ValueError):W.evaluate(manifest,rows)
        for data in ('{"x":NaN}', '{"x":Infinity}', '{"x":1,"x":2}'):
            with self.assertRaises(ValueError):W.decode(data)


if __name__=="__main__":unittest.main()
