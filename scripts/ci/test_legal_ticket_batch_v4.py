#!/usr/bin/env python3
"""Synthetic report-reader controls; these do not execute a native miner."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from check_legal_ticket_batch_v4 import ARMS, RECURRING, SCHEMA, summed, validate, verify_payloads
from test_legal_ticket_cost_v3 import control as serial_control


PAYLOAD = b"synthetic reader control, not a native packet"


def control():
    serial = serial_control()
    begin = copy.deepcopy(serial[0])
    begin.update(schema=SCHEMA,cpu_batch_workers=[1,2,4],cpu_batching_measured=True,
                 winning_packet_payloads_retained=True,packet_archive_setup={"wall_ns":1,"process_cpu_ns":1})
    rows = [begin]
    for round_id in (0,1):
        for workers in ((1,2,4) if round_id == 0 else (4,2,1)):
            for arm in (ARMS if round_id == 0 else ARMS[::-1]):
                row = copy.deepcopy(next(r for r in serial[1:-1] if r["round"] == round_id and r["reuse"] and r["strategy"] == arm))
                row.update(schema=SCHEMA,batch_workers=workers,batch_process_clock_intervals=1,
                    overlapping_trial_times_added_to_batch=False,batch_includes_spawn_join_and_trial_records=True,
                    worker_observations=[dict(worker=i,thread_id=f"ThreadId({i+1})",searches=64//workers,
                        started_offset_ns=i,finished_offset_ns=64-i) for i in range(workers)])
                stream = hashlib.sha256(b"TRNM-LEGAL-CPU-BATCH-STREAM-V4\0")
                for i,search in enumerate(row["searches"]):
                    search["worker"] = i%workers
                    search["search_stream_sha256"] = hashlib.sha256(f"synthetic-{round_id}-{i}".encode()).hexdigest()
                    stream.update(i.to_bytes(8,"little"))
                    stream.update(bytes.fromhex(search["search_stream_sha256"]))
                    for trial in search["trials"]:
                        trial.pop("generation")
                        trial.update(overlapping_kernel_wall_ns=99,packet_bytes=len(PAYLOAD))
                row["stream_sha256"] = stream.hexdigest()
                for packet in row["retained_packets"]:
                    packet.update(bytes=len(PAYLOAD),sha256=hashlib.sha256(PAYLOAD).hexdigest(),
                        file=f"round-{round_id}-workers-{workers}-{'limb' if arm == ARMS[1] else 'general'}/{packet['id']}.packet")
                row["phases"]["packet_archival"] = {"wall_ns":1,"process_cpu_ns":1}
                row["all_exclusive_phases"] = summed(row["phases"].values())
                rows.append(row)
    terminal = copy.deepcopy(serial[-1])
    terminal.update(schema=SCHEMA,cohorts=12)
    rows.append(terminal)
    return rows


class Reader(unittest.TestCase):
    def reject(self, change):
        rows = control()
        change(rows)
        with self.assertRaises((ValueError,KeyError)):
            validate(rows)

    def test_real_batch_scopes_do_not_sum_overlapping_trial_times(self):
        result = validate(control())
        self.assertEqual((result["cohorts"],result["first_admission_calls"],result["distinct_fixture_packet_ids_across_paired_cohorts"]),(12,768,128))
        self.assertEqual(result["groups"][4]["phases"]["all_attempt_generation"]["wall_ns"],64)

    def test_missing_worker_duplicate_thread_and_wrong_partition_reject(self):
        self.reject(lambda r:r[3]["worker_observations"].pop())
        self.reject(lambda r:r[3]["worker_observations"][1].update(thread_id=r[3]["worker_observations"][0]["thread_id"]))
        self.reject(lambda r:r[3]["searches"][1].update(worker=0))

    def test_overlapping_process_clock_and_omitted_cost_reject(self):
        self.reject(lambda r:r[1].update(overlapping_trial_times_added_to_batch=True))
        self.reject(lambda r:r[1]["searches"][0]["trials"][0].update(generation={"wall_ns":1,"process_cpu_ns":1}))
        self.reject(lambda r:r[1]["phases"].pop("packet_archival"))
        self.reject(lambda r:r[1]["observed_outer"].update(wall_ns=1))

    def test_changed_paired_attempt_and_unearned_admission_reject(self):
        self.reject(lambda r:r[2]["searches"][0]["trials"][0].update(proof_sha256="ff"*32))
        self.reject(lambda r:r[1].update(first_native_admissions=63))
        self.reject(lambda r:r[1]["searches"][0].update(won=False))
        self.reject(lambda r:r[1].update(target="00"*32))

    def test_budget_scope_and_payload_path_reject(self):
        self.reject(lambda r:r[-1].update(wall_ns=240_000_000_001))
        self.reject(lambda r:r[0].update(gpu_measured=True))
        self.reject(lambda r:r[1]["retained_packets"][0].update(file="../packet"))
        self.reject(lambda r:r.pop(3))

    def test_unknown_process_cpu_remains_unknown(self):
        rows = control()
        for row in rows[1:-1]:
            row["phases"]["all_attempt_generation"]["process_cpu_ns"] = None
            row["all_exclusive_phases"]["process_cpu_ns"] = None
            row["recurring_producer_encode_admission"] = summed(row["phases"][n] for n in RECURRING)
        result = validate(rows)
        self.assertIsNone(result["comparisons"][0]["ms_per_first_admission"]["batch_generation"]["process_cpu_ms"])

    def test_exact_retained_payloads_and_changed_bytes(self):
        rows = control()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for row in rows[1:-1]:
                for packet in row["retained_packets"]:
                    path = root/packet["file"]
                    path.parent.mkdir(exist_ok=True)
                    path.write_bytes(PAYLOAD)
            self.assertEqual(verify_payloads(rows,root)["files"],768)
            first = root/rows[1]["retained_packets"][0]["file"]
            first.write_bytes(b"X"*len(PAYLOAD))
            with self.assertRaises(ValueError):
                verify_payloads(rows,root)

    def test_retained_symlink_and_unexpected_files_reject(self):
        rows = control()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/"unexpected").symlink_to("/nonexistent")
            with self.assertRaises(ValueError):
                verify_payloads(rows,root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
