#!/usr/bin/env python3
"""Real-signal cancellation controls; no successful synthetic proof evidence.

Control children perform no W1 proving and never create a manifest or receipt.
Helper snapshots explicitly contain only control data. These tests establish
local signal/resource handoff behavior, not a cryptographic or performance gate.
"""
import contextlib
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
EXPERIMENTS = ROOT / "formal/pon-nakamoto-v1/experiments"
sys.path.insert(0, str(EXPERIMENTS))
import w1_stage_measure as stage
import w1_full_staged_run as coordinator


class CancellationHandoffTests(unittest.TestCase):
    def caught_signal(self, signum):
        with stage.cancel_on_signals():
            try:
                os.kill(os.getpid(), signum)
            except stage.Canceled as failure:
                return failure
        self.fail("actual signal did not produce the enclosing cancellation")

    def control_snapshot(self, path, handoff):
        stage.write_new(path, {"control_only": True, "complete_proof_claim": False})
        handoff.published_snapshot("control-only", path)

    def assert_snapshot(self, failure, path):
        snapshot = failure.observed_snapshot
        raw = path.read_bytes()
        self.assertEqual(snapshot["schema"], "TRNM-W1-OBSERVED-SNAPSHOT1")
        self.assertEqual(snapshot["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(snapshot["value"], json.loads(raw))

    def test_prior_actual_cancel_survives_io_without_second_signal(self):
        prior = self.caught_signal(signal.SIGTERM)
        with tempfile.TemporaryDirectory() as temp, stage.cancel_on_signals():
            conflict = Path(temp) / "already-exists"
            conflict.write_text("preserve this conflict\n")
            with self.assertRaises(stage.Canceled) as caught:
                with stage.DeferredCancellation(prior, phase="control-persistence"):
                    stage.write_new(conflict, {"control_only": True})
            self.assertIs(caught.exception, prior)
            self.assertEqual(caught.exception.signum, signal.SIGTERM)
            self.assertFalse(hasattr(caught.exception, "observed_snapshot"))
            self.assertIsInstance(caught.exception.__cause__, FileExistsError)
            event = caught.exception.cancellation_event["handoffs"][-1]
            self.assertIsNone(event["first_deferred"])
            self.assertEqual(event["interrupted_error"]["type"], "FileExistsError")
            self.assertEqual(conflict.read_text(), "preserve this conflict\n")

    def test_prior_cancel_and_io_keep_already_published_snapshot(self):
        prior = self.caught_signal(signal.SIGTERM)
        with tempfile.TemporaryDirectory() as temp, stage.cancel_on_signals():
            saved = Path(temp) / "saved.json"
            with self.assertRaises(stage.Canceled) as caught:
                with stage.DeferredCancellation(prior, phase="control-after-snapshot") as handoff:
                    self.control_snapshot(saved, handoff)
                    stage.write_new(saved, {"must_not_replace": True})
            self.assertIs(caught.exception, prior)
            self.assert_snapshot(caught.exception, saved)
            self.assertIsInstance(caught.exception.__cause__, FileExistsError)

    def test_pair_installation_defers_signal_until_both_handlers_are_installed(self):
        real_signal = signal.signal
        injected = False
        handoff = stage.DeferredCancellation(phase="control-installation")

        def install(signum, handler):
            nonlocal injected
            previous = real_signal(signum, handler)
            if (signum == signal.SIGINT and getattr(handler, "__self__", None) is handoff
                    and not injected):
                injected = True
                os.kill(os.getpid(), signal.SIGTERM)
            return previous

        with stage.cancel_on_signals():
            previous = {sig: signal.getsignal(sig) for sig in stage.CANCEL_SIGNALS}
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
            with patch.object(stage.signal, "signal", side_effect=install), \
                    self.assertRaises(stage.Canceled) as caught:
                with handoff:
                    self.assertEqual(handoff.canceled_signal, signal.SIGTERM)
            self.assertTrue(injected)
            self.assertEqual(caught.exception.signum, signal.SIGTERM)
            self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), previous_mask)
            self.assertEqual({sig: signal.getsignal(sig) for sig in stage.CANCEL_SIGNALS}, previous)

    def exercise_unmask(self, prior, deferred_signal, pending_signal):
        real_mask = signal.pthread_sigmask
        ready = injected = False
        with tempfile.TemporaryDirectory() as temp, stage.cancel_on_signals():
            saved = Path(temp) / "snapshot.json"
            enclosing = signal.getsignal(signal.SIGTERM)

            def unmask(how, mask):
                nonlocal injected
                if (ready and not injected and how == signal.SIG_SETMASK
                        and signal.getsignal(signal.SIGTERM) is enclosing):
                    injected = True
                    # The real kernel holds this signal until the real unmask.
                    os.kill(os.getpid(), pending_signal)
                return real_mask(how, mask)

            with patch.object(stage.signal, "pthread_sigmask", side_effect=unmask), \
                    self.assertRaises(stage.Canceled) as caught:
                with stage.DeferredCancellation(prior, phase="control-unmask") as handoff:
                    self.control_snapshot(saved, handoff)
                    if deferred_signal is not None:
                        os.kill(os.getpid(), deferred_signal)
                    ready = True
            self.assertTrue(injected)
            self.assert_snapshot(caught.exception, saved)
            handoff = caught.exception.cancellation_event["handoffs"][-1]
            self.assertEqual(handoff["restored_handler_cancellations"],
                             [{"signal": int(pending_signal), "type": "Canceled"}])
            return caught.exception

    def test_first_deferred_cancel_wins_over_new_unmask_signal(self):
        failure = self.exercise_unmask(None, signal.SIGTERM, signal.SIGINT)
        self.assertEqual(failure.signum, signal.SIGTERM)

    def test_prior_actual_cancel_wins_over_deferred_and_unmask_signals(self):
        prior = self.caught_signal(signal.SIGTERM)
        self.assertIs(self.exercise_unmask(prior, signal.SIGINT, signal.SIGINT), prior)

    def test_first_cancel_only_at_unmask_keeps_saved_snapshot(self):
        failure = self.exercise_unmask(None, None, signal.SIGINT)
        self.assertEqual(failure.signum, signal.SIGINT)

    def test_io_error_text_does_not_invent_a_cancellation(self):
        with tempfile.TemporaryDirectory() as temp, stage.cancel_on_signals():
            directory = Path(temp) / "CANCELED_SIGNAL_15"
            directory.mkdir()
            with self.assertRaises(IsADirectoryError) as caught:
                with stage.DeferredCancellation(phase="ordinary-io-control"):
                    with directory.open("rb"):
                        pass
            self.assertFalse(hasattr(caught.exception, "cancellation_event"))

    def test_real_keyboard_interrupt_stays_primary_when_persistence_fails(self):
        previous = signal.signal(signal.SIGINT, signal.default_int_handler)
        prior = None
        try:
            try:
                os.kill(os.getpid(), signal.SIGINT)
            except KeyboardInterrupt as failure:
                prior = failure
        finally:
            signal.signal(signal.SIGINT, previous)
        self.assertIsInstance(prior, KeyboardInterrupt)
        with tempfile.TemporaryDirectory() as temp, stage.cancel_on_signals():
            conflict = Path(temp) / "existing"
            conflict.write_text("do not overwrite\n")
            with self.assertRaises(KeyboardInterrupt) as caught:
                with stage.DeferredCancellation(prior, phase="keyboard-io-control"):
                    stage.write_new(conflict, {"control_only": True})
            self.assertIs(caught.exception, prior)
            self.assertEqual(caught.exception.cancellation_event["first_canceled_signal"], signal.SIGINT)
            self.assertIsInstance(caught.exception.__cause__, FileExistsError)

    def test_cancellation_sidecar_write_failure_cannot_return_success(self):
        prior = self.caught_signal(signal.SIGTERM)
        with tempfile.TemporaryDirectory() as temp, stage.cancel_on_signals():
            path = Path(temp) / "cancellation.json"
            path.write_text("preserve conflicting record\n")
            with self.assertRaises(stage.Canceled) as caught:
                stage.publish_cancellation(path, prior, "sidecar-control")
            self.assertIs(caught.exception, prior)
            self.assertEqual(caught.exception.signum, signal.SIGTERM)
            self.assertIsInstance(caught.exception.__cause__, FileExistsError)
            self.assertEqual(path.read_text(), "preserve conflicting record\n")


    def test_later_deferred_signal_is_retained_without_replacing_the_first(self):
        with stage.cancel_on_signals(), self.assertRaises(stage.Canceled) as caught:
            with stage.DeferredCancellation(phase="two-signal-control"):
                os.kill(os.getpid(), signal.SIGTERM)
                os.kill(os.getpid(), signal.SIGINT)
        self.assertEqual(caught.exception.signum, signal.SIGTERM)
        handoff = caught.exception.cancellation_event["handoffs"][-1]
        self.assertEqual([row["signal"] for row in handoff["deferred_events"]],
                         [signal.SIGTERM, signal.SIGINT])
        self.assertFalse(handoff["deferred_events_truncated"])

    def test_live_deadline_from_another_boot_is_not_compared(self):
        wrong_boot = "00000000-0000-0000-0000-000000000000"
        self.assertNotEqual(wrong_boot, stage.local_boot_id())
        with stage.cancel_on_signals(), self.assertRaises(stage.Canceled) as caught:
            with stage.DeferredCancellation(phase="foreign-boot-negative",
                                            live_deadline=(0.0, wrong_boot)):
                os.kill(os.getpid(), signal.SIGTERM)

        def interrupted():
            raise caught.exception

        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(stage.run_cli(interrupted), 143)
        event = json.loads(output.getvalue())
        self.assertEqual(event["first_canceled_signal"], signal.SIGTERM)
        self.assertEqual(event["live_deadline_check_at_handoff"]["status"], "DIFFERENT_BOOT")
        self.assertEqual(event["exit_disposition"], "CANCELED")

    def test_saved_clock_without_live_context_does_not_create_current_timeout(self):
        with tempfile.TemporaryDirectory() as directory, stage.cancel_on_signals():
            path = Path(directory) / "old-clock-control.json"
            # This is a parser/handoff rejection input, never a proof record.
            stage.write_new(path, {"schema": "TRNM-W1-STAGE-MEASUREMENT2",
                                  "effective_deadline_monotonic": 0.0,
                                  "timed_out": False, "deadline_exhausted_at_snapshot": False,
                                  "complete_proof_claim": False})
            with self.assertRaises(stage.Canceled) as caught:
                with stage.DeferredCancellation(phase="no-live-clock-negative") as handoff:
                    handoff.published_snapshot("stage", path)
                    os.kill(os.getpid(), signal.SIGTERM)

            def interrupted():
                raise caught.exception

            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                self.assertEqual(stage.run_cli(interrupted), 143)
            event = json.loads(output.getvalue())
            self.assertEqual(event["live_deadline_check_at_handoff"]["status"], "NO_LIVE_CONTEXT")
            self.assertEqual(event["exit_disposition"], "CANCELED")


class StageAndControllerCancellationTests(unittest.TestCase):
    def stage_control(self, out, code="raise SystemExit(0)", deadline=None):
        return stage.measure([sys.executable, "-c", code], out, 3, deadline=deadline)

    def signal_at_first_snapshot(self):
        original = stage.session_snapshot
        state = {"sent": False, "pid": None}

        def snapshot(session):
            result = original(session)
            state["pid"] = session
            if not state["sent"]:
                state["sent"] = True
                os.kill(os.getpid(), signal.SIGTERM)
            return result

        return snapshot, state

    def assert_control_stage(self, result):
        self.assertEqual(result["schema"], "TRNM-W1-STAGE-MEASUREMENT3")
        self.assertFalse(result["complete_proof_claim"])
        self.assertFalse(result["prover_resource_completeness_established"])
        self.assertIsNotNone(result["rusage"]["user_seconds"])
        self.assertIsNotNone(result["returncode"])

    def test_first_signal_during_normal_cleanup_is_not_ignored(self):
        real_wait = os.wait4
        real_snapshot = stage.session_snapshot
        observed_exit = sent = False

        def wait4(pid, flags):
            nonlocal observed_exit
            result = real_wait(pid, flags)
            observed_exit = observed_exit or bool(result[0])
            return result

        def snapshot(session):
            nonlocal sent
            result = real_snapshot(session)
            if observed_exit and not sent:
                sent = True
                os.kill(os.getpid(), signal.SIGTERM)
            return result

        with tempfile.TemporaryDirectory() as temp, stage.cancel_on_signals(), \
                patch.object(stage.os, "wait4", side_effect=wait4), \
                patch.object(stage, "session_snapshot", side_effect=snapshot):
            out = Path(temp) / "stage"
            with self.assertRaises(stage.Canceled) as caught:
                self.stage_control(out)
            result = json.loads((out / "result.json").read_text())
            self.assertTrue(sent)
            self.assert_control_stage(result)
            self.assertEqual(result["returncode"], 0)
            self.assertTrue(result["completion_observed_before_deadline"])
            self.assertIn("CANCELED_SIGNAL_15", result["termination_reasons"])
            self.assertFalse(result["stage_process_complete"])
            self.assertEqual(caught.exception.signum, signal.SIGTERM)

    def test_signal_after_result_fsync_keeps_completed_fact_but_cancels_call(self):
        write_new = stage.write_new

        def saved_then_cancel(path, value):
            write_new(path, value)
            if path.name == "result.json":
                os.kill(os.getpid(), signal.SIGTERM)

        with tempfile.TemporaryDirectory() as temp, stage.cancel_on_signals(), \
                patch.object(stage, "write_new", side_effect=saved_then_cancel):
            out = Path(temp) / "stage"
            with self.assertRaises(stage.Canceled) as caught:
                self.stage_control(out)
            raw = (out / "result.json").read_bytes()
            result = json.loads(raw)
            self.assert_control_stage(result)
            self.assertTrue(result["stage_process_complete"])
            self.assertIsNone(result["canceled_signal"])
            self.assertEqual(caught.exception.signum, signal.SIGTERM)
            self.assertEqual(caught.exception.observed_snapshot["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(caught.exception.observed_snapshot["value"], result)

    def test_actual_stage_prior_cancel_and_real_write_error_keep_cancellation(self):
        snapshot, state = self.signal_at_first_snapshot()
        write_new = stage.write_new

        def fail_result(path, value):
            if path.name == "result.json":
                path.write_text("exclusive-create I/O conflict\n")
            return write_new(path, value)

        with tempfile.TemporaryDirectory() as temp, stage.cancel_on_signals(), \
                patch.object(stage, "session_snapshot", side_effect=snapshot), \
                patch.object(stage, "write_new", side_effect=fail_result):
            out = Path(temp) / "stage"
            with self.assertRaises(stage.Canceled) as caught:
                self.stage_control(out, "import time;time.sleep(1)")
            self.assertTrue(state["sent"])
            self.assertEqual(caught.exception.signum, signal.SIGTERM)
            self.assertIsInstance(caught.exception.__cause__, FileExistsError)
            self.assertFalse(hasattr(caught.exception, "observed_snapshot"))
            self.assertEqual((out / "result.json").read_text(), "exclusive-create I/O conflict\n")
            self.assertFalse(any(row["state"] != "Z" for row in stage.session_snapshot(state["pid"])["members"]))

    def invocation(self, temp):
        control = temp / "control-only"
        control.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(1)\n")
        control.chmod(0o755)
        input_path = temp / "untrusted-control-input.bin"
        input_path.write_bytes(b"no proof or successful checkpoint is supplied")
        return ["--runner", str(control), "--r0vm", str(control),
            "--fresh-verifier", str(control), "--native-verifier", str(control),
            "--prepare-input", str(input_path), "--checkpoint", str(temp / "checkpoint"),
            "--out", str(temp / "out"), "--total-wall-seconds", "5"]

    def test_controller_marks_unretained_canceled_stage_usage_unknown(self):
        snapshot, state = self.signal_at_first_snapshot()
        write_new = stage.write_new

        def fail_stage_result(path, value):
            if path.name == "result.json" and path.parent.name == "prepare-full-execution":
                path.write_text("exclusive-create I/O conflict\n")
            return write_new(path, value)

        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()), \
                patch.object(stage, "session_snapshot", side_effect=snapshot), \
                patch.object(stage, "write_new", side_effect=fail_stage_result):
            temp = Path(directory)
            with self.assertRaises(stage.Canceled) as caught:
                coordinator.main(self.invocation(temp))
            self.assertTrue(state["sent"])
            self.assertEqual(caught.exception.signum, signal.SIGTERM)
            result = json.loads((temp / "out/result.json").read_text())
            self.assertFalse(result["complete_proof_claim"])
            self.assertFalse(result["end_to_end_observation_complete"])
            self.assertEqual(result["controller_canceled_signal"], signal.SIGTERM)
            self.assertEqual(result["stages"], [])
            self.assertEqual(result["stage_dispatch_attempts"], ["prepare-full-execution"])
            self.assertEqual(result["unretained_stage_labels"], ["prepare-full-execution"])
            self.assertFalse(result["all_new_stage_wait4_usage_available"])
            errors = [handoff.get("interrupted_error", {})
                      for handoff in result["controller_cancellation_event"]["handoffs"]]
            self.assertTrue(any(error.get("type") == "FileExistsError" for error in errors))

    def test_controller_retention_io_keeps_actual_cancel_and_stage_usage(self):
        snapshot, state = self.signal_at_first_snapshot()
        append = coordinator.append_event

        def fail_retention(path, row):
            if path.name == "stages.jsonl":
                path.mkdir()
            return append(path, row)

        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()), \
                patch.object(stage, "session_snapshot", side_effect=snapshot), \
                patch.object(coordinator, "append_event", side_effect=fail_retention):
            temp = Path(directory)
            with self.assertRaises(stage.Canceled) as caught:
                coordinator.main(self.invocation(temp))
            self.assertTrue(state["sent"])
            result = json.loads((temp / "out/result.json").read_text())
            self.assertEqual(result["schema"], "TRNM-W1-COMPLETE-STAGED-RUN3")
            self.assertEqual(result["controller_canceled_signal"], signal.SIGTERM)
            self.assertFalse(result["complete_proof_claim"])
            self.assertFalse(result["end_to_end_observation_complete"])
            self.assertEqual(len(result["stages"]), 1)
            measured = result["stages"][0]["result"]
            self.assert_control_stage(measured)
            self.assertEqual(measured["effective_deadline_monotonic"], result["deadline_monotonic"])
            observations = [item for handoff in result["controller_cancellation_event"]["handoffs"]
                            for item in handoff["observation_errors"]]
            self.assertTrue(any(item["kind"] == "retention_error" and item["type"] == "IsADirectoryError"
                                for item in observations))
            starts = [json.loads(line) for line in (temp / "out/events.jsonl").read_text().splitlines()]
            self.assertEqual([row["stage"] for row in starts], ["prepare-full-execution"])
            self.assertFalse((temp / "checkpoint/manifest.json").exists())
            self.assertEqual(caught.exception.signum, signal.SIGTERM)
            sidecar = json.loads((temp / "out/cancellation.json").read_text())
            self.assertEqual(sidecar["canceled_signal"], signal.SIGTERM)
            self.assertTrue(sidecar["operation_canceled"])

    def test_controller_post_snapshot_cancel_preserves_raw_and_writes_sidecar(self):
        write_new = coordinator.write_new
        saved = {}

        def saved_then_cancel(path, value):
            write_new(path, value)
            if path.name == "result.json" and path.parent.name == "out":
                saved["bytes"] = path.read_bytes()
                os.kill(os.getpid(), signal.SIGTERM)

        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()), \
                patch.object(coordinator, "write_new", side_effect=saved_then_cancel):
            temp = Path(directory)
            with self.assertRaises(stage.Canceled) as caught:
                coordinator.main(self.invocation(temp))
            raw = (temp / "out/result.json").read_bytes()
            self.assertEqual(raw, saved["bytes"])
            result = json.loads(raw)
            # A real process ran; it deliberately supplied no valid checkpoint.
            self.assertFalse(result["complete_proof_claim"])
            self.assertFalse(result["end_to_end_observation_complete"])
            self.assertIsNone(result["controller_canceled_signal"])
            self.assertEqual(caught.exception.signum, signal.SIGTERM)
            sidecar = json.loads((temp / "out/cancellation.json").read_text())
            self.assertEqual(sidecar["canceled_signal"], signal.SIGTERM)
            self.assertEqual(sidecar["observed_snapshot"]["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(len(result["stages"]), 1)

    def test_original_deadline_remains_exhausted_when_cleanup_also_cancels(self):
        real_snapshot = stage.session_snapshot
        deadline = None
        sent = False

        def snapshot(session):
            nonlocal sent
            result = real_snapshot(session)
            if deadline is not None and time.monotonic() >= deadline and not sent:
                sent = True
                os.kill(os.getpid(), signal.SIGTERM)
            return result

        with tempfile.TemporaryDirectory() as temp, stage.cancel_on_signals(), \
                patch.object(stage, "session_snapshot", side_effect=snapshot):
            out = Path(temp) / "stage"
            deadline = time.monotonic() + .4
            with self.assertRaises(stage.Canceled) as caught:
                self.stage_control(out, "import time;time.sleep(1)", deadline)
            result = json.loads((out / "result.json").read_text())
            self.assertTrue(sent)
            self.assertTrue(result["timed_out"])
            self.assertTrue(result["deadline_exhausted_at_snapshot"])
            self.assertEqual(result["effective_deadline_monotonic"], deadline)
            self.assertEqual(result["canceled_signal"], signal.SIGTERM)
            self.assertEqual(caught.exception.signum, signal.SIGTERM)
            def canceled_entrypoint():
                raise caught.exception
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(stage.run_cli(canceled_entrypoint), 124)
            exit_event = json.loads(stderr.getvalue())
            self.assertEqual(exit_event["exit_disposition"], "TIMED_OUT")
            self.assertEqual(exit_event["first_canceled_signal"], signal.SIGTERM)

    def test_post_snapshot_cancel_keeps_fact_and_live_deadline_wins_at_handoff(self):
        original_write = stage.write_new
        saved = {}
        deadline = time.monotonic() + 2

        def saved_then_cancel_and_delay(path, value):
            original_write(path, value)
            if path.name == "result.json":
                saved["bytes"] = path.read_bytes()
                os.kill(os.getpid(), signal.SIGTERM)
                time.sleep(max(0, deadline - time.monotonic()) + .02)

        with tempfile.TemporaryDirectory() as directory, stage.cancel_on_signals():
            out = Path(directory) / "late-cancel-handoff"
            with patch.object(stage, "write_new", side_effect=saved_then_cancel_and_delay), \
                    self.assertRaises(stage.Canceled) as caught:
                self.stage_control(out, deadline=deadline)
            self.assertEqual((out / "result.json").read_bytes(), saved["bytes"])
            raw = json.loads(saved["bytes"])
            self.assertTrue(raw["stage_process_complete"])
            self.assertFalse(raw["deadline_exhausted_at_snapshot"])
            self.assertIsNone(raw["canceled_signal"])
            self.assertFalse(raw["complete_proof_claim"])

            def interrupted():
                raise caught.exception

            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                self.assertEqual(stage.run_cli(interrupted), 124)
            event = json.loads(output.getvalue())
            self.assertEqual(event["exit_disposition"], "TIMED_OUT")
            self.assertEqual(event["first_canceled_signal"], signal.SIGTERM)
            self.assertEqual(event["live_deadline_check_at_handoff"]["status"], "EXHAUSTED")


# These are actual Python processes in distinct Linux sessions. They do no
# native/prover work and never manufacture a receipt or a verification success.
NESTED_SESSION_CONTROL = r'''from pathlib import Path
import json,os,signal,sys,time
def identity(pid):
    raw=Path(f"/proc/{pid}/stat").read_text()
    fields=raw.rsplit(")",1)[1].split()
    return {"pid":pid,"birth_ticks":int(fields[19]),"state":fields[0],
            "parent":int(fields[1]),"group":int(fields[2]),"session":int(fields[3])}
def save(path,value):
    with path.open("x") as f:
        json.dump(value,f,sort_keys=True);f.write("\n");f.flush();os.fsync(f.fileno())
mode,root,directory,deadline,grace=sys.argv[1:]
out=Path(directory);deadline=float(deadline)
if mode=="leaf":
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    save(out/"leaf-identity.json",identity(os.getpid()))
    while True:time.sleep(.05)
sys.path.insert(0,str(Path(root)/"formal/pon-nakamoto-v1/experiments"))
import w1_stage_measure as stage
def entry():
    save(out/(mode+"-identity.json"),identity(os.getpid()))
    with stage.cancel_on_signals():
        if mode=="inner":
            original=signal.getsignal(signal.SIGTERM)
            def delayed_cancel(signum,frame):
                save(out/"inner-term-observed.json",{"signal":signum,"monotonic":time.monotonic()})
                time.sleep(.6)
                original(signum,frame)
            signal.signal(signal.SIGTERM,delayed_cancel)
        command=[sys.executable,__file__,"leaf" if mode=="inner" else "inner",root,directory,repr(deadline),"default"]
        kwargs={"deadline":deadline}
        if mode=="outer" and grace!="default":
            kwargs["termination_grace_seconds"]=float(grace)
        try:
            stage.measure(command,out/(mode+"-stage"),60,**kwargs)
        except (stage.Canceled,KeyboardInterrupt) as failure:
            stage.publish_cancellation(out/(mode+"-cancellation.json"),failure,"real-nested-session-control-"+mode)
        return 0
raise SystemExit(stage.run_cli(entry))
'''


class NestedSupervisorCleanupTests(unittest.TestCase):
    def process_identity(self, pid):
        try:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        except FileNotFoundError:
            return None
        return {"pid": pid, "birth_ticks": int(fields[19]), "state": fields[0]}

    def is_live(self, identity):
        current = self.process_identity(identity["pid"])
        return (current is not None and current["birth_ticks"] == identity["birth_ticks"]
                and current["state"] != "Z")

    def stop_owned(self, identity):
        try:
            descriptor = os.pidfd_open(identity["pid"])
        except ProcessLookupError:
            return
        try:
            current = self.process_identity(identity["pid"])
            if current is None:
                return
            self.assertEqual(current["birth_ticks"], identity["birth_ticks"],
                             "never signal a reused PID")
            if current["state"] != "Z":
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        finally:
            os.close(descriptor)

    def test_cleanup_grace_rejects_unbounded_or_non_numeric_values(self):
        with tempfile.TemporaryDirectory() as directory:
            for index, value in enumerate((0, -1, 30.001, float("inf"), float("nan"),
                                            True, "12", None)):
                with self.subTest(value=value):
                    out = Path(directory) / str(index)
                    with self.assertRaisesRegex(ValueError, "termination grace"):
                        stage.measure([sys.executable, "-c", "raise SystemExit(0)"],
                                      out, 1, termination_grace_seconds=value)
                    self.assertFalse(out.exists())

    def test_outer_grace_allows_real_nested_session_kill_reap_and_raw_handoff(self):
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        known, outer = [], None
        try:
            with tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                control = out / "nested-control.py"
                control.write_text(NESTED_SESSION_CONTROL)
                deadline = time.monotonic() + 30
                try:
                    with (out / "outer.stdout.log").open("wb") as stdout, \
                            (out / "outer.stderr.log").open("wb") as stderr:
                        outer = subprocess.Popen(
                            [sys.executable, str(control), "outer", str(ROOT), str(out),
                             repr(deadline), "12"],
                            stdout=stdout, stderr=stderr, start_new_session=True)
                        known.append(self.process_identity(outer.pid))
                        ready = time.monotonic() + 10
                        leaf = None
                        while time.monotonic() < ready:
                            path = out / "leaf-identity.json"
                            if path.exists():
                                try:
                                    leaf = json.loads(path.read_text())
                                    break
                                except json.JSONDecodeError:
                                    pass
                            self.assertIsNone(outer.poll(), "outer exited before real leaf startup")
                            time.sleep(.02)
                        self.assertIsNotNone(leaf, "real nested leaf must start")
                        inner = json.loads((out / "inner-identity.json").read_text())
                        known.extend((inner, leaf))
                        self.assertNotEqual(leaf["session"], inner["session"])
                        self.assertTrue(self.is_live(leaf))
                        descriptor = os.pidfd_open(outer.pid)
                        try:
                            self.assertEqual(self.process_identity(outer.pid)["birth_ticks"],
                                             known[0]["birth_ticks"])
                            signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                        finally:
                            os.close(descriptor)
                        code = outer.wait(timeout=18)
                    self.assertEqual(code, 143, (out / "outer.stderr.log").read_text())
                    inner_raw = json.loads((out / "inner-stage/result.json").read_text())
                    outer_raw = json.loads((out / "outer-stage/result.json").read_text())
                    self.assertEqual(inner_raw["termination_grace_seconds"], 5)
                    self.assertEqual(outer_raw["termination_grace_seconds"], 12)
                    self.assertEqual(inner_raw["effective_deadline_monotonic"], deadline)
                    self.assertEqual(outer_raw["effective_deadline_monotonic"], deadline)
                    self.assertIn("SIGKILL_DURING_SETTLEMENT", inner_raw["termination_reasons"])
                    self.assertNotIn("SIGKILL_DURING_SETTLEMENT", outer_raw["termination_reasons"])
                    self.assertFalse(self.is_live(leaf))
                    for raw in (inner_raw, outer_raw):
                        self.assertFalse(raw["stage_process_complete"])
                        self.assertEqual(raw["canceled_signal"], signal.SIGTERM)
                        self.assertTrue(raw["owned_session_observation_complete"])
                        self.assertEqual(raw["final_owned_session_members"], [])
                        self.assertIsNotNone(raw["rusage"]["user_seconds"])
                        self.assertFalse(raw["prover_resource_completeness_established"])
                        self.assertFalse(raw["complete_proof_claim"])
                finally:
                    # Include startup failures: every child records its identity
                    # before it can spawn the next session. Never sweep host PIDs.
                    for name in ("outer", "inner", "leaf"):
                        path = out / (name + "-identity.json")
                        if path.exists():
                            try:
                                identity = json.loads(path.read_text())
                                if identity not in known:
                                    known.append(identity)
                            except json.JSONDecodeError:
                                pass
                    for identity in reversed(known):
                        if identity is not None:
                            self.stop_owned(identity)
                    if outer is not None and outer.poll() is None:
                        outer.wait(timeout=5)
                    until = time.monotonic() + 5
                    while time.monotonic() < until:
                        for identity in known:
                            if identity is None:
                                continue
                            try:
                                os.waitpid(identity["pid"], os.WNOHANG)
                            except ChildProcessError:
                                pass
                        if not any(self.is_live(row) for row in known if row is not None):
                            break
                        time.sleep(.02)
                    self.assertFalse(any(self.is_live(row) for row in known if row is not None),
                                     "every test-owned process must be fenced and no longer live")
        finally:
            self.assertEqual(libc.prctl(36, previous.value, 0, 0, 0), 0)



if __name__ == "__main__":
    unittest.main()
