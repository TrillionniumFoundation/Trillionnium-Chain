"""Native HIA API contracts with explicit synthetic event and private state.

These are policy state-machine tests. The input errno, time and FD numbers are
deliberately supplied test values, never claimed as actual kernel fault injection.
All decisions and mutations under test execute in the pinned native HIA image.
"""
from pathlib import Path
import struct

from hia.platform.build import run_native, require_success, sha256, write_json

MASK = (1 << 64) - 1
COMMAND_BYTES = 69632
STATE_BYTES = 1024


def get(raw, offset):
    return struct.unpack_from("<Q", raw, offset)[0]


def put(raw, offset, value):
    struct.pack_into("<Q", raw, offset, value & MASK)


def cap(state, index, fd, rights, registered=0):
    base = 512 + index * 80
    for offset, value in ((0, fd), (8, 1), (16, rights), (24, 4096),
                          (32, 1), (40, registered), (56, 100 + index), (64, 1)):
        put(state, base + offset, value)
    put(state, 432, get(state, 432) | (1 << index))


def active(phase=10, slot=0, registered=0):
    state = bytearray(STATE_BYTES)
    for offset, value in ((0, phase), (8, 10000), (16, 100), (40, 8), (48, 0),
                          (168, 1), (176, slot), (192, 8), (352, 100), (424, 1)):
        put(state, offset, value)
    cap(state, slot, 7, 5 if slot == 0 else 6, registered)
    return state


def quiescent():
    state = active()
    cap(state, 1, 8, 6)
    for offset, value in ((0, 30), (368, 1), (240, 9), (248, 1)):
        put(state, offset, value)
    return state


class Contracts:
    CASES = (
        ("start-refusal-does-not-adopt", "start_refusal"),
        ("submit-refusal-retains-owned-context", "submit_refusal"),
        ("phase-refusal-is-not-closed", "phase_refusal"),
        ("active-close-refusal-is-not-closed", "active_close_refusal"),
        ("clock-failure-preserves-positive-write-and-close", "clock_write"),
        ("clock-failure-retains-created-epoll", "clock_create"),
        ("clock-failure-detaches-successful-registration", "clock_add"),
        ("clock-failure-does-not-repeat-successful-detach", "clock_detach"),
        ("failed-detach-forbids-submit", "failed_detach"),
        ("close-eintr-recorded-without-retry", "close_eintr"),
        ("terminal-tick-has-no-effects", "terminal"),
        ("clock-regression-preserves-positive-read", "clock_regression"),
        ("clock-failure-preserves-consumed-cancel", "clock_cancel"),
    )

    def __init__(self, output: Path, executable: bytes):
        self.output = output
        self.output.mkdir(mode=0o700)
        self.executable = executable
        self.rows = []
        self.serial = 0
        self.receipts = []

    def call(self, state, *, command=None, operation=0, result=0, phase=None,
             now=200, clock_error=0, mode=0, amount=8, deadline=10000):
        command = bytes(COMMAND_BYTES) if command is None else bytes(command)
        event = bytearray(120)
        seconds, nanos = divmod(now, 1_000_000_000)
        values = {0: result, 8: get(state, 0) if phase is None else phase,
                  16: seconds, 24: nanos, 32: clock_error, 56: operation,
                  64: mode, 72: amount, 80: deadline, 88: 0, 96: 0, 104: 1, 112: 2}
        for offset, value in values.items():
            put(event, offset, value)
        payload = bytes(event) + command + bytes(state)
        self.serial += 1
        raw, receipt = run_native(self.executable, payload, self.case_path,
            "call-" + str(self.serial), timeout=5)
        self.receipts.append(receipt)
        require_success(receipt)
        if len(raw) != 70664:
            raise AssertionError("Native contract fixture returned a truncated frame")
        return get(raw, 0), bytearray(raw[8:69640]), bytearray(raw[69640:])

    @staticmethod
    def need(condition, reason):
        if not condition:
            raise AssertionError(reason)

    def start_refusal(self):
        state = bytearray(STATE_BYTES);command = b"Z" * COMMAND_BYTES
        for options, expected in (({"mode": 3}, 576), ({"clock_error": -1}, 582)):
            value, c, s = self.call(state, command=command, operation=1, **options)
            self.need(value == expected and c == command and s == state,
                      "Synchronous start refusal changed state or ownership")

    def submit_refusal(self):
        state = quiescent();command = b"Q" * COMMAND_BYTES
        for options, expected in (({"mode": 3}, 576), ({"now": 99}, 586),
                                  ({"clock_error": -1}, 582), ({"deadline": 60000000201}, 576)):
            value, c, s = self.call(state, command=command, operation=2, **options)
            self.need(value == expected and c == command and s == state,
                      "Submit refusal was confused with a closed or changed context")

    def phase_refusal(self):
        state = active();command = b"P" * COMMAND_BYTES
        value, c, s = self.call(state, command=command, phase=11)
        self.need(value == 586 and s == state and c == command, "Mismatched phase mutated context")
        state = bytearray(STATE_BYTES)
        value, c, s = self.call(state, command=command)
        self.need(value == 586 and s == state and c == command, "Fresh state accepted a nonexistent acknowledgement")

    def active_close_refusal(self):
        state = active();command = b"A" * COMMAND_BYTES
        value, c, s = self.call(state, command=command, operation=3)
        self.need(value == 586 and s == state and c == command, "Active close pretended to close resources")

    def close_owned(self, state, expected_status, expected_fds):
        value, command, state = self.call(state, operation=3)
        for fd in expected_fds:
            self.need(value == 0 and get(command, 0) == 3 and get(command, 8) == fd,
                      "Owned resource was lost or close order changed")
            value, command, state = self.call(state, command=command, result=0, phase=20)
        self.need(value == 128 + expected_status and get(state, 0) == 31
                  and get(state, 144) == 0 and get(state, 152) == len(expected_fds),
                  "Cleanup did not retain the primary outcome and exact close count")
        again, c2, s2 = self.call(state, command=command, operation=3)
        self.need(again == value and c2 == command and s2 == state, "Closed context repeated effects")
        return state

    def clock_write(self):
        state = active(slot=1)
        for offset, value in ((48, 2), (72, 2), (184, 2)):
            put(state, offset, value)
        value, _, state = self.call(state, result=3, clock_error=-1)
        self.need(value == 326 and get(state, 72) == 5 and get(state, 184) == 5
                  and get(state, 104) == 1 and get(state, 424) == 0
                  and get(state, 136) == MASK and get(state, 320) == 3,
                  "Clock failure erased actual positive write effects")
        self.close_owned(state, 70, [7])

    def clock_create(self):
        state = bytearray(STATE_BYTES)
        for offset, value in ((0, 6), (8, 10000), (16, 100), (352, 100)):
            put(state, offset, value)
        value, _, state = self.call(state, result=9, clock_error=-1)
        self.need(value == 326 and get(state, 240) == 9 and get(state, 248) == 1,
                  "Clock failure lost a successfully created epoll descriptor")
        self.close_owned(state, 70, [9])

    def clock_add(self):
        state = active(phase=11)
        put(state, 240, 9);put(state, 248, 1)
        value, command, state = self.call(state, result=0, clock_error=-1)
        self.need(value == 0 and get(command, 0) == 233 and get(command, 16) == 2
                  and get(command, 24) == 7 and get(state, 424) == 0,
                  "Clock failure failed to detach a successful ADD")
        value, command, state = self.call(state, command=command, result=0, phase=23)
        self.need(value == 326, "Settled clock failure lost its terminal")
        refused, c2, s2 = self.call(state, command=command, operation=2)
        self.need(refused == 586 and s2 == state and c2 == command, "Failed context was resubmitted")
        self.close_owned(state, 70, [7, 9])

    def clock_detach(self):
        state = active(phase=14, registered=1)
        put(state, 240, 9);put(state, 248, 1)
        value, _, state = self.call(state, result=0, clock_error=-1)
        self.need(value == 326 and get(state, 512 + 40) == 0 and get(state, 424) == 0,
                  "Successful DEL was repeated after clock failure")

    def failed_detach(self):
        state = active(phase=14, registered=1)
        put(state, 240, 9);put(state, 248, 1)
        value, command, state = self.call(state, result=-2)
        self.need(value == 326 and get(state, 424) == 0, "Failed DEL left context ready")
        refused, c2, s2 = self.call(state, command=command, operation=2)
        self.need(refused == 586 and s2 == state and c2 == command, "Uncertain registration allowed submit")
        self.close_owned(state, 70, [7, 9])

    def close_eintr(self):
        state = active();put(state, 0, 30);put(state, 368, 1)
        value, command, state = self.call(state, operation=3)
        self.need(value == 0 and get(command, 0) == 3 and get(command, 8) == 7
                  and get(state, 512 + 32) == 0 and get(state, 512 + 8) == 2,
                  "Ownership was not invalidated before close")
        value, command, state = self.call(state, command=command, phase=20, result=-4)
        self.need(value == 128 and get(state, 144) == 1 and get(state, 440) == MASK - 3
                  and get(state, 448) == 7 and get(state, 152) == 1,
                  "Close EINTR was lost or repeated")
        again, c2, s2 = self.call(state, command=command, operation=3)
        self.need(again == 128 and c2 == command and s2 == state, "A reused raw FD could be closed again")

    def terminal(self):
        state = quiescent();command = b"T" * COMMAND_BYTES
        value, c, s = self.call(state, command=command, phase=999, clock_error=-1)
        self.need(value == 256 and c == command and s == state, "Sealed terminal changed after another event")

    def clock_regression(self):
        state = active();put(state, 352, 1000);put(state, 64, 1);put(state, 184, 1)
        value, _, state = self.call(state, result=2, now=999)
        self.need(value == 330 and get(state, 64) == 3 and get(state, 184) == 3
                  and get(state, 96) == 1 and get(state, 424) == 0,
                  "Regressing clock either accepted time or erased acknowledged input")

    def clock_cancel(self):
        state = active(phase=13)
        value, _, state = self.call(state, result=1, clock_error=-1)
        self.need(value == 326 and get(state, 128) == 1 and get(state, 424) == 0,
                  "Clock failure erased an acknowledged cancellation read")

    def run(self):
        for name, method in self.CASES:
            self.case_path = self.output / name;self.case_path.mkdir(mode=0o700)
            self.serial = 0;self.receipts = []
            row = {"case": name, "scope": "native policy with synthetic event/state frames",
                   "actual_os_fault_injection": False, "executable_sha256": sha256(self.executable)}
            try:
                getattr(self, method)();row["passed"] = True
            except Exception as exc:
                row.update(passed=False, exception=type(exc).__name__ + ": " + str(exc))
            row["calls"] = self.receipts
            self.rows.append(row);write_json(self.case_path / "result.json", row)
        report = {"schema": "trnm.hia.stream-reactor-policy-contracts.v1",
            "scope": "synthetic acknowledgements executed by actual native HIA; not kernel fault qualification",
            "actual_os_fault_injection": False, "executable_sha256": sha256(self.executable),
            "controls": self.rows, "passed_control_count": sum(row["passed"] for row in self.rows),
            "required_control_count": len(self.rows)}
        write_json(self.output / "report.json", report)
        return report
