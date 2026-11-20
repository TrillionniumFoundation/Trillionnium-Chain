"""Real Unix clients, production daemons, elapsed budgets and listener custody.

Synthetic peers below only provide adversarial test bytes. Actual checkpoint
loads, CAS, lease checks and recovery execute in the native/original binaries.
"""
from pathlib import Path
import os
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time

from .fixtures import record
from .qualification_support import API, identity, need, save


def frame(body):
    return struct.pack(">I", len(body)) + body


def cas(source, target):
    return struct.pack("<Q", source is not None) + (bytes(672) if source is None else source) + target


def exact(stream, n):
    result = bytearray()
    while len(result) < n:
        part = stream.recv(n - len(result))
        if not part:
            return bytes(result)
        result.extend(part)
    return bytes(result)


def wire(path, payload, *, shutdown=False, timeout=8):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(timeout)
        stream.connect(os.fspath(path))
        stream.sendall(payload)
        if shutdown:
            stream.shutdown(socket.SHUT_WR)
        output = bytearray()
        while True:
            part = stream.recv(8192)
            if not part:
                return bytes(output)
            output.extend(part)


class Server:
    def __init__(self, suite, kind, directory, *, pin=None, socket_path=None):
        self.suite, self.kind, self.closed = suite, kind, False
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, exist_ok=True)
        self.socket = Path(socket_path) if socket_path is not None else self.directory / "s"
        self.log = self.directory / "j"
        need(len(bytes(self.socket)) < 108, "The Unix test fixture path exceeds the original address limit")
        self.evidence = suite.output / ("daemon-" + str(len(suite.processes)))
        self.evidence.mkdir(mode=0o700)
        self.executable = suite.native / "trnm-external-node-checkpoint-v2" if kind == "native" else suite.original_cli
        self.before = identity(self.executable.read_bytes())
        args = [str(self.executable), "register-new", str(self.socket), str(self.log)]
        if pin is not None:
            custody = self.evidence / "independent-pin.raw"
            custody.write_bytes(pin)
            args = [str(self.executable), "reopen", str(self.socket), str(self.log), str(custody)]
        self.argv = args
        self.out, self.err = (self.evidence / "stdout.raw").open("xb"), (self.evidence / "stderr.raw").open("xb")
        self.start = time.monotonic_ns()
        self.p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=self.out, stderr=self.err,
                                  start_new_session=True)
        suite.processes.append(self)
        end = time.monotonic() + 8
        while time.monotonic() < end:
            need(self.p.poll() is None, ("Daemon exited before readiness", kind, self.p.returncode,
                                        (self.evidence / "stderr.raw").read_bytes().hex()))
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.settimeout(.2)
            try:
                probe.connect(str(self.socket))
                return
            except (FileNotFoundError, ConnectionRefusedError):
                time.sleep(.01)
            finally:
                probe.close()
        raise AssertionError("Daemon readiness deadline")

    def close(self, *, require_success=True):
        if self.closed:
            return
        self.closed = True
        cleanup = None
        if self.p.poll() is None:
            os.killpg(self.p.pid, signal.SIGKILL)
            self.p.wait(timeout=3)
            cleanup = {"signal": "SIGKILL", "intentional_daemon_stop": True}
        self.out.close()
        self.err.close()
        row = {"argv": self.argv, "executable": self.before, "exit_code": self.p.returncode,
               "cleanup": cleanup, "elapsed_ns": time.monotonic_ns() - self.start,
               "stdout": identity((self.evidence / "stdout.raw").read_bytes()),
               "stderr": identity((self.evidence / "stderr.raw").read_bytes())}
        save(self.evidence / "receipt.json", row)
        need(identity(self.executable.read_bytes()) == self.before, "Daemon executable changed")


class Responder:
    """One fresh bounded peer; every scheduled send and received request is kept."""
    def __init__(self, path, schedule, *, count=2):
        self.path, self.schedule, self.count = Path(path), schedule, count
        self.rows, self.errors = [], []
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path))
        self.listener.listen(4)
        self.listener.settimeout(4)
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        try:
            for _ in range(self.count):
                stream, _ = self.listener.accept()
                with stream:
                    stream.settimeout(3)
                    head = exact(stream, 4)
                    body = exact(stream, int.from_bytes(head, "big")) if len(head) == 4 else b""
                    row = {"request_hex": (head + body).hex(), "sends": []}
                    self.rows.append(row)
                    started = time.monotonic()
                    for after, data in self.schedule:
                        delay = started + after - time.monotonic()
                        if delay > 0:
                            time.sleep(delay)
                        entry = {"scheduled_seconds": after, "elapsed_seconds": time.monotonic() - started,
                                 "data_hex": data.hex()}
                        row["sends"].append(entry)
                        try:
                            stream.sendall(data)
                            entry["result"] = "sent"
                        except (BrokenPipeError, ConnectionResetError) as error:
                            entry["result"] = type(error).__name__
                            break
        except BaseException as error:
            self.errors.append(repr(error))
        finally:
            self.listener.close()

    def close(self, suite, label):
        self.thread.join(timeout=5)
        need(not self.thread.is_alive() and not self.errors, ("Adversarial peer incomplete", self.errors))
        suite.emit({"kind": "adversarial-peer", "case": label, "status": "PASS", "sessions": self.rows})
        self.path.unlink()


def run(suite):
    cp0 = record()
    cp1 = record(1, predecessor=cp0[640:])
    cp2 = record(2, predecessor=cp1[640:])
    with tempfile.TemporaryDirectory(prefix="hcs-") as short:
        root = Path(short)
        terminal = []
        for kind in ("native", "original"):
            server = Server(suite, kind, root / kind)
            p = suite.pair("unix-" + kind)
            actions = []
            def mixed(api, op, body):
                result = api.call(op, body)
                actions.append({"process": api.path.relative_to(suite.output).as_posix(),
                                "call": api.calls, "op": op, "input": body.hex(),
                                "header": result[0], "body": result[1].hex()})
                return result
            p.call(30, bytes(server.socket))
            p.call(31, struct.pack("<QQ", 2, 0))
            p.call(32)
            need(p.call(34, cp0[16:48])[1] == bytes(8), "New server load was not absent")
            need(mixed(p.b, 35, cas(None, cp0))[0][0] == 0, "Original client CAS failed")
            need(p.call(36, cp0[16:48])[1] == struct.pack("<Q", 1) + cp0, "Trait load differs")
            p.call(35, cas(None, cp0), label="checked-compare-failed")
            p.call(37, cas(None, cp0), label="trait-compare-failed")
            need(mixed(p.a, 35, cas(cp0, cp1))[0][0] == 0, "Native checked CAS failed")
            need(mixed(p.b, 37, cas(cp1, cp2))[0][0] == 0, "Original trait CAS failed")
            fresh = record(scope=bytes([17]) * 32, watermark_scope=bytes([17]) * 32)
            need(mixed(p.a, 37, cas(None, fresh))[0][0] == 0, "Native trait CAS failed")
            need(p.call(34, cp0[16:48])[1] == struct.pack("<Q", 1) + cp2, "Advanced value differs")
            p.call(34, bytes(32), label="checked-zero-scope")
            p.call(36, bytes(32), label="trait-zero-scope")
            pin = p.call(33)[1]
            need(int.from_bytes(pin[12:20], "big") == 4, "Cross-scope daemon pin differs")
            a, b = server.directory / "export-native", server.directory / "export-original"
            suite.cli("live-export-" + kind, ["journal-checkpoint", server.socket, a],
                      ["journal-checkpoint", server.socket, b])
            need(a.read_bytes() == b.read_bytes() == pin, "CLI exported pin differs")
            suite.cli("exclusive-live-export-" + kind, ["journal-checkpoint", server.socket, a],
                      ["journal-checkpoint", server.socket, b])
            malformed = [(bytes(4), b""), (struct.pack(">I", 4097), b""),
                         (frame(b"x"), frame(b"CP2S\2\7\0\0")),
                         (frame(b"x" * 4096), frame(b"CP2S\2\7\0\0")),
                         (b"\0\0", b""), (struct.pack(">I", 10) + b"partial", b"")]
            for index, (payload, expected) in enumerate(malformed):
                response = wire(server.socket, payload, shutdown=True)
                suite.emit({"kind": "daemon-wire", "case": kind + "-malformed-" + str(index),
                            "daemon": server.evidence.relative_to(suite.output).as_posix(),
                            "request_hex": payload.hex(), "response_hex": response.hex(),
                            "status": "PASS" if response == expected else "FAIL"})
                need(response == expected, ("Malformed daemon frame", kind, index, response.hex()))
            # Header and body together get five seconds, regardless of partial
            # progress. The actual native/original daemon closes the connection.
            started = time.monotonic()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                stream.settimeout(8)
                stream.connect(str(server.socket))
                stream.sendall(struct.pack(">I", 10))
                for _ in range(3):
                    time.sleep(1)
                    stream.sendall(b"x")
                response = stream.recv(64)
            elapsed = time.monotonic() - started
            suite.emit({"kind": "daemon-deadline", "case": kind, "elapsed_seconds": elapsed,
                        "daemon": server.evidence.relative_to(suite.output).as_posix(),
                        "response_hex": response.hex(), "status": "PASS" if 4.5 <= elapsed < 7.5 and not response else "FAIL"})
            need(4.5 <= elapsed < 7.5 and not response, "Daemon restarted its per-frame elapsed budget")
            need(p.call(33)[1] == pin, "Malformed client poisoned an intact daemon")
            server.close()
            server = Server(suite, kind, server.directory, pin=pin)
            need(p.call(33)[1] == pin, "Pinned cold restart differs")
            terminal.append((server.log.read_bytes(), (server.directory / ".j.head-v2").read_bytes(), pin))
            with server.log.open("r+b") as stream:
                stream.truncate(1461)
                stream.flush()
                os.fsync(stream.fileno())
            # The first request gets InvalidState; the daemon then terminates.
            result = p.a.call(34, cp0[16:48])
            need(result[0][0] == 1 and b"unexpected load response" in result[1], "Live rollback returned a cached value")
            server.p.wait(timeout=5)
            need(server.p.returncode == 1, "Corrupt journal did not terminate daemon")
            suite.emit({"kind": "daemon-live-rollback", "case": kind,
                        "result": {"header": result[0], "body": result[1].hex()},
                        "process": p.a.path.relative_to(suite.output).as_posix(),
                        "call": p.a.calls, "mixed_client_actions": actions,
                        "daemon": server.evidence.relative_to(suite.output).as_posix(),
                        "exit_code": server.p.returncode, "status": "PASS"})
            server.close()
            p.call(34, cp0[16:48], label="checked-unavailable")
            p.call(36, cp0[16:48], label="trait-unavailable")
            p.call(38)
            p.close()
        need(terminal[0] == terminal[1], "Mixed clients produced different durable journals")

        # Every closed response family, malformed frame and trait mapping.
        p = suite.pair("scripted-client")
        path = root / "peer"
        p.call(30, bytes(path))
        for tag in range(1, 9):
            body = b"CP2S\2" + bytes([tag]) + b"\0\0" + (cp0 if tag == 1 else b"")
            for op in (34, 35, 36, 37):
                peer = Responder(path, [(0, frame(body))])
                p.call(op, cp0[16:48] if op in (34, 36) else cas(None, cp0), label="response-" + str(tag))
                peer.close(suite, "response-" + str(tag) + "-" + str(op))
        for index, raw in enumerate((b"", b"\0", bytes(4), struct.pack(">I", 4097),
                                     frame(b"x"), frame(b"CP2S\2\2\1\0"),
                                     frame(b"CP2S\2\1\0\0" + bytes(672)))):
            peer = Responder(path, [(0, raw)])
            p.call(34, cp0[16:48], label="malformed-response-" + str(index))
            peer.close(suite, "malformed-response-" + str(index))
        for index, raw in enumerate((frame(b"CJ1S\1\1\0\0" + terminal[0][2]),
                                     frame(b"CJ1S\1\1\0\0" + bytes(84)),
                                     frame(b"CP2S\2\2\0\0"))):
            peer = Responder(path, [(0, raw)])
            p.call(33, label="pin-response-" + str(index))
            peer.close(suite, "pin-response-" + str(index))
        for seconds, nanos, label, schedule in (
            (0, 0, "zero-timeout", []),
            ((1 << 64) - 1, 999_999_999, "duration-max", [(0, frame(b"CP2S\2\2\0\0"))]),
            (0, 200_000_000, "partial-deadline", [(0, struct.pack(">I", 8)), (.12, b"C"), (.35, b"P2S\2\2\0\0")]),
        ):
            p.call(31, struct.pack("<QQ", seconds, nanos))
            peer = Responder(path, schedule)
            value = p.call(34, cp0[16:48], label=label)
            if label == "partial-deadline":
                need(value[0][0] == 1 and all(.17 < ns / 1e9 < .32 for ns in (p.a.last_elapsed_ns, p.b.last_elapsed_ns)),
                     "Client restarted partial read budget")
            peer.close(suite, label)
        p.call(38)
        for pathbytes in (bytes(root / "missing"), bytes(root) + b"/nul\0tail", b"/" + b"x" * 108):
            p.call(30, pathbytes)
            p.call(31, bytes(16))
            p.call(34, cp0[16:48], label="connect-before-timeout")
            p.call(36, cp0[16:48], label="connect-trait-mapping")
            p.call(38)
        p.close()

        for kind in ("native", "original"):
            server = Server(suite, kind, root / ("lease-" + kind))
            socket_before = server.socket.lstat()
            lease = server.directory / ".s.socket-owner-v1"
            saved = lease.read_bytes()
            # The retained lock, and then a copied unlocked lease inode, must
            # both refuse removal of the still reachable listener.
            for copied in (False, True):
                if copied:
                    lease.rename(server.directory / "old-lease")
                    lease.write_bytes(saved)
                    lease.chmod(0o600)
                args = []
                for side in ("native", "original"):
                    q = root / (kind + "-" + side + "-" + str(copied))
                    q.mkdir(mode=0o700)
                    args.append(["register-new", server.socket, q / "j"])
                result = suite.cli("live-lease-" + kind + "-" + str(copied), *args)
                need(result["exit"] == 1 and b"lock checkpoint socket owner" in bytes.fromhex(result["stderr"]),
                     "Live listener probe was admitted")
                current = server.socket.lstat()
                need((socket_before.st_dev, socket_before.st_ino) == (current.st_dev, current.st_ino)
                     and lease.read_bytes() == saved and server.p.poll() is None,
                     "Connect-only probe changed or fenced live owner")
            response = wire(server.socket, frame(b"x"))
            server.p.wait(timeout=5)
            need(not response and server.p.returncode == 1, "Complete frame did not validate retained lease inode")
            server.close()
            # Copied lease bytes authorize only the now-dead matching socket.
            q = root / ("stale-" + kind)
            recovered = Server(suite, kind, q, socket_path=server.socket)
            recovered.close()

        # A saturated live queue is not ECONNREFUSED. The original bounded
        # nonblocking probe and native probe must preserve its exact inode.
        saturated_results = []
        for kind in ("native", "original"):
            q = root / ("saturated-" + kind)
            q.mkdir(mode=0o700)
            path = q / "s"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            path.chmod(0o600)
            listener.listen(0)
            info = path.lstat()
            record_bytes = b"TRNMCSL1" + struct.pack(">QQIIQqq", info.st_dev, info.st_ino, info.st_uid,
                                                      info.st_mode & 0o7777, info.st_nlink,
                                                      info.st_ctime_ns // 1_000_000_000,
                                                      info.st_ctime_ns % 1_000_000_000)
            lease = q / ".s.socket-owner-v1"
            lease.write_bytes(record_bytes)
            lease.chmod(0o600)
            queued = []
            saturated = False
            try:
                for _ in range(64):
                    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    stream.setblocking(False)
                    try:
                        stream.connect(str(path))
                        queued.append(stream)
                    except BlockingIOError:
                        stream.close()
                        saturated = True
                        break
                need(saturated, "Fixture did not observe actual Unix queue saturation")
                contender = q / "contender"
                contender.mkdir(mode=0o700)
                value = suite.cli_one(kind, ["register-new", path, contender / "j"], "saturated-lease")
                saturated_results.append(value)
                need(value["exit"] == 1 and b"lock checkpoint socket owner" in bytes.fromhex(value["stderr"]),
                     "Saturated owner was replaced")
                current = path.lstat()
                need(current.st_ino == info.st_ino and lease.read_bytes() == record_bytes,
                     "Saturated listener or lease was mutated")
                suite.emit({"kind": "saturated-lease", "case": kind, "result": value,
                            "process": suite.last_cli_path,
                            "queued_connections": len(queued), "status": "PASS"})
            finally:
                for stream in queued:
                    stream.close()
                listener.close()
            recovered = Server(suite, kind, q / "recovered", socket_path=path)
            recovered.close()
        need(saturated_results[0] == saturated_results[1], "Native/original saturated lease errors differ")
