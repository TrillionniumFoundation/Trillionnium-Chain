"""Bounded local systemd transport for fresh PN4 namespace preparation only.

Calling this transport is an effect. Importing it never calls the manager.
The original Python owner retains uncertain requests; no StopUnit/rollback API
exists here. Host administrators and the unrestricted host user are trusted.
"""
import json
import os
import re
import selectors
import stat
import subprocess
from time import monotonic

import llm_runtime_kernel_owned as kernel

MANAGER = '/org/freedesktop/systemd1'
INTERFACE = 'org.freedesktop.systemd1.Manager'
UNIT_INTERFACE = 'org.freedesktop.systemd1.Unit'
SCOPE_INTERFACE = 'org.freedesktop.systemd1.Scope'
_BOUND = 65536


def checked_data(raw, signature, property_value=False):
    kernel.require(type(raw) is bytes and len(raw) <= _BOUND, 'host-bus-response-bound')
    value = json.loads(raw)
    kernel.require(type(value) is dict and set(value) == {'type', 'data'} and
                   value['type'] == signature, 'host-bus-response-type')
    data = value['data']
    if not property_value:
        kernel.require(type(data) is list and len(data) == 1, 'host-bus-response-type')
        data = data[0]
    # busctl serializes a method's result tuple, but get-property serializes the
    # property's value itself. In particular ay is not a one-element list.
    kinds = {'s': str, 'o': str, 'b': bool, 't': int, 'ay': list, 'as': list}
    kernel.require(signature in kinds and type(data) is kinds[signature], 'host-bus-value-type')
    return data


def _command(arguments):
    # Read both pipes as bounded byte buffers. A transport timeout is UNKNOWN:
    # killing this busctl client never cancels a possible manager-side effect.
    kernel.require(type(arguments) is list and 1 <= len(arguments) <= 128 and
        all(type(x) is str and len(x) <= 256 for x in arguments), 'host-bus-arguments')
    with subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}) as child:
        deadline = monotonic()+2
        output = {child.stdout: bytearray(), child.stderr: bytearray()}
        with selectors.DefaultSelector() as selector:
            for stream in output:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            try:
                while selector.get_map():
                    remaining = deadline-monotonic()
                    kernel.require(remaining > 0, 'host-bus-timeout-unknown')
                    for key, _ in selector.select(min(remaining, .05)):
                        buffer = output[key.fileobj]
                        part = os.read(key.fd, min(8192, _BOUND+1-len(buffer)))
                        if part:
                            buffer.extend(part)
                            kernel.require(len(buffer) <= _BOUND, 'host-bus-output-bound-unknown')
                        else:
                            selector.unregister(key.fileobj)
                child.wait(timeout=max(.001, deadline-monotonic()))
                kernel.require(child.returncode == 0, 'host-bus-request-refused-or-unknown')
                return bytes(output[child.stdout])
            except BaseException:
                if child.poll() is None:
                    child.kill()  # Only this transport child, never C/A/native CI.
                child.wait()
                raise


class UserManager:
    def __init__(self):
        self.address = 'unix:path=/run/user/'+str(os.geteuid())+'/bus'
        value = os.stat('/run/user/'+str(os.geteuid())+'/bus', follow_symlinks=False)
        kernel.require(stat.S_ISSOCK(value.st_mode) and value.st_uid == os.geteuid(),
                       'host-user-bus-owner')
        self.socket = (value.st_dev, value.st_ino, value.st_mode, value.st_uid)
        self.owner = self._name_owner()

    def _run(self, args):
        return _command(['/usr/bin/busctl', '--address='+self.address,
                         '--timeout=2', '--json=short', *args])

    def _name_owner(self):
        value = checked_data(self._run(['call', 'org.freedesktop.DBus',
            '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetNameOwner', 's',
            'org.freedesktop.systemd1']), 's')
        kernel.require(type(value) is str and re.fullmatch(r':[0-9]+\.[0-9]+', value),
                       'host-manager-unique-name')
        return value

    def verify(self):
        value = os.stat('/run/user/'+str(os.geteuid())+'/bus', follow_symlinks=False)
        kernel.require((value.st_dev, value.st_ino, value.st_mode, value.st_uid) == self.socket
            and self._name_owner() == self.owner, 'host-manager-replaced')

    def call(self, method, signature, arguments, result_type):
        kernel.require(method in ('StartTransientUnit', 'GetUnit'), 'host-manager-method')
        self.verify()
        value = checked_data(self._run(['call', self.owner, MANAGER, INTERFACE,
            method, signature, *arguments]), result_type)
        self.verify()
        return value

    def property(self, unit_path, interface, name, signature):
        kernel.require(re.fullmatch(r'/org/freedesktop/systemd1/unit/[A-Za-z0-9_]+', unit_path)
            and interface in (UNIT_INTERFACE, SCOPE_INTERFACE), 'host-manager-property-path')
        return checked_data(self._run(['get-property', self.owner, unit_path,
            interface, name]), signature, property_value=True)


def scope_request(unit, pid):
    kernel.require(type(pid) is int and 0 < pid < 2**31 and type(unit) is str and
        re.fullmatch(r'trnm-host-[0-9a-f]{32}\.scope', unit), 'host-original-scope-request')
    # DelegateControllers (rather than Delegate=true, which means all supported
    # controllers) is a writable systemd 255 property for scopes and services.
    properties = [
        ('PIDs', 'au', ['1', str(pid)]),
        ('DelegateControllers', 'as', ['3', 'cpu', 'memory', 'pids']),
        ('CPUAccounting', 'b', ['true']), ('MemoryAccounting', 'b', ['true']),
        ('TasksAccounting', 'b', ['true']),
        ('MemoryMax', 't', [str(17*1024**3)]), ('MemorySwapMax', 't', ['0']),
        ('CPUQuotaPerSecUSec', 't', ['5000000']),
        ('CPUQuotaPeriodUSec', 't', ['100000']), ('TasksMax', 't', ['272']),
    ]
    args = [unit, 'fail', str(len(properties))]
    for name, signature, values in properties:
        args.extend([name, signature, *values])
    return args+['0']  # Empty auxiliary-unit array, not a helper participant.
