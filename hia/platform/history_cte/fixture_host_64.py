"""Separate finite host transport for the 64-row synthetic history fixture."""
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import resource
import sys

spec=spec_from_file_location("history_cte_transport",Path(__file__).with_name("fixture_host.py"))
fixture=module_from_spec(spec)
spec.loader.exec_module(fixture)
SQL=(fixture.SQL[0],"323af866706cd3e8fd497f7766c1cdb37bdecc6bcdf8f85fe54f57823e6f8a34",*fixture.SQL[2:])


def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
    msg=json.load(sys.stdin)
    if set(msg)!={"reader","provider","mode"} or type(msg["mode"]) is not int or not 0<=msg["mode"]<=3:
        raise ValueError("Only the fixed synthetic 64-row fixture modes are supported")
    transport=fixture.transport
    with transport.sealed_library(*msg["reader"]) as reader, transport.sealed_library(*msg["provider"]) as provider:
        print(json.dumps(fixture.drive(reader,provider,msg["mode"],65536,832,SQL)))


if __name__=="__main__":
    main()
