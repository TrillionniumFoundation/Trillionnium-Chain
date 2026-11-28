"""Original CLI formatting, command selection and error priority."""
from .fixtures import record


def run(suite):
    p = suite.root / "cli"
    p.mkdir(mode=0o700)
    nroot, rroot = p / "native", p / "original"
    cp0 = record()
    cp1 = record(1, predecessor=cp0[640:])
    cp2 = record(2, predecessor=cp1[640:])
    cpfiles = []
    for index, cp in enumerate((cp0, cp1, cp2)):
        path = p / ("cp" + str(index))
        path.write_bytes(cp)
        cpfiles.append(path)
    for args in ([], ["bogus"], ["register-new"], ["reopen", "a", "b"],
                 ["ledger-init", "a", "b", "c"], ["a", "b", "c", "d", "e"]):
        suite.cli("usage-" + str(len(args)) + "-" + (args[0] if args else "empty"), args)
    for size in (0, 671, 673, 2048):
        path = p / ("bad-" + str(size))
        path.write_bytes(bytes(size))
        suite.cli("checkpoint-input-" + str(size), ["ledger-init", nroot, path],
                  ["ledger-init", rroot, path])
    suite.cli("missing-input", ["ledger-init", nroot, p / "absent"],
              ["ledger-init", rroot, p / "absent"])
    for index, (cmd, tail) in enumerate((
        ("ledger-init", cpfiles[:1]), ("ledger-resolve", cpfiles[:2]),
        ("ledger-advance", cpfiles[:2]), ("ledger-advance", cpfiles[:2]),
        ("ledger-resolve", cpfiles[:2]), ("ledger-advance", cpfiles[1:]),
        ("ledger-resolve", cpfiles[:2]), ("ledger-init", cpfiles[:1]),
    )):
        suite.cli(cmd + "-" + str(index), [cmd, nroot, *tail], [cmd, rroot, *tail])
    suite.cli("invalid-target-before-missing-root", ["ledger-resolve", p / "missing", cpfiles[0], cpfiles[2]])
    suite.cli("bad-pin-before-daemon", ["reopen", p / "socket", p / "journal", p / "bad-0"])
    path = p / "pin-link"
    path.symlink_to(cpfiles[0])
    suite.cli("pin-symlink", ["reopen", p / "socket", p / "journal", path])
    suite.cli("relative-client", ["journal-checkpoint", "relative", p / "export"])
