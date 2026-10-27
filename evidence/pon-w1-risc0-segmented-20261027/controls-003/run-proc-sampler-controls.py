#!/usr/bin/env python3
"""Run actual upstream sampler controls and retain their genuine short-run files."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(sys.argv[1]).resolve()))
import test_proc_group_sampler
# Preserve real success/timeout samples before TemporaryDirectory cleanup.
test_proc_group_sampler.EVIDENCE_OUT = str(Path(sys.argv[2]).resolve())
unittest.main(module=test_proc_group_sampler, argv=[sys.argv[0]], verbosity=2)
