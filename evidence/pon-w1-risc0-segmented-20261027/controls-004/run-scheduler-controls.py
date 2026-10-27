#!/usr/bin/env python3
"""Retain actual short-run scheduler process files before temporary cleanup."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(sys.argv[1]).resolve()))
import test_segment_scheduler
test_segment_scheduler.EVIDENCE_OUT = str(Path(sys.argv[2]).resolve())
unittest.main(module=test_segment_scheduler, argv=[sys.argv[0]], verbosity=2)
