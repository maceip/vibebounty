#!/usr/bin/env python3
"""Shim — implementation moved to emberglass-tune."""
import runpy
from pathlib import Path

import emberglass_tune

runpy.run_path(str(Path(emberglass_tune.__file__).parent / "env_check.py"), run_name="__main__")
