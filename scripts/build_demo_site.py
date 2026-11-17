#!/usr/bin/env python3
"""Compose the approved demo website from a validated `agentprov demo export`."""
from pathlib import Path
import runpy
import sys

if __name__ == "__main__":
    sys.argv.append("--production")
    source = Path(__file__).resolve().parents[1] / "previews/v1.0-home/build.py"
    runpy.run_path(str(source), run_name="__main__")
