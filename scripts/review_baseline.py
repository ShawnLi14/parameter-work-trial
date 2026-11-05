"""Absolute-path entry point for benchmark subprocesses with a different cwd."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reviewer.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
