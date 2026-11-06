"""Run the find-verify reviewer: `python reviewer/find_verify` or `python -m reviewer.find_verify`."""
if not __package__:
    # Run as a folder (the benchmark starts reviewers in an empty temporary folder):
    # put the project root on the import path; no installation is needed.
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from reviewer.run import main

raise SystemExit(main("find-verify"))
