"""Run the single-call reviewer: `python reviewer/single_call` or `python -m reviewer.single_call`."""
if not __package__:
    # Run as a folder (the benchmark starts reviewers in an empty temporary folder):
    # put the project root on the import path; no installation is needed.
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from reviewer.run import main

raise SystemExit(main("single-call"))
