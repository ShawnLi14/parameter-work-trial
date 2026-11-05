"""Run as `python -m reviewer`, or as `python path/to/reviewer` from any folder.

The benchmark starts each reviewer in an empty temporary folder, so the second form
puts the project root on the import path itself; no installation is needed.
"""
if __package__:
    from .cli import main
else:
    import sys
    from pathlib import Path

    # Python put this folder first on the path, where reviewer/http.py would shadow the
    # standard library's http module. Replace it with the project root.
    here = Path(__file__).resolve().parent
    sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != here]
    sys.path.insert(0, str(here.parent))
    from reviewer.cli import main

raise SystemExit(main())
