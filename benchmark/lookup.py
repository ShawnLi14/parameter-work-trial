"""Read, search, and list a PR case's code straight from its Git store, without unpacking.

A reviewer names a case and a side ("base" or "head"); it never sees a commit ID or
commit message, both of which could reveal the answer. Changelogs stay hidden here
for the same reason they are left out of diffs.
"""
from pathlib import PurePosixPath

from .pr_history import HIDDEN
from .runner import git

SIDES = ("base", "head")
MAX_LINES = 2000
MAX_MATCHES = 200


def _commit(lock, side):
    if side not in SIDES:
        raise ValueError("side must be base or head")
    return lock["base_commit"] if side == "base" else lock["commit"]


def _path(path):
    """Accept only a plain relative path inside the repository."""
    path = (path or "").strip().strip("/")
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or "\\" in path or ":" in path or path.startswith("-"):
        raise ValueError("path must be relative, with forward slashes, inside the repository")
    return path


def _hidden(path):
    return PurePosixPath(path).name.lower().startswith("changelog")


def read(lock, side, path, start=1, end=None):
    path, commit = _path(path), _commit(lock, side)
    if not path or _hidden(path):
        raise ValueError(f"no such file: {path}")
    try:
        blob = git("-C", lock["store"], "show", f"{commit}:{path}")
    except ValueError:
        raise ValueError(f"no such file: {path}") from None
    if b"\0" in blob[:8000]:
        return {"side": side, "path": path, "binary": True, "bytes": len(blob)}
    lines = blob.decode("utf-8", "replace").splitlines()
    start = max(1, start)
    end = min(len(lines), end or len(lines), start + MAX_LINES - 1)
    return {"side": side, "path": path, "start": start, "end": end, "total_lines": len(lines),
            "truncated": end < len(lines), "lines": lines[start - 1:end]}


def search(lock, side, pattern, path=None, ignore_case=False):
    if not pattern:
        raise ValueError("pattern is required")
    scope = [_path(path)] if path else ["."]
    commit = _commit(lock, side)
    flags = ["-i"] if ignore_case else []
    try:
        out = git("-C", lock["store"], "grep", "-n", "-I", "-E", *flags, "-e", pattern, commit, "--", *scope, *HIDDEN)
    except ValueError as error:
        if str(error):
            raise ValueError(f"search failed: {error}") from None
        out = b""  # git grep exits nonzero with no output when nothing matches.
    matches = []
    for row in out.decode("utf-8", "replace").splitlines():
        # Each row is "<commit>:<path>:<line>:<text>"; the commit is removed before returning.
        _, rest = row.split(":", 1)
        file, number, text = rest.split(":", 2)
        matches.append({"path": file, "line": int(number), "text": text[:400]})
        if len(matches) == MAX_MATCHES:
            break
    return {"side": side, "pattern": pattern, "matches": matches, "truncated": len(matches) == MAX_MATCHES}


def listing(lock, side, path=None):
    path, commit = _path(path), _commit(lock, side)
    target = f"{commit}:{path}" if path else commit
    try:
        out = git("-C", lock["store"], "ls-tree", target)
    except ValueError:
        raise ValueError(f"no such directory: {path}") from None
    entries = []
    for row in out.decode("utf-8", "replace").splitlines():
        meta, name = row.split("\t", 1)
        kind = meta.split()[1]
        if kind == "blob" and _hidden(name):
            continue
        entries.append({"name": name, "type": "dir" if kind == "tree" else "file"})
    return {"side": side, "path": path, "entries": entries}
