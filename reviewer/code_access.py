"""Narrow read-only code access. No model-controlled executables or shell strings."""

import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import threading
from urllib.parse import quote

from .http import request_json

ROOT = Path(__file__).resolve().parents[1]


def pin_pr_base(request, token=None):
    """GitHub PR diffs use the merge base, not the current target-branch tip."""
    pr = request["pr"]
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    comparison = request_json(
        f"https://api.github.com/repos/{pr['repository']}/compare/{pr['base_sha']}...{pr['head_sha']}",
        headers=headers, timeout=60)
    revision = comparison["merge_base_commit"]["sha"]
    if not isinstance(revision, str) or not re.fullmatch(r"[a-fA-F0-9]{40,64}", revision):
        raise ValueError("GitHub did not return a valid merge base")
    pr["base_sha"] = revision


def safe_path(value, allow_empty=False):
    if not isinstance(value, str):
        raise ValueError("path must be a string")
    path = PurePosixPath(value)
    if (not value and not allow_empty) or path.is_absolute() or ".." in path.parts or any(c in value for c in "\\:\0") or value.startswith("-"):
        raise ValueError("path must stay inside the repository")
    if any(p.lower() in {".git", ".env"} or p.lower().startswith((".env.", "changelog")) for p in path.parts):
        raise ValueError("path is excluded from review")
    return value


def validate_action(tool, args):
    if tool not in ("read", "search", "list") or not isinstance(args, dict):
        raise ValueError("unsupported lookup")
    allowed = {"side", "path"} | ({"start", "end"} if tool == "read" else {"pattern"} if tool == "search" else set())
    if set(args) - allowed or args.get("side") not in ("base", "head"):
        raise ValueError("invalid lookup arguments")
    result = {"side": args["side"], "path": safe_path(args.get("path", ""), tool != "read")}
    if tool == "read":
        start = args.get("start", 1)
        end = args.get("end", start + 99) if type(start) is int else None
        if type(start) is not int or type(end) is not int or start < 1 or end < start or end-start >= 200:
            raise ValueError("read requires a positive range of at most 200 lines")
        result.update(start=start, end=end)
    if tool == "search":
        pattern = args.get("pattern")
        if not isinstance(pattern, str) or not pattern.strip() or len(pattern) > 200:
            raise ValueError("search requires a pattern of 1-200 characters")
        result["pattern"] = pattern
    return result


class LookupProblem(ValueError):
    """A lookup failure whose message is safe to show the model."""


def lookup_problem(stderr):
    text = (stderr or "").strip().splitlines()[-1:] or [""]
    text = text[0].removeprefix("benchmark: ")
    # Never pass commit ids or long tool output through to the model.
    text = re.sub(r"\b[0-9a-f]{12,40}\b", "<rev>", text)[:300]
    if "Unmatched" in text or "Invalid" in text and "regular" in text or "-e option" in text:
        return f"Invalid search pattern ({text}); escape regex characters such as ( [ . * for literal text"
    return text or "Lookup failed; narrow or revise the lookup"


class CodeAccess:
    """Cache shared by investigators. Results never include harness labels or commands."""

    def __init__(self, request, github_token=None):
        self.request = request
        self.github_token = github_token
        self.cache = {}
        self.lock = threading.Lock()
        self.command = None
        if request.get("lookup"):
            command = request["lookup"].get("command")
            # Accept the repository's known benchmark protocol, reconstruct its
            # executable ourselves, and never execute an arbitrary supplied command.
            if (not isinstance(command, list) or len(command) != 10
                    or command[1:4] != ["-m", "benchmark", "--catalog"]
                    or command[5:7] != ["lookup", "--work"] or command[8] != "--case"
                    or not all(isinstance(s, str) for s in command)
                    or not re.fullmatch(r"[A-Za-z0-9_-]+", command[9])):
                raise ValueError("unsupported benchmark lookup command")
            self.command = [sys.executable, "-m", "benchmark", "--catalog", str(Path(command[4]).resolve()),
                            "lookup", "--work", str(Path(command[7]).resolve()), "--case", command[9]]

    @property
    def available(self):
        if self.command:
            return "benchmark read/search/list"
        if self.request.get("source_dir") and self.request.get("base_source_dir"):
            return "local tree read/search/list (search is literal)"
        if self.request.get("pr"):
            return "GitHub pinned read/list; search is unavailable"
        return "diff only; repository lookups unavailable"

    def lookup(self, tool, args, timeout=30):
        args = validate_action(tool, args)
        key = json.dumps([tool, args], sort_keys=True)
        # Serialize cache misses to avoid duplicate I/O. Model calls still run concurrently.
        with self.lock:
            if key not in self.cache:
                try:
                    result = self._lookup(tool, args, timeout)
                    if len(json.dumps(result)) > 30_000:
                        result = {"error": "Result exceeds 30000 characters; narrow the lookup", "truncated": True}
                except LookupProblem as error:
                    # A specific, safe reason ("no such file", "invalid regex") lets the model correct itself.
                    result = {"error": str(error)}
                except (ValueError, OSError, subprocess.SubprocessError, KeyError, UnicodeError):
                    result = {"error": "Lookup failed or requested code is unavailable; narrow or revise the lookup"}
                self.cache[key] = result
            # Do not let one investigator mutate another's cached observations.
            return json.loads(json.dumps(self.cache[key]))

    def _lookup(self, tool, args, timeout):
        if self.command:
            extra = [tool]
            for key, value in args.items():
                if value != "":
                    extra.extend(["--"+key, str(value)])
            process = subprocess.run(self.command + extra, cwd=ROOT, capture_output=True,
                                     encoding="utf-8", timeout=timeout, shell=False)
            if process.returncode:
                raise LookupProblem(lookup_problem(process.stderr))
            result = json.loads(process.stdout)
            # Apply the same hidden-path policy to broad search/list observations.
            if tool == "search":
                result["matches"] = [m for m in result.get("matches", []) if self._visible(m["path"])]
            if tool == "list":
                result["entries"] = [e for e in result.get("entries", []) if self._visible(e["name"])]
            return result
        side, path = args["side"], args["path"]
        directory = self.request.get("source_dir" if side == "head" else "base_source_dir")
        if directory:
            root = Path(directory).resolve()
            target = root.joinpath(*PurePosixPath(path).parts)
            # Reject links/junction escapes before every read.
            if not target.resolve().is_relative_to(root) or target.is_symlink():
                raise ValueError("path escapes source tree")
            if tool == "read":
                if target.stat().st_size > 1_000_000:
                    raise ValueError("file too large")
                return self._lines(target.read_bytes(), args)
            if tool == "list":
                entries = []
                for child in sorted(target.iterdir()):
                    try:
                        safe_path(child.relative_to(root).as_posix())
                    except ValueError:
                        continue
                    if child.is_symlink() or not child.resolve().is_relative_to(root):
                        continue
                    entries.append({"name": child.name, "type": "dir" if child.is_dir() else "file"})
                    if len(entries) >= 200:
                        break
                return {"entries": entries, "truncated": len(entries) == 200}
            matches, scanned = [], 0
            paths = [target] if target.is_file() else target.rglob("*")
            for child in paths:
                scanned += 1
                if scanned > 1000 or len(matches) >= 100:
                    break
                try:
                    relative = safe_path(child.relative_to(root).as_posix())
                    if child.is_symlink() or not child.resolve().is_relative_to(root) or not child.is_file() or child.stat().st_size > 1_000_000:
                        continue
                    for number, line in enumerate(child.read_text(encoding="utf-8").splitlines(), 1):
                        if args["pattern"] in line:
                            matches.append({"path": relative, "line": number, "text": line[:400]})
                            if len(matches) == 100:
                                break
                except (ValueError, OSError):
                    continue
            return {"side": side, "matches": matches, "truncated": scanned > 1000 or len(matches) >= 100}
        pr = self.request.get("pr")
        if pr:
            if tool == "search":
                return {"error": "GitHub search cannot be pinned to this revision; use list and read"}
            repository = pr["repository"]
            revision = pr[side+"_sha"]
            if not re.fullmatch(r"[\w.-]+/[\w.-]+", repository) or not re.fullmatch(r"[a-fA-F0-9]{40,64}", revision):
                raise ValueError("invalid GitHub reference")
            headers = {"Accept": "application/vnd.github+json"}
            if self.github_token:
                headers["Authorization"] = "Bearer " + self.github_token
            url = f"https://api.github.com/repos/{repository}/contents/{quote(path, safe='/')}?ref={revision}"
            data = request_json(url, headers=headers, timeout=timeout)
            if tool == "list":
                if not isinstance(data, list):
                    raise ValueError("not a directory")
                entries = []
                for item in data[:200]:
                    try:
                        safe_path(item["path"])
                    except ValueError:
                        continue
                    if item["type"] in ("file", "dir"):
                        entries.append({"name": item["name"], "type": item["type"]})
                return {"entries": entries, "truncated": len(data) > 200}
            if data.get("type") != "file" or data.get("encoding") != "base64" or data.get("size", 0) > 1_000_000:
                raise ValueError("unsupported file")
            import base64
            return self._lines(base64.b64decode(data["content"]), args)
        return {"error": "No repository context configured; only supplied diff is available"}

    @staticmethod
    def _visible(path):
        try:
            safe_path(path)
            return True
        except ValueError:
            return False

    @staticmethod
    def _lines(blob, args):
        if b"\0" in blob:
            return {"binary": True}
        lines = blob.decode("utf-8").splitlines()
        end = min(args["end"], len(lines))
        return {"side": args["side"], "path": args["path"], "start": args["start"], "end": end,
                "total_lines": len(lines), "lines": lines[args["start"]-1:end], "truncated": end < len(lines)}
