"""Track code actually observed by one investigator, including diff coordinates."""

import re

from .code_access import safe_path


class Evidence:
    def __init__(self, diff):
        self.lines = {}
        self.changed = set()
        self.versions = {}
        base = head = None
        old = new = old_left = new_left = 0
        for line in diff.splitlines():
            if line.startswith("diff --git "):
                base = head = None
                old_left = new_left = 0
            elif old_left or new_left:
                if line.startswith("\\"):
                    continue
                if line.startswith((" ", "-")) and old_left:
                    self._add("base", base, old, line[1:], line.startswith("-"))
                    old += 1
                    old_left -= 1
                if line.startswith((" ", "+")) and new_left:
                    self._add("head", head, new, line[1:], line.startswith("+"))
                    new += 1
                    new_left -= 1
            elif line.startswith("--- "):
                base = self._path(line[4:])
            elif line.startswith("+++ "):
                head = self._path(line[4:])
                for path in (base, head):
                    if path:
                        self.versions[path] = {side: name for side, name in (("base", base), ("head", head)) if name}
            elif line.startswith("@@ "):
                match = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
                if match:
                    old, old_left, new, new_left = (int(match[1]), int(match[2] or 1), int(match[3]), int(match[4] or 1))

    @staticmethod
    def _path(value):
        value = value.split("\t")[0]
        if value == "/dev/null":
            return None
        if value.startswith(("a/", "b/")):
            value = value[2:]
        # Quoted Git paths need unescaping; fail closed instead of inventing locations.
        if value.startswith('"'):
            return None
        try:
            return safe_path(value)
        except ValueError:
            return None

    def _add(self, side, path, number, text, changed=False):
        if path and number > 0:
            key = (side, path, number)
            self.lines.setdefault(key, set()).add(text)
            if changed:
                self.changed.add(key)

    def observe(self, args, result):
        if not isinstance(result, dict) or result.get("error"):
            return
        if isinstance(result.get("lines"), list):
            for number, text in enumerate(result["lines"], result.get("start", args.get("start", 1))):
                if isinstance(text, str):
                    self._add(args["side"], args["path"], number, text)
        for match in result.get("matches", []):
            self._add(args["side"], match["path"], match["line"], match["text"])

    def citations(self, values, required=True):
        if not isinstance(values, list) or (required and not values):
            raise ValueError("Non-empty code citations required")
        keys = set()
        for item in values:
            if not isinstance(item, dict) or type(item.get("line")) is not int:
                raise ValueError("Invalid code citation")
            key = (item.get("side"), item.get("path"), item["line"])
            quote = item.get("quote")
            if not isinstance(quote, str) or not quote.strip() or not any(quote in text for text in self.lines.get(key, ())):
                raise ValueError("Citation does not match observed code")
            keys.add(key)
        return keys
