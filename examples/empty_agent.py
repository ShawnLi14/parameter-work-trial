"""Protocol smoke test, NOT a security reviewer. Has zero recall by design."""
import json
import sys

request = json.load(sys.stdin)
assert request["mode"] in {"snapshot","pr"}
print(json.dumps({"findings": []}))
