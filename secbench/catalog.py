"""Source-backed labels. These are advisory assertions, not executable validation."""
import hashlib
import json
from pathlib import Path

CATALOG = Path(__file__).with_name("data") / "catalog.json"


def load(path=CATALOG):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    validate(data)
    return data


def digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate(data):
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    require(data["schema_version"] == 1, "unsupported catalog schema")
    case_ids, label_ids = set(), set()
    for case in data["cases"]:
        require(case["id"] not in case_ids, "duplicate case")
        case_ids.add(case["id"])
        require(case["split"] in {"dev", "holdout"}, "invalid split")
        require(case["mode"] in {"snapshot","pr"}, "invalid task mode")
        if case["mode"] == "snapshot":
            require(case["validation"] == "advisory_only", "unsupported validation level")
            require(bool(case["labels"]), "missing labels")
        else:
            require(case["validation"] == "function_boundary_checked", "unsupported PR validation")
            require(case["construction"] == "authored_regression", "unsupported PR construction")
            require(case["variant"] in {"regression","safe_edit","preexisting"}, "invalid variant")
            require(bool(case["labels"]) == (case["variant"] == "regression"), "invalid PR expectations")
        for label in case["labels"]:
            require(label["id"] not in label_ids, "duplicate label")
            label_ids.add(label["id"])
            require(bool(label["mechanism"] and label["evidence_required"]), "missing rubric")
            require(label["source"].startswith("https://securitylab.github.com/advisories/"), "invalid source")
            require(label["fix_commit"] is None and label["introducing_commit"] is None, "unverified PR commits")
    groups = {}
    for case in data["cases"]:
        group = case["leakage_group"]
        require(groups.setdefault(group, case["split"]) == case["split"], "related code crosses splits")
