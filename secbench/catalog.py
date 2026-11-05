"""Catalog loading and validation.

Two kinds of catalog share this format: the advisory target list in
data/targets.json, whose cases group the 49 targets by repository, and the PR suite
built from it, whose cases are real upstream commit pairs.
"""
import hashlib
import json
from pathlib import Path

TARGETS = Path(__file__).with_name("data") / "targets.json"
HISTORICAL_CONSTRUCTIONS = {"historical_commit_pair", "fix_reverted"}
POSITIVE_VARIANTS = {"introduced_historical", "fix_reverted"}
CONTROL_VARIANTS = {"security_fix", "benign_nearby", "preexisting_touch"}


def load(path=TARGETS):
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
        if case["mode"] == "snapshot":
            # A target group: the advisory targets reported for one repository.
            require(case["validation"] == "advisory_only", "unsupported validation level")
            require(bool(case["labels"]), "missing labels")
        else:
            require(case["mode"] == "pr", "invalid case mode")
            require(case["construction"] in HISTORICAL_CONSTRUCTIONS, "unsupported PR construction")
            require(case["validation"] == "source_reviewed", "unsupported PR validation")
            require(case["variant"] in POSITIVE_VARIANTS | CONTROL_VARIANTS, "invalid variant")
            require(bool(case["labels"]) == (case["variant"] in POSITIVE_VARIANTS), "invalid PR expectations")
        for label in case["labels"]:
            require(label["id"] not in label_ids, "duplicate label")
            label_ids.add(label["id"])
            require(bool(label["mechanism"] and label["evidence_required"]), "missing rubric")
            require(label["source"].startswith("https://securitylab.github.com/advisories/"), "invalid source")
    groups = {}
    for case in data["cases"]:
        group = case["leakage_group"]
        require(groups.setdefault(group, case["split"]) == case["split"], "related code crosses splits")
