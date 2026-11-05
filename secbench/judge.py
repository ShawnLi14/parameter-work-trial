"""Draft adjudications with TypeSafe AI's Jev decision model.

Jev answers typed questions (choices with probabilities) and writes no text, so each
decision's rationale records what Jev chose and how confident it was. Grades it
cannot make confidently stay `unresolved`, which keeps precision and F1 unset rather
than wrong. These are automatic grades: report them as such, and calibrate the
threshold against a hand-graded sample before relying on the scores.
"""
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request

from . import lookup
from .catalog import digest
from .runner import checked_lock

API_URL = "https://api.typesafe.ai/v1/systemone"
PROMPT_VERSION = "judge-v1"
CONTEXT_LINES = 40
MAX_STATE_CHARS = 90_000  # Stays inside Jev's 32k-token context for one question.
ROOT = Path(__file__).resolve().parents[1]


def api_key():
    """JEV_API_KEY from the environment, else from the project's .env file."""
    if os.environ.get("JEV_API_KEY"):
        return os.environ["JEV_API_KEY"]
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8").splitlines():
            name, _, value = line.partition("=")
            if name.strip() == "JEV_API_KEY" and value.strip():
                return value.strip().strip("'\"")
    raise ValueError("JEV_API_KEY is not set in the environment or .env")


def call_jev(payload, key, timeout=60):
    request = urllib.request.Request(API_URL, data=json.dumps(payload).encode(), method="POST", headers={
        "Authorization": "Bearer " + key, "Content-Type": "application/json", "User-Agent": "secbench"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        detail = error.read()[:300].decode("utf-8", "replace").replace(key, "<redacted>")
        raise ValueError(f"Jev request failed with HTTP {error.code}: {detail}") from None


def file_diff(diff, path):
    """The part of a unified diff that changes one file."""
    for part in re.split(r"(?m)^(?=diff --git )", diff):
        if part.startswith(f"diff --git a/{path} ") or f" b/{path}\n" in part.split("\n", 1)[0] + "\n":
            return part
    return ""


def code_at(lock, side, path, line):
    """Numbered lines around a location, or None when the file does not exist on that side."""
    try:
        excerpt = lookup.read(lock, side, path, max(1, line - CONTEXT_LINES), line + CONTEXT_LINES)
    except ValueError:
        return None
    if excerpt.get("binary"):
        return {"text": "(binary file)", "in_range": False}
    numbered = "\n".join(f"{excerpt['start'] + i}: {text}" for i, text in enumerate(excerpt["lines"]))
    return {"text": numbered, "in_range": line <= excerpt["total_lines"]}


def options(case):
    """Named choices for the decision question, with what each one means."""
    named = {}
    for i, label in enumerate(case["labels"], 1):
        named[f"target_{i}"] = (f"The finding identifies this known vulnerability: {label['title']}. "
                                f"Mechanism: {label['mechanism']} Location: {label['location_hint']}.")
    for i, item in enumerate(case.get("also_valid", []), 1):
        named[f"extra_{i}"] = f"The finding identifies this other real issue the diff introduces: {item['description']}"
    named["false_alarm"] = ("The finding does not identify any listed issue, and its claim is unsupported, "
                            "generic, or about code this diff does not make vulnerable.")
    named["other_issue"] = ("The finding plausibly describes a different, real vulnerability that this diff "
                            "introduces, not listed above.")
    return named


def finding_state(case, lock, diff, finding):
    side = finding.get("side") if finding.get("side") in lookup.SIDES else "head"
    location = code_at(lock, side, finding["path"], finding["line"])
    if location is None:
        other = "base" if side == "head" else "head"
        location = code_at(lock, other, finding["path"], finding["line"])
        side = other
    sections = [
        "A security reviewer examined a proposed pull request and reported the finding below. "
        "Decide whether it identifies a vulnerability that this pull request introduces.",
        "FINDING\n" + json.dumps({k: finding.get(k) for k in ("title", "description", "path", "line", "evidence")}, indent=1),
        "CHANGES TO THE CITED FILE IN THIS PULL REQUEST\n" + (file_diff(diff, finding["path"]) or "(this pull request does not change the cited file)"),
        f"CODE AROUND THE CITED LINE ({side} side; base is before the change, head is after)\n" + (location["text"] if location else "(the cited file does not exist on either side)"),
    ]
    state = "\n\n".join(sections)
    if len(state) > MAX_STATE_CHARS:
        state = state[:MAX_STATE_CHARS] + "\n(truncated)"
    return state, location


def grade(data, results, work, key=None, threshold=0.7, model="jev-latest", send=call_jev):
    """Return a grades file in the scorer's format, with Jev's answers recorded per decision."""
    if results["catalog_sha256"] != digest(data):
        raise ValueError("results belong to a different catalog")
    key = key or api_key()
    cases = {c["id"]: c for c in data["cases"]}
    decisions, returned_models = [], set()
    for row in results["cases"]:
        if row["status"] != "ok" or not row["output"]["findings"]:
            continue
        case = cases[row["case_id"]]
        lock = checked_lock(data, case, work)
        diff = (Path(work) / "diffs" / (case["id"] + ".patch")).read_text(encoding="utf-8")
        named = options(case)
        drafts = []
        for finding in row["output"]["findings"]:
            decision = {"case_id": case["id"], "finding_id": finding["id"], "decision": "unresolved",
                        "label_id": None, "rationale": ""}
            state, location = finding_state(case, lock, diff, finding)
            if location is None:
                decision.update(decision="false_positive",
                                rationale=f"Automatic check: {finding['path']} does not exist on either side of this PR.")
                decisions.append(decision)
                continue
            answer = send({"model": model, "state": state, "questions": {
                "decision": {"type": "choice", "instructions": "Which statement best describes the finding?", "criteria": named},
                "supported": {"type": "noul", "instructions": (
                    "Does the code shown support the finding's specific claim: the dangerous operation, how "
                    "attacker-controlled data reaches it, and the missing defense?")}}}, key)
            returned_models.add(answer.get("model", model))
            choice = answer["answers"]["decision"]
            supported = answer["answers"]["supported"]["noul"]
            chosen, confidence = choice["choice"], choice["confidence"]
            decision["judge"] = {"choice": chosen, "confidence": confidence, "supported": supported,
                                 "probabilities": choice.get("probabilities"), "line_in_range": location["in_range"]}
            summary = f"Jev chose {chosen} with confidence {confidence:.2f}; claim supported by code p={supported:.2f}."
            confident = confidence >= threshold
            if chosen.startswith("target_") and confident and supported >= 0.5:
                label = case["labels"][int(chosen.split("_")[1]) - 1]
                decision.update(decision="match", label_id=label["id"])
            elif chosen.startswith("extra_") and confident and supported >= 0.5:
                decision.update(decision="also_valid", also_valid_id=case["also_valid"][int(chosen.split("_")[1]) - 1]["id"])
            elif chosen == "false_alarm" and confident:
                decision.update(decision="false_positive")
            else:
                summary += " Left unresolved for human review."
            decision["rationale"] = "Automatic: " + summary
            drafts.append(decision)
        # One finding can match a target: the most confident match keeps it, the rest are duplicates.
        best = {}
        for d in drafts:
            if d["decision"] == "match":
                key_ = d["label_id"]
                if key_ not in best or d["judge"]["confidence"] > best[key_]["judge"]["confidence"]:
                    best[key_] = d
        for d in drafts:
            if d["decision"] == "match" and best[d["label_id"]] is not d:
                d["decision"] = "duplicate"
                d["rationale"] += " Duplicate of a more confident match for the same target."
        decisions.extend(drafts)
    from .scoring import grade_template
    template = grade_template(results)
    template["adjudicator"] = f"automatic: Jev ({', '.join(sorted(returned_models)) or model}), {PROMPT_VERSION}, threshold {threshold}"
    template["decisions"] = decisions
    return template
