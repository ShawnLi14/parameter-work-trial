"""Draft adjudications with TypeSafe AI's Jev decision model.

For each case, Jev sees the reviewer's whole output and the case's known bugs, and
answers one question per finding: which known bug, if any, does it describe? Grading
is by alignment with the known bugs only; Jev does not check the code. Jev writes no
text, so each rationale records its choice and confidence. Answers below the
confidence threshold stay `unresolved` for a person. These are automatic grades:
report them as such and calibrate the threshold against a hand-graded sample.
"""
import json
import os
from pathlib import Path
import urllib.error
import urllib.request

from .catalog import digest
from .scoring import grade_template

API_URL = "https://api.typesafe.ai/v1/systemone"
PROMPT_VERSION = "judge-v2-alignment"
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


def known_bugs(case):
    """Named options: each known bug in the case, plus "none"."""
    named = {}
    for i, label in enumerate(case["labels"], 1):
        named[f"bug_{i}"] = (f"{label['title']}. Mechanism: {label['mechanism']} "
                             f"Location: {label['location_hint']}.")
    for i, item in enumerate(case.get("also_valid", []), 1):
        named[f"extra_{i}"] = item["description"]
    named["none"] = "The finding does not describe any of the bugs above."
    return named


def case_state(case, findings, named):
    bugs = "\n".join(f"- {name}: {text}" for name, text in named.items() if name != "none")
    shown = [{k: f.get(k) for k in ("id", "title", "description", "path", "line", "evidence")} for f in findings]
    return ("A security reviewer reported the findings below for a proposed pull request. Decide, for each "
            "finding, which known bug in this pull request it describes. A finding describes a bug only if "
            "its explanation identifies the same mechanism: the same dangerous operation, how attacker data "
            "reaches it, and the missing defense. Sharing a file, a keyword, or a weakness category is not "
            "enough.\n\nKNOWN BUGS IN THIS PULL REQUEST\n" + (bugs or "(none: this pull request is not known "
            "to introduce a vulnerability)") + "\n\nREVIEWER FINDINGS\n" + json.dumps(shown, indent=1))


def grade(data, results, key=None, threshold=0.7, model="jev-latest", send=call_jev):
    """Return a grades file in the scorer's format, with Jev's answers recorded per decision."""
    if results["catalog_sha256"] != digest(data):
        raise ValueError("results belong to a different catalog")
    key = key or api_key()
    cases = {c["id"]: c for c in data["cases"]}
    decisions, returned_models = [], set()
    for row in results["cases"]:
        if row["status"] != "ok" or not row["output"]["findings"]:
            continue
        case, findings = cases[row["case_id"]], row["output"]["findings"]
        named = known_bugs(case)
        answer = send({"model": model, "state": case_state(case, findings, named), "questions": {
            f["id"]: {"type": "choice", "criteria": named,
                      "instructions": f"Which known bug does finding {f['id']} describe?"} for f in findings}}, key)
        returned_models.add(answer.get("model", model))
        drafts = []
        for f in findings:
            choice = answer["answers"][f["id"]]
            chosen, confidence = choice["choice"], choice["confidence"]
            decision = {"case_id": case["id"], "finding_id": f["id"], "decision": "unresolved", "label_id": None,
                        "judge": {"choice": chosen, "confidence": confidence, "probabilities": choice.get("probabilities")}}
            rationale = f"Automatic: Jev chose {chosen} with confidence {confidence:.2f}."
            if confidence < threshold:
                rationale += " Left unresolved for human review."
            elif chosen.startswith("bug_"):
                decision.update(decision="match", label_id=case["labels"][int(chosen.split("_")[1]) - 1]["id"])
            elif chosen.startswith("extra_"):
                decision.update(decision="also_valid", also_valid_id=case["also_valid"][int(chosen.split("_")[1]) - 1]["id"])
            else:
                decision["decision"] = "false_positive"
            decision["rationale"] = rationale
            drafts.append(decision)
        # One finding can match a bug: the most confident match keeps it, the rest are duplicates.
        best = {}
        for d in drafts:
            if d["decision"] == "match" and (d["label_id"] not in best or d["judge"]["confidence"] > best[d["label_id"]]["judge"]["confidence"]):
                best[d["label_id"]] = d
        for d in drafts:
            if d["decision"] == "match" and best[d["label_id"]] is not d:
                d["decision"] = "duplicate"
                d["rationale"] += " Duplicate of a more confident match for the same bug."
        decisions.extend(drafts)
    template = grade_template(results)
    template["adjudicator"] = f"automatic: Jev ({', '.join(sorted(returned_models)) or model}), {PROMPT_VERSION}, threshold {threshold}"
    template["decisions"] = decisions
    return template
