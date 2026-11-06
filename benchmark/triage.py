"""Attribute each benchmark failure to the find-verify stage that caused it.

Every labelled bug ends in one of these stages:
  found              a confirmed finding matched it
  verifier_rejected  a hunter proposed it, the verifier rejected it
  verifier_uncertain a hunter proposed it, the verifier could not decide
  unverified         a hunter proposed it, but it was over the candidate cap
  not_proposed       no hunter proposed it
Every false finding is a verifier_confirmed_false: a hunter proposed it and the verifier
wrongly confirmed it. Rejected candidates are never graded by the scorer, so triage asks
Jev to match all candidates (not only findings) against the labels.
"""

from .judge import grade


def finding_key(item):
    return (item["path"], item["line"], item.get("side", "head"), item["title"].strip())


def triage(data, results, grades, key=None, send=None):
    cases = {c["id"]: c for c in data["cases"]}
    rows = [r for r in results["cases"] if r["status"] == "ok" and "candidates" in r["output"]]
    # Grade every candidate as if it were a finding.
    pseudo = {**results, "cases": [{"case_id": r["case_id"], "status": "ok", "output": {"findings": [
        {**c, "evidence": [c["description"][:300]]} for c in r["output"]["candidates"]]}} for r in rows]}
    candidate_grades = grade(data, pseudo, key=key, **({"send": send} if send else {}))
    by_candidate = {(d["case_id"], d["finding_id"]): d for d in candidate_grades["decisions"]}
    by_finding = {(d["case_id"], d["finding_id"]): d for d in grades["decisions"]}

    bugs, false_findings, hunters = [], [], {}
    for row in rows:
        case, out = cases[row["case_id"]], row["output"]
        verdicts = {v["candidate"]["id"]: v for v in out.get("verifications", [])}
        unverified = {c["id"] for c in out.get("unverified", [])}
        candidates = {c["id"]: c for c in out["candidates"]}
        matched = {}  # label id -> candidate ids Jev matched to it
        for cid, candidate in candidates.items():
            d = by_candidate.get((row["case_id"], cid), {})
            stats = hunters.setdefault(candidate.get("source", "finder"), {"candidates": 0, "matched_labels": 0, "confirmed": 0})
            stats["candidates"] += 1
            stats["confirmed"] += verdicts.get(cid, {}).get("verdict") == "confirmed"
            if d.get("decision") in ("match", "duplicate") and d.get("label_id"):
                matched.setdefault(d["label_id"], []).append(cid)
                stats["matched_labels"] += d["decision"] == "match"
        found = {d["label_id"] for (c, _), d in by_finding.items() if c == row["case_id"] and d["decision"] == "match"}
        for label in case["labels"]:
            ids = matched.get(label["id"], [])
            if label["id"] in found:
                stage = "found"
            elif not ids:
                stage = "not_proposed"
            elif any(verdicts.get(i, {}).get("verdict") == "rejected" for i in ids):
                stage = "verifier_rejected"
            elif any(i in unverified for i in ids):
                stage = "unverified"
            else:
                stage = "verifier_uncertain"
            bugs.append({"case_id": case["id"], "split": case["split"], "label_id": label["id"], "title": label["title"],
                         "mechanism": label["mechanism"], "location_hint": label["location_hint"], "stage": stage,
                         "proposed_by": sorted({candidates[i].get("source", "finder") for i in ids}),
                         "verifier_reasons": [verdicts[i]["reason"] for i in ids if i in verdicts and stage != "found"]})
        index = {finding_key(v["candidate"]): v for v in out.get("verifications", [])}
        for f in out["findings"]:
            d = by_finding.get((row["case_id"], f["id"]))
            if d and d["decision"] == "false_positive":
                v = index.get(finding_key(f), {})
                false_findings.append({"case_id": case["id"], "split": case["split"], "variant": case.get("variant"),
                                       "finding_id": f["id"], "title": f["title"], "path": f["path"], "line": f["line"],
                                       "proposed_by": v.get("candidate", {}).get("source", "finder"),
                                       "description": f["description"], "evidence": f["evidence"]})
    summary = {}
    for item in bugs:
        split = summary.setdefault(item["split"], {})
        split[item["stage"]] = split.get(item["stage"], 0) + 1
    for item in false_findings:
        split = summary.setdefault(item["split"], {})
        split["verifier_confirmed_false"] = split.get("verifier_confirmed_false", 0) + 1
    return {"summary": summary, "hunters": hunters, "bugs": bugs, "false_findings": false_findings,
            "candidate_grades": candidate_grades}
