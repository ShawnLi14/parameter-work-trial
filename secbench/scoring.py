"""Scoring uses explicit human/judge adjudications, never substring matching."""
from .catalog import digest
from .runner import validate_output


def grade_template(results):
    return {"results_sha256": digest(results), "adjudicator": "", "decisions": [
        {"case_id": row["case_id"], "finding_id": f["id"], "decision": "unresolved",
         "label_id": None, "rationale": ""}
        for row in results["cases"] if row["status"] == "ok"
        for f in row["output"]["findings"]]}


def score(data, results, grades):
    if results["catalog_sha256"] != digest(data):
        raise ValueError("results belong to a different catalog")
    if grades["results_sha256"] != digest(results):
        raise ValueError("grades belong to different results")
    cases = {c["id"]: c for c in data["cases"]}
    rows = {r["case_id"]: r for r in results["cases"]}
    if len(rows) != len(results["cases"]) or not rows or set(rows) - set(cases):
        raise ValueError("empty, duplicate, or unknown result cases")
    for row in rows.values():
        if row["status"] not in {"ok", "error"}:
            raise ValueError("invalid result status")
        if row["status"] == "ok":
            # Validate without rewriting IDs: hand-edited IDs must not alter matching.
            original = [f.get("id") for f in row["output"]["findings"]]
            validate_output(row["output"])
            if original != [f["id"] for f in row["output"]["findings"]]:
                raise ValueError("invalid finding IDs")
    expected = {(cid, f["id"]) for cid,r in rows.items() if r["status"] == "ok" for f in r["output"]["findings"]}
    decisions = {(d["case_id"], d["finding_id"]):d for d in grades["decisions"]}
    if len(decisions) != len(grades["decisions"]) or set(decisions) != expected:
        raise ValueError("each finding must have exactly one adjudication")
    hits, false_positives, duplicates, unresolved = set(), 0, 0, 0
    for (cid, _), d in decisions.items():
        decision = d["decision"]
        if decision not in {"match", "false_positive", "duplicate", "unresolved"}:
            raise ValueError("unknown adjudication decision")
        if decision != "unresolved" and (not grades.get("adjudicator", "").strip() or not d.get("rationale", "").strip()):
            raise ValueError("resolved decisions require adjudicator and rationale")
        if decision in {"match", "duplicate"}:
            lid = d.get("label_id")
            if lid not in {l["id"] for l in cases[cid]["labels"]}:
                raise ValueError("match or duplicate requires a label from the same case")
            if decision == "match":
                if (cid,lid) in hits:
                    raise ValueError("label credited twice; adjudicate extras as duplicate")
                hits.add((cid,lid))
            else:
                duplicates += 1
        elif decision == "false_positive":
            false_positives += 1
        else:
            unresolved += 1
    for (cid,_), d in decisions.items():
        if d["decision"] == "duplicate" and (cid,d["label_id"]) not in hits:
            raise ValueError("duplicate has no matched finding")
    total = sum(len(cases[cid]["labels"]) for cid in rows)
    tp = len(hits)
    precision = tp / (tp + false_positives + duplicates) if tp + false_positives + duplicates else None
    complete = unresolved == 0
    positive_cases=[cid for cid in rows if cases[cid]["labels"]]
    controls=[cid for cid in rows if not cases[cid]["labels"]]
    alarm_cases={cid for (cid,_),d in decisions.items() if cid in controls and d["decision"] == "false_positive"}
    control_failures=sum(rows[cid]["status"] != "ok" for cid in controls)
    f1_denominator=2*tp+false_positives+duplicates+total-tp
    return {"catalog_sha256": digest(data), "results_sha256": digest(results),
            "scope": "constructed PR regression detection" if any(cases[cid]["mode"] == "pr" for cid in rows) else "advisory-labelled snapshot detection only", "grading_complete": complete,
            "cases": len(rows), "case_ids": sorted(rows), "failed_cases": sum(r["status"] != "ok" for r in rows.values()),
            "target_count": total, "true_positives": tp, "false_negatives": total-tp,
            "adjudicated_false_positives": false_positives, "duplicates": duplicates,
            "unresolved_findings": unresolved, "target_recall": tp / total if total else None,
            "precision": precision if complete else None,
            "f1": 2*tp/f1_denominator if complete and f1_denominator else None,
            "false_positive_rate": None,
            "negative_control_cases":len(controls), "negative_control_failures":control_failures,
            "negative_control_alarm_rate":len(alarm_cases)/len(controls) if controls and complete and not control_failures else None,
            "macro_case_recall": sum(sum(c==cid for c,_ in hits)/len(cases[cid]["labels"]) for cid in positive_cases)/len(positive_cases) if positive_cases else None,
            "notes": ["Recall is a lower bound while adjudication remains unresolved.",
                      "Global false-positive rate is not measured. PR controls test only whether the reviewed change introduces a security issue; unchanged vulnerabilities are excluded.",
                      "Off-label valid findings require a catalog revision and rerun/regrading, not an automatic false-positive label.",
                      "Snapshot labels are advisory-backed. PR validation scope is recorded in the separate validation artifact; no deployed application exploit validation is implied."]}
