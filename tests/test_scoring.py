import copy
import unittest

from benchmark.catalog import digest, load
from benchmark.runner import validate_output
from benchmark.scoring import grade_template, score


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.data = load()
        self.case = self.data["cases"][0]
        self.results = {"schema_version":1,"catalog_sha256":digest(self.data),"cases":[
            {"case_id":self.case["id"],"status":"ok","output":validate_output({"findings":[
                {"title":"Read outside root","description":"User path reaches file read", "path":"src/index.ts","line":1,"evidence":["src/index.ts:1 path not checked"]}
            ]})}]}

    def grades(self, decision="match"):
        g = grade_template(self.results)
        g["adjudicator"] = "test reviewer"
        g["decisions"][0].update(decision=decision,label_id=self.case["labels"][0]["id"],rationale="Mechanism and evidence checked")
        return g

    def test_catalog_and_leakage_groups(self):
        self.assertEqual(6,len(self.data["cases"]))
        self.assertEqual(49,sum(len(c["labels"]) for c in self.data["cases"]))
        self.assertNotIn("GHSL-2024-061",str(self.data["cases"][2]["labels"]))
        self.assertEqual(self.data["cases"][4]["split"],self.data["cases"][5]["split"])

    def test_exact_recall(self):
        s = score(self.data,self.results,self.grades())
        self.assertEqual(1,s["true_positives"])
        self.assertAlmostEqual(1/6,s["target_recall"])

    def test_unresolved_not_automatically_false_positive(self):
        s = score(self.data,self.results,grade_template(self.results))
        self.assertEqual(1,s["unresolved_findings"])
        self.assertIsNone(s["precision"])
        self.assertIsNone(s["f1"])

    def test_reject_catalog_or_run_drift(self):
        g=self.grades()
        self.results["cases"][0]["status"]="error"
        with self.assertRaisesRegex(ValueError,"different results"):
            score(self.data,self.results,g)

    def test_cannot_match_another_repository_label(self):
        g=self.grades()
        g["decisions"][0]["label_id"]=self.data["cases"][1]["labels"][0]["id"]
        with self.assertRaises(ValueError): score(self.data,self.results,g)

    def test_duplicate_cannot_inflate_recall(self):
        self.results["cases"][0]["output"]["findings"].append(copy.deepcopy(self.results["cases"][0]["output"]["findings"][0]))
        validate_output(self.results["cases"][0]["output"])
        g=grade_template(self.results)
        g["adjudicator"]="reviewer"
        for d in g["decisions"]:
            d.update(decision="match",label_id=self.case["labels"][0]["id"],rationale="reviewed")
        with self.assertRaisesRegex(ValueError,"twice"): score(self.data,self.results,g)
        g["decisions"][1]["decision"]="duplicate"
        s=score(self.data,self.results,g)
        self.assertEqual(1,s["true_positives"])
        self.assertEqual(0.5,s["precision"])

    def test_failure_stays_in_recall_denominator(self):
        self.results["cases"][0].update(status="error",error="timeout")
        s=score(self.data,self.results,grade_template(self.results))
        self.assertEqual(6,s["false_negatives"])
        self.assertEqual(1,s["failed_cases"])

    def test_bad_agent_output(self):
        for value in ({}, {"findings":"none"}, {"findings":[{"title":"x"}]}):
            with self.assertRaises(ValueError): validate_output(value)


if __name__ == "__main__": unittest.main()
