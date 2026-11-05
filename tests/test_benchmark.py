import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from secbench.catalog import digest, load
from secbench.runner import prepare, task, run, validate_output
from secbench.scoring import grade_template, score
from secbench.source_checks import anchors, check_sources


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
        self.assertEqual(set(anchors()), {l["id"] for c in self.data["cases"] for l in c["labels"]})

    def test_exact_recall(self):
        s = score(self.data,self.results,self.grades())
        self.assertEqual(1,s["true_positives"])
        self.assertAlmostEqual(1/6,s["target_recall"])
        self.assertIsNone(s["false_positive_rate"])

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


class PreparationTests(unittest.TestCase):
    def test_local_prepare_no_history_no_labels_and_drift_detection(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            repo=root/"repo"
            subprocess.run(["git","init",str(repo)],check=True,capture_output=True)
            (repo/"source.py").write_text("print('fixture')\n",encoding="utf-8")
            subprocess.run(["git","-C",str(repo),"add","source.py"],check=True,capture_output=True)
            subprocess.run(["git","-C",str(repo),"-c","user.name=Fixture","-c","user.email=fixture@example.invalid","-c","core.hooksPath=","commit","-m","fixture"],check=True,capture_output=True)
            data=load()
            data["cases"][0]["ref"]="HEAD"
            case=data["cases"][0]
            work=root/"work"
            lock=prepare(data,case,work,repo)
            request=task(data,case,work)
            self.assertNotIn("labels",request)
            self.assertNotIn("GHSL",json.dumps(request))
            self.assertFalse((Path(lock["source_dir"])/".git").exists())
            # A prepared but unrelated file must not be called source validation.
            one_case = copy.deepcopy(data)
            one_case["cases"] = [case]
            prepare(one_case,one_case["cases"][0],root/"single",repo)
            report=check_sources(one_case,root/"single")
            self.assertTrue(all(l["status"] == "needs_investigation" for l in report["cases"][0]["labels"]))
            agent=Path(__file__).resolve().parents[1]/"examples"/"empty_agent.py"
            results=run(data,[case],work,[sys.executable,str(agent)],"smoke",10)
            self.assertEqual("ok",results["cases"][0]["status"])
            s=score(data,results,grade_template(results))
            self.assertEqual(0,s["target_recall"])
            (Path(lock["source_dir"])/"source.py").write_text("modified",encoding="utf-8")
            with self.assertRaisesRegex(ValueError,"modified"): task(data,case,work)


if __name__ == "__main__": unittest.main()
