# -*- coding: utf-8 -*-
"""Tests de cohérence : génération -> analyse. Lancer :  python -m unittest discover -s tests -v"""
import json, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
import generate_events as gen      # noqa: E402
import analyze_logs as ana         # noqa: E402

SEV = ana.SEV


class PipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        gen.generate(seed=42, out=str(d / "data"), teacher_dir=str(d / "teacher"), quiet=True)
        cls.key = json.loads((d / "teacher" / "answer_key.json").read_text())["events"]
        cls.records, _ = ana.load_records([str(d / "data" / "s3_layout")])
        cls.findings = ana.run_detections(cls.records)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_deterministic(self):
        with tempfile.TemporaryDirectory() as t2:
            gen.generate(seed=42, out=t2 + "/d", teacher_dir=t2 + "/t", quiet=True)
            recs2, _ = ana.load_records([t2 + "/d/s3_layout"])
        self.assertEqual([r["eventID"] for r in self.records], [r["eventID"] for r in recs2])

    def test_every_scenario_detected_at_least_high(self):
        flagged = {e for f in self.findings if SEV[f["severity"]] >= SEV["HIGH"] for e in f["related_eventIDs"]}
        for sc in ("S1", "S2", "S3", "S4", "S5", "S6"):
            ids = {e for e, v in self.key.items() if v["scenario"] == sc}
            self.assertTrue(ids & flagged, f"scénario {sc} non détecté")

    def test_no_decoy_above_medium(self):
        decoys = {e for e, v in self.key.items() if v["role"] == "decoy"}
        for f in self.findings:
            if SEV[f["severity"]] >= SEV["HIGH"]:
                self.assertFalse(set(f["related_eventIDs"]) & decoys, f"faux positif HIGH+ : {f['details']}")

    def test_log_gap_detected(self):
        gaps = [f for f in self.findings if f["rule"] == "R08"]
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["severity"], "CRITICAL")

    def test_no_event_inside_logging_gap(self):
        gap = json.loads((Path(self.tmp.name) / "teacher" / "answer_key.json").read_text())["logging_gap"]
        inside = [r for r in self.records if gap["stop"] < r["eventTime"] < gap["start"]]
        self.assertEqual(inside, [])

    def test_records_have_cloudtrail_core_fields(self):
        for r in self.records:
            for k in ("eventVersion", "userIdentity", "eventTime", "eventSource", "eventName",
                      "awsRegion", "sourceIPAddress", "eventID", "eventType"):
                self.assertIn(k, r)


if __name__ == "__main__":
    unittest.main()
