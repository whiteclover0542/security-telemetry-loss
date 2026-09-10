import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class StudyInputsTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / "config" / "study_inputs.json").read_text())

    def test_three_unique_cases_and_expected_hosts(self):
        cases = self.config["primary_cases"]
        self.assertEqual(len(cases), 3)
        self.assertEqual({x["host"] for x in cases}, {"SysClient0201", "SysClient0501", "SysClient0051"})
        self.assertEqual(len({x["case"] for x in cases}), 3)

    def test_member_ranges_stay_inside_archives(self):
        for case in self.config["primary_cases"]:
            self.assertGreater(case["member_size"], 0)
            self.assertLessEqual(case["member_data_offset"] + case["member_size"], case["archive_size"])

    def test_pinned_label_hashes_match_review_sources_when_present(self):
        review = ROOT / "external" / "corrected-optc-review"
        if not review.exists():
            self.skipTest("review source is intentionally excluded from Git")
        for case in self.config["primary_cases"]:
            path = review / case["label_file"]
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), case["label_sha256"])

    def test_prespecified_loss_conditions(self):
        loss = self.config["loss_conditions"]
        self.assertEqual(loss["primary_rate"], "0.10")
        self.assertEqual(loss["patterns"], ["random", "contiguous"])
        self.assertGreaterEqual(loss["seeds"]["last"] - loss["seeds"]["first"] + 1, 10)

    def test_detector_is_pinned_and_uses_validation_threshold(self):
        detector = self.config["detector"]
        self.assertEqual(len(detector["commit"]), 40)
        self.assertEqual(detector["training_dates"], ["2019-09-19", "2019-09-20", "2019-09-21"])
        self.assertEqual(detector["validation_date"], "2019-09-22")
        self.assertEqual(detector["threshold_method"], "max_val_loss")
        self.assertEqual(detector["evaluation_method"], "node_evaluation")
        self.assertIn("frozen", detector["case_detection_rule"])
        self.assertIn("stop", detector["baseline_gate"])

    def test_normal_archives_cover_training_and_validation_dates(self):
        archives = self.config["normal_input_archives"]
        self.assertEqual([item["date"] for item in archives], [
            "2019-09-19", "2019-09-20", "2019-09-21", "2019-09-22"
        ])
        for archive in archives:
            self.assertGreater(archive["archive_size"], 0)
            self.assertEqual(len(archive["md5"]), 32)


if __name__ == "__main__":
    unittest.main()
