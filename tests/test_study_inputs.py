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


if __name__ == "__main__":
    unittest.main()
