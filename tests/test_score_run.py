import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from aggregate_results import check_record
from score_run import load_frozen_labels, load_predictions, score

LABELS = {"n1", "n2", "n3", "n4"}


def predictions_file(directory, rows):
    path = Path(directory) / "preds.jsonl"
    path.write_text("".join(json.dumps({"node_id": n, "pred_score": s}) + "\n"
                            for n, s in rows), encoding="utf-8")
    return path


class ScoreTests(unittest.TestCase):
    def test_strictly_above_threshold_counts_as_detected(self):
        scores = {"n1": 0.51, "n2": 0.50, "n3": 0.49, "n4": 0.90}
        result = score(scores, LABELS, 0.50)
        self.assertEqual(result["detected_label_nodes"], 2, "a score equal to the threshold is not a detection")
        self.assertEqual(result["total_label_nodes"], 4)
        self.assertTrue(result["case_detected"])

    def test_deleted_label_nodes_stay_in_the_denominator(self):
        # Loss removed n3 and n4 from the input entirely.
        result = score({"n1": 0.9, "n2": 0.9}, LABELS, 0.5)
        self.assertEqual(result["total_label_nodes"], 4)
        self.assertEqual(result["detected_label_nodes"], 2)
        self.assertEqual(result["label_nodes_absent_from_input"], 2)

    def test_case_not_detected_when_no_label_node_alerts(self):
        result = score({"n1": 0.1, "other": 0.99}, LABELS, 0.5)
        self.assertFalse(result["case_detected"])
        self.assertEqual(result["detected_label_nodes"], 0)
        self.assertEqual(result["node_precision"], 0.0)

    def test_node_precision_ignores_non_label_alerts_correctly(self):
        result = score({"n1": 0.9, "x": 0.9, "y": 0.9}, LABELS, 0.5)
        self.assertEqual(result["alerted_nodes"], 3)
        self.assertAlmostEqual(result["node_precision"], 1 / 3)

    def test_precision_is_none_without_alerts(self):
        self.assertIsNone(score({"n1": 0.1}, LABELS, 0.5)["node_precision"])


class LoadTests(unittest.TestCase):
    def test_duplicate_node_score_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = predictions_file(directory, [("n1", 0.1), ("n1", 0.9)])
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_predictions(path)

    def test_empty_predictions_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "no node predictions"):
                load_predictions(predictions_file(directory, []))

    def test_frozen_labels_must_be_unique_and_present(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "labels.json"
            path.write_text(json.dumps({
                "schema": "frozen-labels-v1", "label_sha256": "a" * 64, "node_ids": ["n1", "n1"]
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicates"):
                load_frozen_labels(path)

    def test_frozen_labels_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "labels.json"
            path.write_text(json.dumps({
                "schema": "frozen-labels-v1", "label_sha256": "b" * 64, "node_ids": ["n1", "n2"]
            }), encoding="utf-8")
            body, nodes = load_frozen_labels(path)
            self.assertEqual(nodes, {"n1", "n2"})
            self.assertEqual(body["label_sha256"], "b" * 64)


class ContractIntegrationTests(unittest.TestCase):
    """The scorer's output is the aggregator's input; hold them to one contract."""

    def run_scorer(self, directory, extra):
        labels = Path(directory) / "labels.json"
        labels.write_text(json.dumps({
            "schema": "frozen-labels-v1", "label_sha256": "a" * 64,
            "node_ids": sorted(LABELS),
        }), encoding="utf-8")
        predictions = predictions_file(directory, [("n1", 0.9), ("n2", 0.1), ("x", 0.8)])
        output = Path(directory) / "record.json"
        command = [
            sys.executable, str(ROOT / "scripts" / "score_run.py"),
            "--predictions", str(predictions), "--labels", str(labels),
            "--threshold", "0.5", "--run-id", "r1", "--case", "scenario-1",
            "--host", "SysClient0201", "--requested-rate", "0.10",
            "--input-sha256", "c" * 64, "--selection-start", "100", "--selection-end", "200",
            "--deleted-count", "10", "--detector-commit", "d" * 40,
            "--checkpoint-sha256", "e" * 64,
            "--started-at-utc", "2026-09-10T00:00:00+00:00", "--output", str(output), *extra,
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        return result, output

    def test_scorer_output_satisfies_the_run_record_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = self.run_scorer(
                directory, ["--pattern", "random", "--seed", "0", "--mask-sha256", "f" * 64])
            self.assertEqual(result.returncode, 0, result.stderr)
            record = json.loads(output.read_text())
            check_record(record)
            self.assertEqual(record["detected_label_nodes"], 1)
            self.assertEqual(record["total_label_nodes"], 4)
            self.assertTrue(record["case_detected"])

    def test_baseline_record_also_satisfies_the_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = self.run_scorer(directory, ["--pattern", "baseline"])
            self.assertEqual(result.returncode, 0, result.stderr)
            check_record(json.loads(output.read_text()))

    def test_loss_run_without_a_seed_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            result, _ = self.run_scorer(directory, ["--pattern", "random", "--mask-sha256", "f" * 64])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--seed is required", result.stderr)


if __name__ == "__main__":
    unittest.main()
