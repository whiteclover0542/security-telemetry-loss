import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from aggregate_results import aggregate, check_record


def record(case="scenario-1", pattern="random", seed=0, detected_nodes=5, total=10,
           rate="0.10", exit_status="completed"):
    return {
        "run_id": f"{case}-{pattern}-{rate}-{seed}", "case": case, "host": "SysClient0201",
        "pattern": pattern, "requested_rate": rate,
        "seed": None if pattern == "baseline" else seed,
        "input_sha256": "a" * 64, "mask_sha256": None if pattern == "baseline" else "b" * 64,
        "selection_start": 100, "selection_end": 200, "deleted_count": 10,
        "detector_commit": "c" * 40, "checkpoint_sha256": "d" * 64, "threshold": 0.5,
        "case_detected": detected_nodes > 0, "detected_label_nodes": detected_nodes,
        "total_label_nodes": total, "started_at_utc": "2026-09-10T00:00:00+00:00",
        "finished_at_utc": "2026-09-10T01:00:00+00:00", "exit_status": exit_status,
    }


def arm(pattern, detected_nodes, rate="0.10", case="scenario-1"):
    return [record(case=case, pattern=pattern, seed=s, detected_nodes=detected_nodes, rate=rate)
            for s in range(2)]


def varied_arm(pattern, node_counts, rate="0.10", case="scenario-1"):
    return [record(case=case, pattern=pattern, seed=s, detected_nodes=n, rate=rate)
            for s, n in enumerate(node_counts)]


class ContractTests(unittest.TestCase):
    def test_missing_field_is_rejected(self):
        broken = record()
        del broken["threshold"]
        with self.assertRaisesRegex(ValueError, "threshold"):
            check_record(broken)

    def test_detection_flag_must_agree_with_node_count(self):
        broken = record(detected_nodes=0)
        broken["case_detected"] = True
        with self.assertRaisesRegex(ValueError, "disagrees"):
            check_record(broken)

    def test_baseline_must_not_carry_a_seed(self):
        broken = record(pattern="baseline")
        broken["seed"] = 3
        with self.assertRaisesRegex(ValueError, "seed must be null"):
            check_record(broken)

    def test_detected_nodes_cannot_exceed_total(self):
        with self.assertRaisesRegex(ValueError, "outside 0"):
            check_record(record(detected_nodes=11, total=10))


class AggregateTests(unittest.TestCase):
    def test_effects_use_the_frozen_definitions(self):
        records = [record(pattern="baseline", detected_nodes=10)]
        records += arm("random", 8) + arm("contiguous", 4)
        summary = aggregate(records)
        row = summary["rows"][0]
        self.assertEqual(row["baseline_recall"], 1.0)
        self.assertAlmostEqual(row["EC"], 0.4)
        self.assertAlmostEqual(row["LC_random"], 0.2)
        self.assertAlmostEqual(row["LC_contiguous"], 0.6)
        self.assertEqual(row["E"], 0.0)

    def test_saturated_case_detection_switches_the_conclusion_metric(self):
        records = [record(pattern="baseline", detected_nodes=10)]
        records += arm("random", 8) + arm("contiguous", 4)
        overall = aggregate(records)["overall_at_primary_rate"]
        self.assertTrue(overall["case_detection_saturated"])
        self.assertEqual(overall["conclusion_metric"], "frozen_label_node_recall")
        self.assertAlmostEqual(overall["mean_EC"], 0.4)

    def test_unsaturated_case_detection_keeps_the_primary_metric(self):
        records = [record(pattern="baseline", detected_nodes=10)]
        records += arm("random", 8)
        records += [record(pattern="contiguous", seed=0, detected_nodes=0),
                    record(pattern="contiguous", seed=1, detected_nodes=2)]
        overall = aggregate(records)["overall_at_primary_rate"]
        self.assertFalse(overall["case_detection_saturated"])
        self.assertEqual(overall["conclusion_metric"], "case_detection_rate")
        self.assertEqual(overall["mean_E"], 0.5)

    def test_case_without_baseline_detection_is_excluded_with_a_reason(self):
        records = [record(pattern="baseline", detected_nodes=0)]
        records += arm("random", 8) + arm("contiguous", 4)
        summary = aggregate(records)
        self.assertIn("not defined", summary["rows"][0]["excluded_reason"])
        self.assertIsNone(summary["overall_at_primary_rate"]["mean_E"])

    def test_failed_runs_are_kept_but_excluded_from_averages(self):
        records = [record(pattern="baseline", detected_nodes=10)]
        records += arm("random", 8) + arm("contiguous", 4)
        records.append(record(pattern="contiguous", seed=9, detected_nodes=0, exit_status="failed"))
        summary = aggregate(records)
        self.assertEqual(summary["runs_failed"], 1)
        self.assertEqual(summary["rows"][0]["contiguous"]["seeds"], 2)

    def test_equal_means_can_still_differ_in_spread(self):
        # Both arms average 5/10, but contiguous is all-or-nothing across seeds.
        records = [record(pattern="baseline", detected_nodes=10)]
        records += varied_arm("random", [5, 5, 5, 5])
        records += varied_arm("contiguous", [10, 0, 10, 0])
        summary = aggregate(records)
        row = summary["rows"][0]
        self.assertAlmostEqual(row["EC"], 0.0, msg="means are identical by construction")
        self.assertGreater(row["EV"], 0.0, "contiguous spread must be larger")
        self.assertEqual(row["random"]["RC_stdev"], 0.0)
        self.assertEqual(row["contiguous"]["RC_range"], 1.0)

    def test_severe_seed_fraction_uses_the_frozen_threshold(self):
        records = [record(pattern="baseline", detected_nodes=10)]
        records += varied_arm("random", [6, 6, 6, 6])
        records += varied_arm("contiguous", [10, 1, 10, 1])
        row = aggregate(records)["rows"][0]
        self.assertEqual(row["random"]["severe_seed_fraction"], 0.0)
        self.assertEqual(row["contiguous"]["severe_seed_fraction"], 0.5)
        self.assertEqual(row["E_severe"], 0.5)

    def test_spread_effect_is_absent_without_baseline_detection(self):
        records = [record(pattern="baseline", detected_nodes=0)]
        records += varied_arm("random", [5, 5]) + varied_arm("contiguous", [10, 0])
        self.assertNotIn("EV", aggregate(records)["rows"][0])

    def test_secondary_rates_are_reported_separately(self):
        records = [record(pattern="baseline", detected_nodes=10)]
        records += arm("random", 8) + arm("contiguous", 4)
        records += arm("random", 9, rate="0.01") + arm("contiguous", 9, rate="0.01")
        summary = aggregate(records)
        self.assertEqual({row["requested_rate"] for row in summary["rows"]}, {"0.01", "0.10"})
        self.assertEqual(summary["overall_at_primary_rate"]["evaluable_cases"], 1)


if __name__ == "__main__":
    unittest.main()
