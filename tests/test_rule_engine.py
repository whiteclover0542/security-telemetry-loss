from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from rule_engine import SlidingWindowRule, run_rule


def stream(times, key="p1"):
    return [(t, {"pid": key}) for t in times]


def rule(**kwargs):
    settings = {"name": "r", "key_field": "pid", "window_seconds": 60, "threshold": 3}
    settings.update(kwargs)
    return SlidingWindowRule(**settings)


class ThresholdTests(unittest.TestCase):
    def test_fires_when_threshold_met_inside_window(self):
        self.assertEqual(run_rule(rule(), stream([0, 10, 20]))["alerts"], 1)

    def test_does_not_fire_when_events_straddle_the_window(self):
        self.assertEqual(run_rule(rule(), stream([0, 10, 100]))["alerts"], 0)

    def test_counter_resets_after_firing(self):
        self.assertEqual(run_rule(rule(), stream([0, 1, 2, 3, 4, 5]))["alerts"], 2)

    def test_separate_keys_do_not_combine(self):
        events = [(0, {"pid": "a"}), (1, {"pid": "b"}), (2, {"pid": "a"}), (3, {"pid": "b"})]
        self.assertEqual(run_rule(rule(), events)["alerts"], 0)

    def test_event_without_the_key_is_ignored(self):
        self.assertEqual(run_rule(rule(), [(0, {}), (1, {}), (2, {})])["alerts"], 0)


class OrderDependenceTests(unittest.TestCase):
    """P1: the same events in a different arrival order can change the verdict."""

    def test_same_events_different_order_changes_verdict(self):
        # Three events inside one minute plus a much later one. In occurrence
        # order the trio fires before the late event moves the watermark.
        self.assertEqual(run_rule(rule(), stream([0, 10, 20, 600]))["alerts"], 1)

        # The very same four events, with the late one first. Its watermark
        # retires the trio's window before any of them is seen.
        self.assertEqual(run_rule(rule(), stream([600, 0, 10, 20]))["alerts"], 0)

    def test_the_reordered_events_are_dropped_as_late(self):
        result = run_rule(rule(), stream([600, 0, 10, 20]))
        self.assertEqual(result["dropped_late"], 3)
        self.assertEqual(result["accepted"], 1)

    def test_partial_delay_is_enough_to_suppress(self):
        # Only the third event is held back past the watermark.
        self.assertEqual(run_rule(rule(), stream([0, 10, 600, 20]))["alerts"], 0)

    def test_allowed_lateness_restores_the_verdict(self):
        result = run_rule(rule(allowed_lateness=600), stream([600, 0, 10, 20]))
        self.assertEqual(result["alerts"], 1)
        self.assertEqual(result["dropped_late"], 0)

    def test_insufficient_lateness_does_not_restore_it(self):
        self.assertEqual(run_rule(rule(allowed_lateness=60), stream([600, 0, 10, 20]))["alerts"], 0)

    def test_order_is_immaterial_without_a_watermark_jump(self):
        # Nothing gets retired, so permuting close events changes nothing.
        self.assertEqual(run_rule(rule(), stream([0, 10, 20]))["alerts"],
                         run_rule(rule(), stream([20, 0, 10]))["alerts"])


class GuardTests(unittest.TestCase):
    def test_rejects_invalid_configuration(self):
        for bad in ({"threshold": 0}, {"window_seconds": 0}, {"allowed_lateness": -1}):
            with self.assertRaises(ValueError):
                rule(**bad)


if __name__ == "__main__":
    unittest.main()
