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


class LateEventBookkeepingTests(unittest.TestCase):
    """Engine v1 wiped live state when an accepted late event landed on the deadline."""

    def test_late_event_on_the_deadline_does_not_wipe_live_state(self):
        # Key a has 100 and 110. Key b moves the watermark to 160 (deadline 100),
        # then a late a@100 is accepted exactly on the deadline. b@161 advances
        # the watermark again. All four a events fit in [100, 120], so a@120 fires.
        events = [(100, {"pid": "a"}), (110, {"pid": "a"}), (160, {"pid": "b"}),
                  (100, {"pid": "a"}), (161, {"pid": "b"}), (120, {"pid": "a"})]
        result = run_rule(rule(threshold=4), events)
        self.assertEqual(result["dropped_late"], 0)
        self.assertEqual(result["alerts"], 1)

    def test_accepted_permutations_agree_with_occurrence_order(self):
        import itertools
        base = [0, 5, 12, 30, 41, 55]
        expected = run_rule(rule(), stream(base))["alerts"]
        for order in itertools.permutations(base):
            result = run_rule(rule(allowed_lateness=120), stream(list(order)))
            self.assertEqual(result["dropped_late"], 0)
            self.assertEqual(result["alerts"], expected, order)

    def test_late_event_can_complete_a_span_that_ends_after_it(self):
        # 20 and 40 arrive first; the late 0 makes {0, 20, 40} fit in 60 seconds.
        self.assertEqual(run_rule(rule(), stream([20, 40, 0]))["alerts"], 1)

    def test_in_order_streams_match_a_naive_counter(self):
        import random
        rng = random.Random(7)
        for _ in range(200):
            times, t = [], 0.0
            for _ in range(rng.randint(5, 60)):
                t += rng.choice([0.0, rng.uniform(0, 40)])
                times.append((t, rng.choice("ab")))
            expected, held = 0, {"a": [], "b": []}
            for when, key in times:
                held[key] = [x for x in held[key] if x >= when - 60] + [when]
                if len(held[key]) >= 3:
                    expected += 1
                    held[key] = []
            events = [(when, {"pid": key}) for when, key in times]
            self.assertEqual(run_rule(rule(), events)["alerts"], expected)


class GuardTests(unittest.TestCase):
    def test_rejects_invalid_configuration(self):
        for bad in ({"threshold": 0}, {"window_seconds": 0}, {"allowed_lateness": -1}):
            with self.assertRaises(ValueError):
                rule(**bad)


if __name__ == "__main__":
    unittest.main()
