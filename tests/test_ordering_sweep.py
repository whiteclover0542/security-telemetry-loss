from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from ordering_sweep import delayed, project, run


class ProjectTests(unittest.TestCase):
    def rule(self, **kw):
        base = {"object": "FLOW", "action": "START", "key": "pid"}
        base.update(kw)
        return base

    def events(self):
        return [
            (0, {"object": "FLOW", "action": "START", "pid": 1, "properties": {"dest_ip": "a"}}),
            (1, {"object": "FILE", "action": "READ", "pid": 2, "properties": {"file_path": "x"}}),
            (2, {"object": "FLOW", "action": "START", "pid": 3, "properties": {"dest_ip": "b"}}),
        ]

    def test_filters_by_object_and_action(self):
        out = project(self.events(), self.rule())
        self.assertEqual([(t, v) for t, v, _ in out], [(0, 1), (2, 3)])

    def test_list_of_actions_is_accepted(self):
        rule = self.rule(object="FILE", action=["READ", "WRITE"], key="pid")
        self.assertEqual(len(project(self.events(), rule)), 1)

    def test_non_pid_key_reads_from_properties(self):
        out = project(self.events(), self.rule(key="dest_ip"))
        self.assertEqual([v for _, v, _ in out], ["a", "b"])

    def test_events_missing_the_key_are_skipped(self):
        events = [(0, {"object": "FLOW", "action": "START", "pid": 1, "properties": {}})]
        self.assertEqual(project(events, self.rule(key="dest_ip")), [])


class DelayTests(unittest.TestCase):
    def projected(self):
        # (time, key, pid) triples; pids 1 and 2, one malicious.
        return [(float(i), i % 2, 1 if i % 2 else 2) for i in range(10)]

    def test_no_event_is_removed(self):
        out = delayed(self.projected(), 0.5, 100, "random", {1}, seed=0)
        self.assertEqual(len(out), len(self.projected()))

    def test_output_is_sorted_by_arrival(self):
        out = delayed(self.projected(), 0.5, 100, "random", {1}, seed=0)
        times = [t for t, _ in out]
        self.assertEqual(times, sorted(times))

    def test_targeted_only_delays_malicious_pids(self):
        # Malicious pid is 1 (odd indices), whose key value is also 1 here.
        # Any arrival beyond the original max (9) must be a delayed pid-1 event,
        # whose key value is 1.
        out = delayed(self.projected(), 1.0, 100, "targeted", {1}, seed=0)
        late_values = [value for t, value in out if t > 9]
        self.assertTrue(late_values)
        self.assertTrue(all(value == 1 for value in late_values))

    def test_targeted_with_no_malicious_events_returns_none(self):
        self.assertIsNone(delayed(self.projected(), 0.5, 100, "targeted", set(), seed=0))

    def test_seed_is_reproducible(self):
        a = delayed(self.projected(), 0.5, 100, "random", {1}, seed=7)
        b = delayed(self.projected(), 0.5, 100, "random", {1}, seed=7)
        self.assertEqual(a, b)


class RunTests(unittest.TestCase):
    def test_run_projects_and_counts(self):
        projected = [(float(i), "k", 1) for i in range(5)]
        result = run(projected, "pid", 60, 3)
        self.assertEqual(result["alerts"], 1)


if __name__ == "__main__":
    unittest.main()
