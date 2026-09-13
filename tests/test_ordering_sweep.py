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


class ModelTests(unittest.TestCase):
    def projected(self):
        return [(float(i), i % 3, 1 if i % 2 else 2) for i in range(40)]

    def test_m1_keeps_occurrence_times_in_arrival_order(self):
        m1 = delayed(self.projected(), 0.3, 5, "random", {1}, seed=3, model="m1")
        m2 = delayed(self.projected(), 0.3, 5, "random", {1}, seed=3, model="m2")
        self.assertEqual(sorted(t for t, _ in m1), [float(i) for i in range(40)])
        self.assertEqual([v for _, v in m1], [v for _, v in m2])
        self.assertNotEqual([t for t, _ in m1], sorted(t for t, _ in m1))

    def test_m1_matches_a_zero_buffer_reorder(self):
        from mitigation_sweep import distort
        from reorder_buffer import reorder
        m1 = delayed(self.projected(), 0.3, 5, "random", {1}, seed=3, model="m1")
        moved = distort(self.projected(), 0.3, 5, seed=3)
        released = reorder([(a, o, v) for a, o, v in moved], 0)
        self.assertEqual(m1, [(o, v) for o, v in released])

    def test_delete_removes_exactly_what_random_delay_moves(self):
        from ordering_sweep import choose
        projected = [(float(i) * 100, i % 3, 1) for i in range(40)]  # delay 5 never collides
        chosen = choose(projected, 0.25, "random", {1}, seed=4)
        kept = delayed(projected, 0.25, 5, "delete", {1}, seed=4)
        m2 = delayed(projected, 0.25, 5, "random", {1}, seed=4, model="m2")
        self.assertEqual({t for t, _ in kept}, {projected[i][0] for i in range(40) if i not in chosen})
        self.assertEqual({t - 5 for t, _ in m2 if t % 100}, {projected[i][0] for i in chosen})

    def test_unknown_model_is_rejected(self):
        with self.assertRaises(ValueError):
            delayed(self.projected(), 0.3, 5, "random", {1}, seed=0, model="m3")


class DistributionTests(unittest.TestCase):
    def projected(self, n=2000):
        return [(i * 0.5, i % 7, i % 5) for i in range(n)]

    def delays(self, dist, delay=60.0, fraction=0.2, seed=1):
        from mitigation_sweep import distort
        moved = distort(self.projected(), fraction, delay, seed, dist, window=60.0)
        return [a - o for a, o, _ in moved if a != o], moved

    def test_fixed_and_uniform_pick_the_same_events(self):
        _, fixed = self.delays("fixed")
        _, uniform = self.delays("uniform")
        self.assertEqual({o for a, o, _ in fixed if a != o}, {o for a, o, _ in uniform if a != o})

    def test_uniform_is_bounded_by_twice_the_mean(self):
        d, _ = self.delays("uniform")
        self.assertTrue(all(0 <= x <= 120 for x in d))
        self.assertAlmostEqual(sum(d) / len(d), 60, delta=6)

    def test_lognormal_has_the_requested_mean(self):
        d, _ = self.delays("lognormal", seed=2)
        self.assertAlmostEqual(sum(d) / len(d), 60, delta=12)
        self.assertGreater(max(d), 120)

    def test_burst_delays_whole_slots(self):
        d, moved = self.delays("burst")
        self.assertTrue(all(abs(x - 60) < 1e-9 for x in d))
        slots = {int(o // 60) for a, o, _ in moved if a != o}
        self.assertTrue(all(all(a != o for a, o, _ in moved if int(o // 60) == s) for s in slots))
        self.assertGreaterEqual(sum(1 for a, o, _ in moved if a != o), int(2000 * 0.2))

    def test_buffer_covering_every_delay_restores_the_baseline(self):
        from reorder_buffer import reorder
        from ordering_sweep import run_pairs
        base = run_pairs([(t, v) for t, v, _ in self.projected()], "pid", 60, 20)["alerts"]
        for dist in ("fixed", "uniform", "burst"):
            _, moved = self.delays(dist)
            horizon = max(a - o for a, o, _ in moved)
            released = reorder([(a, o, v) for a, o, v in moved], horizon)
            self.assertEqual(run_pairs([(o, v) for o, v in released], "pid", 60, 20)["alerts"], base, dist)


class RunTests(unittest.TestCase):
    def test_run_projects_and_counts(self):
        projected = [(float(i), "k", 1) for i in range(5)]
        result = run(projected, "pid", 60, 3)
        self.assertEqual(result["alerts"], 1)


if __name__ == "__main__":
    unittest.main()
