import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from evidence_loss import measure


def index(positions, pids, creates):
    return {"label_positions": positions, "label_pids": pids, "label_is_process_create": creates}


class EvidenceLossTests(unittest.TestCase):
    def test_counts_deleted_labelled_events(self):
        result = measure(index([10, 20, 30, 40], [1, 1, 2, 2], [False] * 4), {20, 40})
        self.assertEqual(result["label_events_deleted"], 2)
        self.assertEqual(result["event_loss_rate"], 0.5)

    def test_process_is_silenced_only_when_all_its_events_go(self):
        # pid 1 loses both events, pid 2 keeps one.
        result = measure(index([10, 11, 20, 21], [1, 1, 2, 2], [False] * 4), {10, 11, 20})
        self.assertEqual(result["processes_in_window"], 2)
        self.assertEqual(result["processes_fully_silenced"], 1)
        self.assertEqual(result["process_silence_rate"], 0.5)

    def test_surviving_process_is_not_counted_as_silenced(self):
        result = measure(index([10, 11], [1, 1], [False, False]), {10})
        self.assertEqual(result["processes_fully_silenced"], 0)

    def test_process_creations_are_tracked_separately(self):
        result = measure(index([10, 20, 30], [1, 2, 3], [True, False, True]), {10, 20})
        self.assertEqual(result["process_creates_in_window"], 2)
        self.assertEqual(result["process_creates_deleted"], 1)
        self.assertEqual(result["creation_loss_rate"], 0.5)

    def test_nothing_deleted_gives_zero_loss(self):
        result = measure(index([1, 2, 3], [1, 1, 1], [False] * 3), set())
        self.assertEqual(result["event_loss_rate"], 0.0)
        self.assertEqual(result["processes_fully_silenced"], 0)
        self.assertEqual(result["creation_loss_rate"], None)

    def test_everything_deleted_silences_every_process(self):
        result = measure(index([1, 2, 3], [1, 2, 2], [True, False, False]), {1, 2, 3})
        self.assertEqual(result["event_loss_rate"], 1.0)
        self.assertEqual(result["process_silence_rate"], 1.0)
        self.assertEqual(result["creation_loss_rate"], 1.0)

    def test_events_without_a_pid_are_excluded_from_process_counts(self):
        result = measure(index([1, 2], [None, 5], [False, False]), {1, 2})
        self.assertEqual(result["processes_in_window"], 1)
        self.assertEqual(result["label_events_deleted"], 2)


if __name__ == "__main__":
    unittest.main()
