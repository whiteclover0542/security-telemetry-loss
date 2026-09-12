from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from reorder_buffer import perfectly_ordered, reorder


def stream(triples):
    """triples: (arrival, occurrence, tag), given in arrival order as a real buffer sees them."""
    ordered = sorted(triples)
    return [(a, o, {"tag": tag}) for a, o, tag in ordered]


class ReorderTests(unittest.TestCase):
    def test_no_distortion_passes_through_in_order(self):
        s = stream([(0, 0, "a"), (10, 10, "b"), (20, 20, "c")])
        out = reorder(s, buffer_seconds=0)
        self.assertEqual([t for t, _ in out], [0, 10, 20])
        self.assertTrue(perfectly_ordered(out))

    def test_zero_buffer_keeps_distortion(self):
        # occurrence 20 arrives last (delayed to 320); no buffer, so it stays last.
        s = stream([(0, 0, "a"), (10, 10, "b"), (320, 20, "c")])
        out = reorder(s, buffer_seconds=0)
        self.assertEqual([t for t, _ in out], [0, 10, 20])
        # released order by arrival: a, b, then c — occurrence 0,10,20 happens to
        # sort here because c's occurrence is the largest, so check a real inversion.

    def test_delayed_event_stays_out_of_order_without_buffer(self):
        # occurrence 5 delayed to arrive at 300, after occurrence 100.
        s = stream([(0, 0, "a"), (300, 5, "late"), (100, 100, "b")])
        out = reorder(s, buffer_seconds=0)
        # released in arrival order: a (0), b (100), late (300).
        self.assertEqual([e["tag"] for _, e in out], ["a", "b", "late"])
        self.assertFalse(perfectly_ordered(out))

    def test_large_buffer_restores_occurrence_order(self):
        s = stream([(0, 0, "a"), (300, 5, "late"), (100, 100, "b")])
        out = reorder(s, buffer_seconds=300)
        self.assertEqual([e["tag"] for _, e in out], ["a", "late", "b"])
        self.assertTrue(perfectly_ordered(out))

    def test_a_positive_buffer_restores_order_a_zero_one_does_not(self):
        # b has occurrence == arrival (100), so any positive buffer keeps it held
        # until late (arrival 300) shows up, letting late sort ahead of it.
        s = stream([(0, 0, "a"), (300, 5, "late"), (100, 100, "b")])
        self.assertFalse(perfectly_ordered(reorder(s, buffer_seconds=0)))
        self.assertTrue(perfectly_ordered(reorder(s, buffer_seconds=1)))

    def test_every_event_is_released_once(self):
        s = stream([(0, 0, "a"), (300, 5, "late"), (100, 100, "b")])
        for buf in (0, 50, 200, 300, 1000):
            self.assertEqual(len(reorder(s, buf)), 3)

    def test_negative_buffer_rejected(self):
        with self.assertRaises(ValueError):
            reorder([], -1)


if __name__ == "__main__":
    unittest.main()
