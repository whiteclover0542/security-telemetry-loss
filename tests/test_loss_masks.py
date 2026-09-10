import random
import unittest

from scripts.loss_masks import deletion_count, make_mask


class LossMaskTests(unittest.TestCase):
    def test_exact_counts_and_bounds_for_all_planned_conditions(self):
        for n in (0, 1, 19, 100, 1001):
            for rate in ("0", "0.01", "0.05", "0.10", "0.20", "1"):
                for seed in range(30):
                    for pattern in ("random", "contiguous"):
                        mask = make_mask(n, rate, seed, pattern)
                        self.assertEqual(len(mask), deletion_count(n, rate))
                        self.assertEqual(mask, sorted(set(mask)))
                        self.assertTrue(all(0 <= x < n for x in mask))
                        if pattern == "contiguous" and mask:
                            self.assertEqual(mask, list(range(mask[0], mask[-1] + 1)))

    def test_reproducible_and_does_not_mutate_global_rng(self):
        before = random.getstate()
        for pattern in ("random", "contiguous"):
            self.assertEqual(make_mask(1000, ".1", 29, pattern), make_mask(1000, ".1", 29, pattern))
        self.assertEqual(before, random.getstate())

    def test_decimal_floor_does_not_round_up(self):
        self.assertEqual(deletion_count(19, ".1"), 1)
        self.assertEqual(deletion_count(100, ".29"), 29)

    def test_invalid_inputs_are_rejected(self):
        for rate in ("NaN", "Infinity", "-0.1", "1.1"):
            with self.assertRaises(ValueError):
                make_mask(100, rate, 0, "random")
        for count in (-1, 1.5, True):
            with self.assertRaises(ValueError):
                make_mask(count, ".1", 0, "random")
        with self.assertRaises(ValueError):
            make_mask(100, ".1", 0, "other")

    def test_contiguous_can_reach_both_boundaries(self):
        starts = {make_mask(4, ".5", seed, "contiguous")[0] for seed in range(100)}
        self.assertEqual(starts, {0, 1, 2})


if __name__ == "__main__":
    unittest.main()
