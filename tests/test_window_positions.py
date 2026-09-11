import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from window_positions import aware_timestamp, scan

WINDOW_START = aware_timestamp("2019-09-23T11:00:00-04:00")
WINDOW_END = aware_timestamp("2019-09-23T13:00:00-04:00")


def write_events(directory, hours):
    path = Path(directory) / "events.json"
    with path.open("x", encoding="utf-8") as stream:
        for index, hour in enumerate(hours):
            stream.write(json.dumps({
                "id": str(index), "timestamp": f"2019-09-23T{hour:02d}:00:00.000-04:00"
            }) + "\n")
    return path


class WindowPositionTests(unittest.TestCase):
    def test_selection_covers_only_the_window(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_events(directory, [9, 10, 11, 12, 13, 14])
            result = scan(path, WINDOW_START, WINDOW_END)
            self.assertEqual((result["selection_start"], result["selection_end"]), (2, 4))
            self.assertEqual(result["in_window_count"], 2)
            self.assertEqual(result["order_violations"], 0)

    def test_window_end_is_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_events(directory, [13, 13])
            self.assertIsNone(scan(path, WINDOW_START, WINDOW_END)["selection_start"])

    def test_out_of_order_input_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_events(directory, [11, 9, 12])
            result = scan(path, WINDOW_START, WINDOW_END)
            self.assertEqual(result["order_violations"], 1)
            # Positions 0 and 2 are in the window, so the range also holds position 1.
            self.assertEqual(result["selection_end"] - result["selection_start"], 3)
            self.assertEqual(result["in_window_count"], 2)

    def test_naive_timestamp_is_refused(self):
        with self.assertRaisesRegex(ValueError, "explicit UTC offset"):
            aware_timestamp("2019-09-23T11:00:00")


if __name__ == "__main__":
    unittest.main()
