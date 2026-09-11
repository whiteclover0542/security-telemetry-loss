import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
# window_positions stayed in the root toolset; mask_overlap imports from it.
sys.path.insert(0, str(ROOT.parent / "scripts"))
from mask_overlap import measure
from window_positions import aware_timestamp

WINDOW_START = aware_timestamp("2019-09-23T11:00:00-04:00")
WINDOW_END = aware_timestamp("2019-09-23T13:00:00-04:00")


def write_events(directory, hours):
    path = Path(directory) / "events.json"
    with path.open("x", encoding="utf-8") as stream:
        for index, hour in enumerate(hours):
            stream.write(json.dumps({
                "id": str(index),
                "timestamp": f"2019-09-23T{hour:02d}:00:00.000-04:00",
            }) + "\n")
    return path


class MaskOverlapTests(unittest.TestCase):
    def test_reports_span_and_attack_window_share(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_events(directory, [9, 11, 12, 14])
            record = measure(path, [1, 2], WINDOW_START, WINDOW_END)
            self.assertEqual(record["deleted_span_seconds"], 3600.0)
            self.assertEqual(record["attack_window_event_count"], 2)
            self.assertEqual(record["deleted_inside_attack_window"], 2)
            self.assertEqual(record["fraction_of_attack_window_deleted"], 1.0)

    def test_loss_outside_the_attack_window_is_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_events(directory, [9, 11, 12, 14])
            record = measure(path, [0, 3], WINDOW_START, WINDOW_END)
            self.assertEqual(record["deleted_inside_attack_window"], 0)
            self.assertEqual(record["fraction_of_attack_window_deleted"], 0.0)


if __name__ == "__main__":
    unittest.main()
