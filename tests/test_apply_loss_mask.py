import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from apply_loss_mask import apply, sha256_file


class ApplyLossMaskTests(unittest.TestCase):
    def make_input_and_mask(self, directory):
        source = Path(directory) / "events.json.gz"
        with source.open("xb") as stream:
            with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as raw:
                raw.write(b'{"id":"a","timestamp":"2019-09-23T00:00:00Z"}\n')
                raw.write(b'{"id":"b","timestamp":"2019-09-23T00:00:01Z"}\n')
                raw.write(b'{"id":"c","timestamp":"2019-09-23T00:00:02Z"}\n')
        mask = Path(directory) / "mask.json"
        mask.write_text(json.dumps({
            "schema": "loss-mask-v2", "source_sha256": sha256_file(source),
            "event_count": 3, "selection_start": 0, "selection_end": 3,
            "requested_rate": "0.33", "realized_rate": 1 / 3,
            "seed": 0, "pattern": "random", "positions": [1]
        }), encoding="utf-8")
        return source, mask

    def test_applies_mask_and_writes_audit_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            source, mask = self.make_input_and_mask(directory)
            output, manifest = Path(directory) / "lost.json.gz", Path(directory) / "lost.manifest.json"
            record = apply(source, mask, output, manifest)
            with gzip.open(output, "rt", encoding="utf-8") as stream:
                self.assertEqual([json.loads(line)["id"] for line in stream], ["a", "c"])
            self.assertEqual(record["input_event_count"], 3)
            self.assertEqual(record["deleted_count"], 1)
            self.assertEqual(record["output_event_count"], 2)
            self.assertEqual(json.loads(manifest.read_text())["output_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())

    def test_rejects_position_outside_its_own_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            source, mask = self.make_input_and_mask(directory)
            record = json.loads(mask.read_text())
            record["selection_start"], record["selection_end"] = 2, 3
            mask.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "outside its own selection"):
                apply(source, mask, Path(directory) / "out.json", Path(directory) / "out.manifest.json")

    def test_rejects_mask_for_another_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source, mask = self.make_input_and_mask(directory)
            changed = Path(directory) / "changed.json"
            changed.write_text('{"id":"other"}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source SHA-256"):
                apply(changed, mask, Path(directory) / "out.json", Path(directory) / "out.manifest.json")


if __name__ == "__main__":
    unittest.main()
