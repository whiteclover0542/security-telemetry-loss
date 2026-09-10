import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from fetch_inria_members import select_member, verify_member


class FetchInriaMembersTests(unittest.TestCase):
    def row(self, offset=100, size=200):
        return {
            "name": "2019-09-19/AIA-201-225/event-sysclient0201.json.gz",
            "file_id": 713570,
            "data_offset": offset,
            "size": size,
        }

    def test_identical_repeated_index_entry_is_safe(self):
        self.assertEqual(select_member([self.row(), self.row()], 201)["data_offset"], 100)

    def test_conflicting_index_entries_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "2 distinct"):
            select_member([self.row(), self.row(offset=300)], 201)


class VerifyMemberTests(unittest.TestCase):
    def make_member(self, directory, lines=2):
        path = Path(directory) / "member.json.gz"
        with path.open("xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as stream:
                for index in range(lines):
                    stream.write(json.dumps({"id": index}).encode() + b"\n")
        return path

    def test_reports_sha256_and_event_count(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_member(directory, lines=3)
            sha256, events = verify_member(path, path.stat().st_size)
            self.assertEqual(sha256, hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(events, 3)

    def test_size_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_member(directory)
            with self.assertRaisesRegex(ValueError, "stored size"):
                verify_member(path, path.stat().st_size + 1)

    def test_truncated_gzip_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.make_member(directory)
            data = path.read_bytes()[:-8]
            path.write_bytes(data)
            with self.assertRaises(Exception):
                verify_member(path, len(data))


if __name__ == "__main__":
    unittest.main()
