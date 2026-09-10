from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from fetch_inria_members import select_member


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


if __name__ == "__main__":
    unittest.main()
