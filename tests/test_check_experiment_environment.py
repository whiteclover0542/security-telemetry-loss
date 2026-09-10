from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from check_experiment_environment import command_result, linux_memory_bytes


class EnvironmentCheckTests(unittest.TestCase):
    def test_reads_linux_memory_total(self):
        with tempfile.TemporaryDirectory() as directory:
            meminfo = Path(directory) / "meminfo"
            meminfo.write_text("MemTotal:       8192 kB\nMemFree:        1024 kB\n", encoding="utf-8")
            self.assertEqual(linux_memory_bytes(meminfo), 8192 * 1024)

    def test_missing_command_is_reported(self):
        def missing(*args, **kwargs):
            raise FileNotFoundError()
        self.assertEqual(command_result(["missing"], run=missing), {"available": False})


if __name__ == "__main__":
    unittest.main()
