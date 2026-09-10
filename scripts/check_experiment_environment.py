"""Inspect an execution host before running the PIDSMaker experiment."""
import argparse
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys


def command_result(command, run=subprocess.run):
    try:
        result = run(command, capture_output=True, text=True, timeout=15, check=False)
    except FileNotFoundError:
        return {"available": False}
    except subprocess.TimeoutExpired:
        return {"available": True, "timed_out": True}
    output = (result.stdout or result.stderr).strip().splitlines()
    return {"available": True, "exit_code": result.returncode, "output": output[:3]}


def linux_memory_bytes(meminfo_path=Path("/proc/meminfo")):
    if not meminfo_path.exists():
        return None
    values = {}
    for line in meminfo_path.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition(":")
        parts = value.split()
        if parts and parts[0].isdigit():
            values[key] = int(parts[0]) * 1024
    return values.get("MemTotal")


def windows_memory_bytes():
    import ctypes

    class MemoryStatus(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulong if name.startswith("dw") else ctypes.c_ulonglong)
                    for name in ("dwLength", "dwMemoryLoad", "ullTotalPhys", "ullAvailPhys",
                                 "ullTotalPageFile", "ullAvailPageFile", "ullTotalVirtual",
                                 "ullAvailVirtual", "ullAvailExtendedVirtual")]

    status = MemoryStatus()
    status.dwLength = ctypes.sizeof(MemoryStatus)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return None
    return status.ullTotalPhys


def memory_total_bytes():
    """Memory is the constraint that decides whether this host can run the replay."""
    if sys.platform == "win32":
        return windows_memory_bytes()
    return linux_memory_bytes()


def collect(cwd=None):
    cwd = Path.cwd() if cwd is None else cwd
    disk = shutil.disk_usage(cwd)
    return {
        "schema": "experiment-environment-v1",
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "workspace": str(cwd),
        "disk_free_bytes": disk.free,
        "memory_total_bytes": memory_total_bytes(),
        "commands": {
            "psql": command_result(["psql", "--version"]),
            "docker": command_result(["docker", "version", "--format", "{{.Server.Version}}"]),
            "nvidia_smi": command_result([
                "nvidia-smi", "--query-gpu=name,memory.total,driver_version",
                "--format=csv,noheader",
            ]),
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="new JSON result path; omit to print")
    args = parser.parse_args()
    record = collect()
    rendered = json.dumps(record, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
