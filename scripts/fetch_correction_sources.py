"""Fetch a pinned, small review subset; downloaded code is never executed."""
import hashlib
import json
from pathlib import Path
import subprocess
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
REV = "644f41fb0a955e471f34bed016fb2bfd9c74dc04"
BASE = "https://gitlab.inria.fr/api/v4/projects/fmajorcz%2Fa_new_hope_for_darpa_optc/repository"


def fetch(url, output):
    if output.exists():
        return
    subprocess.run(["curl.exe", "--silent", "--show-error", "--fail", "--location",
                    "--max-time", "45", "--max-filesize", "5242880", "--output", str(output), url], check=True)


def main():
    root = ROOT / "external" / "corrected-optc-review"
    root.mkdir(parents=True, exist_ok=True)
    records = []
    for directory in ("corrections", "labelling/host", "labelling/host/ground_truths"):
        tree = root / (directory.replace("/", "_") + "_tree.json")
        fetch(f"{BASE}/tree?path={quote(directory, safe='')}&per_page=100&ref={REV}", tree)
        entries = json.loads(tree.read_text())
        if len(entries) >= 100:
            raise ValueError("pagination required; subset incomplete")
        for entry in entries:
            path = entry["path"]
            if entry["type"] != "blob" or Path(path).suffix.lower() not in (".py", ".md", ".txt", ".csv", ".json", ".sh"):
                continue
            target = root / path
            if not target.resolve().is_relative_to(root.resolve()):
                raise ValueError("invalid source path")
            target.parent.mkdir(parents=True, exist_ok=True)
            url = f"{BASE}/files/{quote(path, safe='')}/raw?ref={REV}"
            fetch(url, target)
            records.append({"path": path, "commit": REV, "url": url, "bytes": target.stat().st_size,
                            "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
            print(path, target.stat().st_size, flush=True)
    (ROOT / "research" / "correction_sources_manifest.json").write_text(json.dumps(records, indent=2) + "\n")


if __name__ == "__main__":
    main()
