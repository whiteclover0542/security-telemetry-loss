"""Download selected TAR members by verified byte range and validate gzip files."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--date", required=True)
    parser.add_argument("--host", type=int, required=True)
    args = parser.parse_args()
    index = ROOT / "data" / "inria_index" / args.date / "index.jsonl"
    rows = [json.loads(x) for x in index.read_text().splitlines()]
    suffix = f"sysclient{args.host:04d}.json.gz"
    matches = [x for x in rows if x["name"].endswith(suffix)]
    if len(matches) != 1:
        raise ValueError(f"expected one indexed member, found {len(matches)}")
    row = matches[0]
    start, size = row["data_offset"], row["size"]
    end = start + size - 1
    out_dir = ROOT / "data" / "inria_selected" / args.date
    out_dir.mkdir(parents=True, exist_ok=True)
    output = out_dir / Path(row["name"]).name
    headers = output.with_suffix(output.suffix + ".headers")
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}")
    url = f"https://entrepot.recherche.data.gouv.fr/api/access/datafile/{row['file_id']}"
    result = subprocess.run([
        "curl.exe", "--silent", "--show-error", "--fail", "--location",
        "--retry", "3", "--retry-delay", "2", "--max-time", "3600",
        "--range", f"{start}-{end}", "--max-filesize", str(size),
        "--dump-header", str(headers), "--output", str(output), url,
    ])
    if result.returncode:
        output.unlink(missing_ok=True)
        raise RuntimeError(f"curl failed ({result.returncode})")
    text = headers.read_text(encoding="utf-8")
    ranges = re.findall(r"(?im)^content-range:\s*bytes (\d+)-(\d+)/(\d+)", text)
    if not ranges or tuple(map(int, ranges[-1][:2])) != (start, end):
        raise ValueError("server did not return the requested member range")
    if output.stat().st_size != size:
        raise ValueError("downloaded size does not match TAR header")
    events = 0
    sha = hashlib.sha256()
    with output.open("rb") as raw:
        for chunk in iter(lambda: raw.read(1024 * 1024), b""):
            sha.update(chunk)
    with gzip.open(output, "rb") as stream:
        for line in stream:
            if line.strip():
                json.loads(line)
                events += 1
    record = {**row, "downloaded_at_utc": datetime.now(timezone.utc).isoformat(),
              "downloaded_bytes": output.stat().st_size, "sha256": sha.hexdigest(),
              "gzip_and_jsonl_valid": True, "event_count": events,
              "local_path": str(output.relative_to(ROOT))}
    manifest = out_dir / "manifest.jsonl"
    with manifest.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")
    print(json.dumps(record), flush=True)


if __name__ == "__main__":
    main()
