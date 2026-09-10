"""Download selected TAR members by verified byte range and validate gzip files."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def curl_command():
    """The GPU and PostgreSQL execution host is not necessarily Windows."""
    found = shutil.which("curl.exe") or shutil.which("curl")
    if found is None:
        raise RuntimeError("curl was not found on PATH")
    return found


def verify_member(path, expected_size):
    """Read the member back: full SHA-256, gzip CRC and every JSON line."""
    if path.stat().st_size != expected_size:
        raise ValueError("stored size does not match TAR header")
    digest = hashlib.sha256()
    with path.open("rb") as raw:
        for chunk in iter(lambda: raw.read(1024 * 1024), b""):
            digest.update(chunk)
    events = 0
    with gzip.open(path, "rb") as stream:
        for line in stream:
            if line.strip():
                json.loads(line)
                events += 1
    return digest.hexdigest(), events


def record_attempt(out_dir, entry):
    with (out_dir / "attempts.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry) + "\n")


def select_member(rows, host):
    suffix = f"sysclient{host:04d}.json.gz"
    matches = [x for x in rows if x["name"].endswith(suffix)]
    unique = {
        (x["name"], x["file_id"], x["data_offset"], x["size"]): x
        for x in matches
    }
    if len(unique) != 1:
        raise ValueError(f"expected one indexed member, found {len(unique)} distinct members")
    return next(iter(unique.values()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--date", required=True)
    parser.add_argument("--host", type=int, required=True)
    parser.add_argument("--verify-only", action="store_true",
                        help="re-verify an already stored member and write its missing manifest entry")
    args = parser.parse_args()
    index = ROOT / "data" / "inria_index" / args.date / "index.jsonl"
    rows = [json.loads(x) for x in index.read_text().splitlines()]
    row = select_member(rows, args.host)
    start, size = row["data_offset"], row["size"]
    end = start + size - 1
    out_dir = ROOT / "data" / "inria_selected" / args.date
    out_dir.mkdir(parents=True, exist_ok=True)
    output = out_dir / Path(row["name"]).name
    now = datetime.now(timezone.utc).isoformat()

    if args.verify_only:
        if not output.exists():
            raise FileNotFoundError(f"nothing stored at {output}")
        source = "verified_existing_file"
    else:
        if output.exists():
            raise FileExistsError(f"refusing to overwrite {output}; use --verify-only to record it")
        # Keep the headers of every attempt, including failures, under their own timestamp.
        headers = output.with_suffix(output.suffix + f".{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.headers")
        url = f"https://entrepot.recherche.data.gouv.fr/api/access/datafile/{row['file_id']}"
        result = subprocess.run([
            curl_command(), "--silent", "--show-error", "--fail", "--location",
            "--retry", "3", "--retry-delay", "2", "--max-time", "3600",
            "--range", f"{start}-{end}", "--max-filesize", str(size),
            "--dump-header", str(headers), "--output", str(output), url,
        ])
        if result.returncode:
            output.unlink(missing_ok=True)
            record_attempt(out_dir, {**row, "attempted_at_utc": now, "outcome": "curl_failed",
                                     "curl_exit_code": result.returncode,
                                     "headers_path": headers.relative_to(ROOT).as_posix()})
            raise RuntimeError(f"curl failed ({result.returncode}); attempt recorded")
        text = headers.read_text(encoding="utf-8")
        ranges = re.findall(r"(?im)^content-range:\s*bytes (\d+)-(\d+)/(\d+)", text)
        if not ranges or tuple(map(int, ranges[-1][:2])) != (start, end):
            output.unlink(missing_ok=True)
            record_attempt(out_dir, {**row, "attempted_at_utc": now, "outcome": "wrong_range",
                                     "headers_path": headers.relative_to(ROOT).as_posix()})
            raise ValueError("server did not return the requested member range; attempt recorded")
        source = "downloaded"

    try:
        sha256, events = verify_member(output, size)
    except Exception as error:
        # Never leave a stored file with no record of what happened to it.
        record_attempt(out_dir, {**row, "attempted_at_utc": now, "outcome": "verification_failed",
                                 "source": source, "error": f"{type(error).__name__}: {error}"})
        if source == "downloaded":
            output.unlink(missing_ok=True)
        raise
    record = {**row, "recorded_at_utc": now, "source": source,
              "stored_bytes": output.stat().st_size, "sha256": sha256,
              "gzip_and_jsonl_valid": True, "event_count": events,
              "local_path": output.relative_to(ROOT).as_posix()}
    with (out_dir / "manifest.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")
    print(json.dumps(record), flush=True)


if __name__ == "__main__":
    main()
