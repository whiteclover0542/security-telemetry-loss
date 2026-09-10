"""Index public Inria TAR headers using verified bounded HTTP Range requests."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tarfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
ARCHIVES = {"2019-09-23": (713574, 120309340160),
            "2019-09-24": (713575, 111941212160),
            "2019-09-25": (713576, 67718440960)}


def fetch_range(url, start, length, work):
    header, body = work / "response.headers", work / "response.bin"
    result = subprocess.run([
        "curl.exe", "--silent", "--show-error", "--fail", "--location",
        "--max-time", "45", "--range", f"{start}-{start + length - 1}",
        "--max-filesize", str(length), "--dump-header", str(header),
        "--output", str(body), url,
    ], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"curl failed ({result.returncode}); no valid range saved")
    headers = header.read_text(encoding="utf-8")
    matches = re.findall(r"(?im)^content-range:\s*bytes (\d+)-(\d+)/(\d+)", headers)
    if not matches or tuple(map(int, matches[-1][:2])) != (start, start + length - 1):
        raise ValueError("server did not return requested byte range")
    data = body.read_bytes()
    if len(data) != length:
        raise ValueError("truncated response")
    return data, int(matches[-1][2])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--date", choices=ARCHIVES, required=True)
    parser.add_argument("--host", type=int, required=True)
    parser.add_argument("--max-members", type=int, default=30)
    args = parser.parse_args()
    file_id, total = ARCHIVES[args.date]
    work = ROOT / "data" / "inria_index" / args.date
    work.mkdir(parents=True, exist_ok=True)
    index = work / "index.jsonl"
    rows = [json.loads(line) for line in index.read_text().splitlines()] if index.exists() else []
    wanted = f"sysclient{args.host:04d}.json.gz"
    for row in rows:
        if row["name"].endswith(wanted):
            print(json.dumps(row), flush=True)
            return
    offset = rows[-1]["next_offset"] if rows else 0
    url = f"https://entrepot.recherche.data.gouv.fr/api/access/datafile/{file_id}"
    for _ in range(args.max_members):
        data, remote_total = fetch_range(url, offset, 512, work)
        if remote_total != total:
            raise ValueError("archive size differs from recorded version")
        if data == b"\0" * 512:
            print("End of archive; target not found", flush=True)
            return
        member = tarfile.TarInfo.frombuf(data, "utf-8", "strict")
        if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
            raise ValueError(f"unsupported TAR type {member.type!r}; refusing incorrect offsets")
        row = {"name": member.name, "size": member.size,
               "header_offset": offset, "data_offset": offset + 512,
               "next_offset": offset + 512 + ((member.size + 511) // 512) * 512,
               "archive_date": args.date, "file_id": file_id,
               "checked_at_utc": datetime.now(timezone.utc).isoformat()}
        if row["next_offset"] > total:
            raise ValueError("member extends beyond archive")
        with index.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row) + "\n")
        print(json.dumps(row), flush=True)
        if member.name.endswith(wanted):
            return
        offset = row["next_offset"]
    print("Batch completed; rerun to resume from recorded offset", flush=True)


if __name__ == "__main__":
    main()
