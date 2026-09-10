"""Read bounded public-source samples; never download whole datasets or execute them."""
import hashlib
import argparse
import json
import zlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "optc_readme": "https://raw.githubusercontent.com/FiveDirections/OpTC-data/master/README.md",
    "optc_schema": "https://raw.githubusercontent.com/FiveDirections/OpTC-data/master/ecar.md",
    "optc_errata": "https://raw.githubusercontent.com/FiveDirections/OpTC-data/master/errata.md",
    "h051_evaluation_folder": "https://drive.google.com/drive/folders/1WnVHzCyZ8uwQfTVvHknwcugCOLn25hD5",
    "h501_dump_sample": "https://drive.google.com/uc?export=download&id=1046BVjpMql1bb5WHr9yQeB6Uq6RpngbM",
    "ecar_archive_prefix": "https://drive.usercontent.google.com/download?id=1z2SvDukO9yNCR_X8PYIV13XT9FSQXuiW&export=download&confirm=t",
}
ALTERNATIVES = {
    "h201_attack_folder": "https://drive.google.com/drive/folders/15nia2-dLBVw1ieLHz-JMKXCXvO226Ktx",
    "h501_attack_folder": "https://drive.google.com/drive/folders/1FEx6FMXf3BrVgrmiaQNeObtKAJF3VElY",
    "inria_description": "https://correctedoptc.inria.fr/",
    "inria_metadata": "https://entrepot.recherche.data.gouv.fr/api/datasets/:persistentId/?persistentId=doi:10.57745/UXCWOC",
}
FILES = {
    "h201_first": "https://drive.usercontent.google.com/download?id=1pJLxJsDV8sngiedbfVajMetczIgM3PQd&export=download&confirm=t",
    "h201_last": "https://drive.usercontent.google.com/download?id=1HFSyvmgH0jvdnnnTdKfWRjZYOrLWoIkv&export=download&confirm=t",
    "h501_first": "https://drive.usercontent.google.com/download?id=1VfyGr8wfSe8LBIHBWuYBlU8c2CyEgO5C&export=download&confirm=t",
    "h501_last": "https://drive.usercontent.google.com/download?id=1fRQqc68r8-z5BL7H_eAKIDOeHp7okDuM&export=download&confirm=t",
    "inria_readme": "https://entrepot.recherche.data.gouv.fr/api/access/datafile/717349",
    "inria_0925_tar_prefix": "https://entrepot.recherche.data.gouv.fr/api/access/datafile/713576",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alternatives", action="store_true")
    parser.add_argument("--files", action="store_true")
    args = parser.parse_args()
    now = datetime.now(timezone.utc)
    target = ROOT / "research" / "source_checks" / now.strftime("%Y%m%dT%H%M%S%fZ")
    target.mkdir(parents=True, exist_ok=False)
    records = []
    for name, url in (FILES if args.files else ALTERNATIVES if args.alternatives else SOURCES).items():
        record = {"name": name, "url": url, "checked_at_utc": now.isoformat()}
        try:
            request = Request(url, headers={"User-Agent": "security-telemetry-loss-source-check/1.0"})
            with urlopen(request, timeout=25) as response:
                content = response.read(262145)
                truncated = len(content) > 262144
                content = content[:262144]
                record.update(status=response.status, content_type=response.headers.get("Content-Type"),
                              bytes_saved=len(content), truncated=truncated,
                              sha256=hashlib.sha256(content).hexdigest(),
                              postgres_dump_magic=content.startswith(b"PGDMP"))
                (target / (name + ".sample")).write_bytes(content)
                if content.startswith(b"\x1f\x8b"):
                    # A partial gzip prefix is sufficient for a bounded schema check.
                    # Do not treat this as a complete archive or experiment dataset.
                    decoded = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(content, 1048576)
                    lines = decoded.split(b"\n")[:-1]
                    events = [json.loads(line) for line in lines if line.strip()]
                    record["complete_json_lines_in_prefix"] = len(events)
                    record["hostnames_in_prefix"] = sorted({e.get("hostname", "") for e in events})
                    record["first_event_keys"] = sorted(events[0]) if events else []
                    record["sample_only"] = True
                    (target / (name + ".jsonl")).write_bytes(b"\n".join(lines) + b"\n")
        except Exception as error:
            record.update(error=type(error).__name__ + ": " + str(error))
        records.append(record)
        print(json.dumps(record, ensure_ascii=True), flush=True)
    (target / "manifest.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    print(target)


if __name__ == "__main__":
    main()
