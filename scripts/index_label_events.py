"""Locate the labelled malicious events inside a frozen input file.

The provider ships the malicious events themselves, in the same schema as the
host logs, so evidence loss can be counted directly rather than estimated. This
walks the input once and records where those events sit, which process they
belong to and which of them create a process, since a lost creation severs the
parent-child link that a later trace would follow.

Positions are absolute in the input file, matching the loss masks.
"""
import argparse
from datetime import datetime
import gzip
import hashlib
import json
from pathlib import Path


def open_events(path):
    return gzip.open(path, "rt", encoding="utf-8") if path.suffix == ".gz" else path.open("r", encoding="utf-8")


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_label_ids(path):
    ids = set()
    with open_events(path) as stream:
        for line in stream:
            if line.strip():
                ids.add(json.loads(line)["id"])
    if not ids:
        raise ValueError("no labelled events found")
    return ids


def index_positions(input_path, label_ids, selection):
    """Walk the input once, recording every labelled event inside the window."""
    start, end = selection
    positions, pids, creations = [], [], []
    seen = set()
    found_outside = 0
    with open_events(input_path) as stream:
        for position, line in enumerate(stream):
            if not line.strip():
                continue
            event = json.loads(line)
            if event["id"] not in label_ids:
                continue
            seen.add(event["id"])
            if not start <= position < end:
                found_outside += 1
                continue
            positions.append(position)
            pids.append(event.get("pid"))
            creations.append(event.get("object") == "PROCESS" and event.get("action") == "CREATE")
    return {
        "label_positions": positions,
        "label_pids": pids,
        "label_is_process_create": creations,
        "labelled_events_matched": len(seen),
        "labelled_events_outside_window": found_outside,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="frozen host log")
    parser.add_argument("--labels", type=Path, required=True, help="provider malicious event file")
    parser.add_argument("--window", type=Path, required=True, help="window_positions.py record")
    parser.add_argument("--case", required=True)
    parser.add_argument("--output", type=Path, required=True, help="new JSON record path")
    args = parser.parse_args()

    window = json.loads(args.window.read_text(encoding="utf-8"))
    if window.get("schema") != "window-positions-v1":
        raise ValueError("unsupported window schema")
    input_sha256 = sha256_file(args.input)
    if window["input_sha256"] != input_sha256:
        raise ValueError("window record was computed on a different input")

    label_ids = load_label_ids(args.labels)
    selection = (window["selection_start"], window["selection_end"])
    found = index_positions(args.input, label_ids, selection)
    if not found["label_positions"]:
        raise ValueError("no labelled event falls inside the evaluation window")

    record = {
        "schema": "label-positions-v1",
        "case": args.case,
        "input_path": args.input.as_posix(),
        "input_sha256": input_sha256,
        "labels_path": args.labels.as_posix(),
        "labels_sha256": sha256_file(args.labels),
        "labelled_events_total": len(label_ids),
        "selection_start": window["selection_start"],
        "selection_end": window["selection_end"],
        "selection_event_count": window["selection_event_count"],
        "indexed_at_utc": datetime.now(tz=None).astimezone().isoformat(),
        **found,
        "label_events_in_window": len(found["label_positions"]),
        "process_create_events_in_window": sum(found["label_is_process_create"]),
        "distinct_pids_in_window": len({p for p in found["label_pids"] if p is not None}),
    }
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(record, stream)
        stream.write("\n")
    summary = {k: v for k, v in record.items() if not isinstance(v, list)}
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
