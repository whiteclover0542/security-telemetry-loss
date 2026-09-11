"""Measure what a loss mask actually removed in wall-clock time.

The experiment design records the real duration of a deleted span and its
overlap with the attack window as auxiliary measurements. This runs after mask
generation and reads the attack window only for reporting, so it never feeds
label information back into mask selection.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from window_positions import aware_timestamp, open_events, sha256_file


def measure(input_path, positions, attack_start, attack_end):
    deleted = set(positions)
    first = last = None
    inside_attack = attack_window_events = event_count = 0
    with open_events(input_path) as stream:
        for position, line in enumerate(stream):
            moment = aware_timestamp(json.loads(line)["timestamp"])
            event_count = position + 1
            in_attack = attack_start <= moment < attack_end
            attack_window_events += in_attack
            if position in deleted:
                inside_attack += in_attack
                last = moment
                if first is None:
                    first = moment
    if len(deleted) and first is None:
        raise ValueError("mask positions do not occur in this input")
    return {
        "input_event_count": event_count,
        "deleted_count": len(deleted),
        "deleted_first_timestamp": None if first is None else first.isoformat(),
        "deleted_last_timestamp": None if last is None else last.isoformat(),
        "deleted_span_seconds": None if first is None else (last - first).total_seconds(),
        "attack_window_event_count": attack_window_events,
        "deleted_inside_attack_window": inside_attack,
        "fraction_of_attack_window_deleted":
            inside_attack / attack_window_events if attack_window_events else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--mask", type=Path, required=True)
    parser.add_argument("--attack-start", type=aware_timestamp, required=True)
    parser.add_argument("--attack-end", type=aware_timestamp, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new JSON record path")
    args = parser.parse_args()
    mask = json.loads(args.mask.read_text(encoding="utf-8"))
    if mask.get("schema") != "loss-mask-v2":
        raise ValueError("unsupported mask schema")
    input_sha256 = sha256_file(args.input)
    if mask["source_sha256"] != input_sha256:
        raise ValueError("mask source SHA-256 does not match input")

    record = {
        "schema": "mask-overlap-v1",
        "input_path": args.input.as_posix(),
        "input_sha256": input_sha256,
        "mask_path": args.mask.as_posix(),
        "mask_sha256": sha256_file(args.mask),
        "pattern": mask["pattern"],
        "seed": mask["seed"],
        "requested_rate": mask["requested_rate"],
        "attack_window_start": args.attack_start.isoformat(),
        "attack_window_end": args.attack_end.isoformat(),
        **measure(args.input, mask["positions"], args.attack_start, args.attack_end),
    }
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    print(json.dumps(record), flush=True)


if __name__ == "__main__":
    main()
