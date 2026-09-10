"""Map a UTC evaluation window to absolute event positions in a frozen input.

The loss mask generator draws deletions from a contiguous position range, so the
random and contiguous conditions must be restricted to the same evaluation
window. This tool produces that range and records how well the window maps onto
it. Offsets are mandatory in the window arguments: the OpTC timestamps carry a
local offset, and the recorded PIDSMaker window strings have no stated zone.
"""
import argparse
from datetime import datetime
import gzip
import hashlib
import json
from pathlib import Path


def aware_timestamp(text):
    parsed = datetime.fromisoformat(text)
    if parsed.utcoffset() is None:
        raise ValueError(f"timestamp needs an explicit UTC offset: {text}")
    return parsed


def open_events(path):
    return gzip.open(path, "rt", encoding="utf-8") if path.suffix == ".gz" else path.open("r", encoding="utf-8")


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan(path, window_start, window_end):
    event_count = in_window = order_violations = 0
    first = last = None
    previous = None
    with open_events(path) as stream:
        for position, line in enumerate(stream):
            if not line.strip():
                raise ValueError(f"blank line at event position {position}")
            moment = aware_timestamp(json.loads(line)["timestamp"])
            event_count = position + 1
            if previous is not None and moment < previous:
                order_violations += 1
            previous = moment
            if window_start <= moment < window_end:
                in_window += 1
                last = position
                if first is None:
                    first = position
    return {
        "event_count": event_count,
        "in_window_count": in_window,
        "order_violations": order_violations,
        "selection_start": first,
        "selection_end": None if last is None else last + 1,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--start", type=aware_timestamp, required=True, help="inclusive, with UTC offset")
    parser.add_argument("--end", type=aware_timestamp, required=True, help="exclusive, with UTC offset")
    parser.add_argument("--output", type=Path, required=True, help="new JSON record path")
    parser.add_argument("--allow-impure-range", action="store_true",
                        help="proceed when the position range also contains events outside the window")
    args = parser.parse_args()
    if args.start >= args.end:
        parser.error("--start must be earlier than --end")

    result = scan(args.input, args.start, args.end)
    if result["selection_start"] is None:
        raise ValueError("no event falls inside the requested window")
    span = result["selection_end"] - result["selection_start"]
    outside = span - result["in_window_count"]
    if outside and not args.allow_impure_range:
        raise ValueError(
            f"position range holds {outside} events outside the window; "
            "the input is not sorted by timestamp, so record the decision with --allow-impure-range"
        )

    record = {
        "schema": "window-positions-v1",
        "input_path": args.input.as_posix(),
        "input_sha256": sha256_file(args.input),
        "window_start": args.start.isoformat(),
        "window_end": args.end.isoformat(),
        "events_outside_window_inside_range": outside,
        **result,
        "selection_event_count": span,
    }
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    print(json.dumps(record), flush=True)


if __name__ == "__main__":
    main()
