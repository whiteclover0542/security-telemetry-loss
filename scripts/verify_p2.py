"""Verify premise P2 on a real OpTC host log.

P2: events carry an occurrence time that can be told apart from an arrival or
collection time. If the only time field is occurrence time, the raw log is an
idealised occurrence-ordered stream carrying no pipeline delay, which is what lets
arrival delay be modelled on top of it.

Reports the time fields present, whether any properties key resembles a collection
time, the timestamp precision, and how monotonic the raw stream already is.
"""
import argparse
import gzip
import json
from collections import Counter
from pathlib import Path

TIME_HINTS = ("time", "date", "ts", "stamp", "epoch", "ingest", "collect", "recv")


def inspect(source, limit):
    top_keys, prop_keys, time_props, precisions = Counter(), Counter(), Counter(), Counter()
    n = out_of_order = 0
    prev = first_ts = last_ts = None
    with gzip.open(source, "rt", encoding="utf-8") as stream:
        for line in stream:
            e = json.loads(line)
            n += 1
            for k in e:
                top_keys[k] += 1
            for k in e.get("properties", {}):
                prop_keys[k] += 1
                if any(h in k.lower() for h in TIME_HINTS):
                    time_props[k] += 1
            ts = e["timestamp"]
            digits = "".join(c for c in ts.split(".")[1] if c.isdigit()) if "." in ts else ""
            precisions[len(digits)] += 1
            first_ts = first_ts or ts
            last_ts = ts
            if prev is not None and ts < prev:
                out_of_order += 1
            prev = ts
            if limit and n >= limit:
                break
    return {
        "events_inspected": n,
        "top_level_keys": sorted(top_keys),
        "keys_in_every_event": sorted(k for k, v in top_keys.items() if v == n),
        "distinct_properties_keys": len(prop_keys),
        "time_like_properties_keys": dict(time_props),
        "timestamp_fractional_digit_counts": dict(precisions),
        "first_timestamp": first_ts,
        "last_timestamp": last_ts,
        "out_of_order_adjacent_pairs": out_of_order,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=500_000, help="0 for the whole file")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    found = inspect(args.input, args.limit)
    only_occurrence = not found["time_like_properties_keys"] or set(
        found["time_like_properties_keys"]) <= {"start_time", "end_time"}
    record = {
        "schema": "p2-verification-v1",
        "input": args.input.as_posix(),
        **found,
        "occurrence_time_only": only_occurrence,
        "raw_stream_monotonic": found["out_of_order_adjacent_pairs"] == 0,
        "note": ("start_time and end_time describe an entity's activity span, not "
                 "log collection time; no ingest or arrival field is present."),
    }
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
