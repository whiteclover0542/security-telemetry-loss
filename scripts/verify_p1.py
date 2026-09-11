"""Verify premise P1 on a real OpTC host log.

P1: a time-window rule's verdict depends on the order events arrive in, not only
on which events arrive. This feeds the events of one evaluation window through the
same rule twice - once in occurrence order, once with a fraction delayed - and
reports how the alerts change. No event is ever removed; only arrival times move.

The rule is a generic burst rule (N events from one pid within T seconds), the
most common threshold shape in operations.
"""
import argparse
import gzip
import json
import random
from datetime import datetime
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from rule_engine import SlidingWindowRule, run_rule


def load_window(source, start_iso, end_iso):
    start = datetime.fromisoformat(start_iso).timestamp()
    end = datetime.fromisoformat(end_iso).timestamp()
    events = []
    with gzip.open(source, "rt", encoding="utf-8") as stream:
        for line in stream:
            event = json.loads(line)
            moment = datetime.fromisoformat(event["timestamp"]).timestamp()
            if moment >= end:
                break
            if moment >= start:
                events.append((moment, {"pid": event.get("pid")}))
    return events


def delayed_stream(events, fraction, delay, seed=0):
    """Delay a fraction of events by `delay` seconds; keep every event present."""
    rng = random.Random(seed)
    moved = [((moment + delay) if rng.random() < fraction else moment, moment, event)
             for moment, event in events]
    moved.sort(key=lambda row: row[0])
    return [(moment, event) for _, moment, event in moved]


def make_rule(window_seconds, threshold, allowed_lateness=0.0):
    return SlidingWindowRule("burst", "pid", window_seconds, threshold, allowed_lateness)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--start", required=True, help="window start, ISO with offset")
    parser.add_argument("--end", required=True, help="window end, ISO with offset")
    parser.add_argument("--window-seconds", type=float, default=60)
    parser.add_argument("--threshold", type=int, default=50)
    parser.add_argument("--output", type=Path, required=True, help="new JSON result path")
    args = parser.parse_args()

    events = load_window(args.input, args.start, args.end)
    baseline = run_rule(make_rule(args.window_seconds, args.threshold), events)

    scenarios = []
    for fraction, delay in ((0.01, 300), (0.05, 300), (0.20, 300),
                            (0.05, args.window_seconds), (0.05, 900)):
        stream = delayed_stream(events, fraction, delay)
        result = run_rule(make_rule(args.window_seconds, args.threshold), stream)
        scenarios.append({
            "delayed_fraction": fraction,
            "delay_seconds": delay,
            "alerts": result["alerts"],
            "alerts_vs_baseline": result["alerts"] - baseline["alerts"],
            "distinct_keys": len(result["alert_keys"]),
            "dropped_late": result["dropped_late"],
        })

    record = {
        "schema": "p1-verification-v1",
        "input": args.input.as_posix(),
        "window": [args.start, args.end],
        "events_in_window": len(events),
        "rule": {"window_seconds": args.window_seconds, "threshold": args.threshold},
        "baseline_alerts": baseline["alerts"],
        "baseline_keys": len(baseline["alert_keys"]),
        "scenarios": scenarios,
        "p1_supported": any(s["alerts_vs_baseline"] != 0 for s in scenarios),
        "note": "No event is removed in any scenario; only arrival order changes.",
    }
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    print(json.dumps({k: v for k, v in record.items() if k != "scenarios"}, indent=2))
    for s in scenarios:
        print(f"  delay {s['delay_seconds']:>5.0f}s on {s['delayed_fraction']:>5.0%}: "
              f"alerts {s['alerts']:,} ({s['alerts_vs_baseline']:+,}), "
              f"dropped_late {s['dropped_late']:,}")


if __name__ == "__main__":
    main()
