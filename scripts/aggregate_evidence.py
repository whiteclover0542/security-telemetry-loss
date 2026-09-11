"""Aggregate the evidence-loss sweep using the pre-registered definitions.

A-v2 is about spread, so for each metric the per-seed standard deviation is the
dependent variable and EV = SD(contiguous) - SD(random) is the effect. The mean
difference is reported alongside it, because A-v1 was co-registered and both are
computed from the same runs rather than chosen after the fact.
"""
import argparse
import json
from pathlib import Path
import statistics

METRICS = ("event_loss_rate", "process_silence_rate", "creation_loss_rate")


def load(paths):
    records = []
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                if record.get("schema") != "evidence-loss-v1":
                    raise ValueError("unsupported record schema")
                records.append(record)
    return records


def describe(values):
    clean = [v for v in values if v is not None]
    if not clean:
        return None
    return {
        "n": len(clean),
        "mean": statistics.fmean(clean),
        "sd": statistics.stdev(clean) if len(clean) > 1 else 0.0,
        "min": min(clean),
        "max": max(clean),
        "range": max(clean) - min(clean),
    }


def aggregate(records):
    grouped = {}
    for record in records:
        key = (record["case"], record["requested_rate"], record["pattern"])
        grouped.setdefault(key, []).append(record)

    rows = []
    for case in sorted({k[0] for k in grouped}):
        for rate in sorted({k[1] for k in grouped if k[0] == case}):
            arms = {p: grouped.get((case, rate, p)) for p in ("random", "contiguous")}
            if not all(arms.values()):
                continue
            row = {"case": case, "requested_rate": rate,
                   "seeds": len(arms["random"]),
                   "deleted_count": arms["random"][0]["deleted_count"]}
            for metric in METRICS:
                stats = {p: describe([r[metric] for r in arms[p]]) for p in arms}
                row[metric] = stats
                if stats["random"] and stats["contiguous"]:
                    row[f"{metric}__EV"] = stats["contiguous"]["sd"] - stats["random"]["sd"]
                    row[f"{metric}__mean_diff"] = stats["contiguous"]["mean"] - stats["random"]["mean"]
                    row[f"{metric}__sd_ratio"] = (
                        stats["contiguous"]["sd"] / stats["random"]["sd"]
                        if stats["random"]["sd"] > 0 else None)
            rows.append(row)

    primary = [r for r in rows if r["requested_rate"] == "0.10"]
    overall = {}
    for metric in METRICS:
        evs = [r[f"{metric}__EV"] for r in primary if f"{metric}__EV" in r]
        diffs = [r[f"{metric}__mean_diff"] for r in primary if f"{metric}__mean_diff" in r]
        overall[metric] = {
            "cases": len(evs),
            "mean_EV": statistics.fmean(evs) if evs else None,
            "EV_positive_in_all_cases": bool(evs) and all(e > 0 for e in evs),
            "mean_difference": statistics.fmean(diffs) if diffs else None,
        }
    return {"schema": "evidence-aggregate-v1", "records": len(records),
            "rows": rows, "primary_rate": "0.10", "overall_at_primary_rate": overall}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path, nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = aggregate(load(args.records))
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2)
        stream.write("\n")
    print(json.dumps(summary["overall_at_primary_rate"], indent=2), flush=True)


if __name__ == "__main__":
    main()
