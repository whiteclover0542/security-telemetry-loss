"""Compute the pre-registered effect summaries from run records.

Written before any result exists so the calculation cannot be shaped by one.
Reports the mean effects (E, EC) and the spread effects (EV, E_severe): the
hypothesis is that contiguous loss is the less predictable pattern, so the
seed-to-seed spread is a measurement rather than a nuisance. Refuses records
that do not satisfy config/run_record_schema.json, keeps failed runs out of the
averages, and reports whether the case detection rate saturated.
"""
import argparse
import json
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads((ROOT / "config" / "run_record_schema.json").read_text(encoding="utf-8"))
CHECKS = {
    "string": str, "integer": int, "number": (int, float), "boolean": bool,
    "string_or_null": (str, type(None)), "integer_or_null": (int, type(None)),
}


def check_record(record):
    for field, kind in CONTRACT["required_fields"].items():
        if field not in record:
            raise ValueError(f"run record is missing required field {field!r}")
        expected = CHECKS[kind]
        value = record[field]
        if kind == "boolean":
            if not isinstance(value, bool):
                raise ValueError(f"field {field!r} must be a boolean")
        elif isinstance(value, bool) or not isinstance(value, expected):
            raise ValueError(f"field {field!r} must be {kind}")
    if record["pattern"] not in CONTRACT["value_rules"]["pattern"]:
        raise ValueError(f"unknown pattern {record['pattern']!r}")
    if record["exit_status"] not in CONTRACT["value_rules"]["exit_status"]:
        raise ValueError(f"unknown exit status {record['exit_status']!r}")
    if record["total_label_nodes"] <= 0:
        raise ValueError("total_label_nodes must be positive")
    if not 0 <= record["detected_label_nodes"] <= record["total_label_nodes"]:
        raise ValueError("detected_label_nodes outside 0..total_label_nodes")
    if record["case_detected"] != (record["detected_label_nodes"] > 0):
        raise ValueError("case_detected disagrees with detected_label_nodes")
    if (record["pattern"] == "baseline") != (record["seed"] is None):
        raise ValueError("seed must be null for baseline runs and set otherwise")
    return record


def load_records(paths):
    records = []
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(check_record(json.loads(line)))
    return records


def recall(record):
    return record["detected_label_nodes"] / record["total_label_nodes"]


SEVERE_FRACTION_OF_BASELINE = 0.5


def summarise_arm(runs, baseline_recall=None):
    recalls = [recall(run) for run in runs]
    summary = {
        "seeds": len(runs),
        "detected_runs": sum(run["case_detected"] for run in runs),
        "R": statistics.fmean(float(run["case_detected"]) for run in runs),
        "RC": statistics.fmean(recalls),
        "RC_min": min(recalls),
        "RC_max": max(recalls),
        "RC_range": max(recalls) - min(recalls),
        # Sample standard deviation, fixed before results as the spread measure.
        "RC_stdev": statistics.stdev(recalls) if len(recalls) > 1 else 0.0,
    }
    if baseline_recall is not None:
        threshold = baseline_recall * SEVERE_FRACTION_OF_BASELINE
        severe = sum(value < threshold for value in recalls)
        summary["severe_seeds"] = severe
        summary["severe_seed_fraction"] = severe / len(recalls)
    return summary


def aggregate(records):
    completed = [r for r in records if r["exit_status"] == "completed"]
    failed = [r for r in records if r["exit_status"] != "completed"]
    cases = {}
    for record in completed:
        key = (record["case"], record["requested_rate"], record["pattern"])
        cases.setdefault(key, []).append(record)

    baselines = {}
    for (case, _, pattern), runs in cases.items():
        if pattern == "baseline":
            if len(runs) != 1:
                raise ValueError(f"expected exactly one baseline run for {case}, found {len(runs)}")
            baselines[case] = runs[0]

    rows, evaluable = [], []
    rates = sorted({rate for _, rate, pattern in cases if pattern != "baseline"})
    for case in sorted({case for case, _, _ in cases}):
        baseline = baselines.get(case)
        for rate in rates:
            arms = {p: cases.get((case, rate, p)) for p in ("random", "contiguous")}
            if not all(arms.values()):
                continue
            baseline_recall = None if baseline is None else recall(baseline)
            summary = {p: summarise_arm(runs, baseline_recall) for p, runs in arms.items()}
            row = {
                "case": case, "requested_rate": rate,
                "baseline_detected": None if baseline is None else baseline["case_detected"],
                "baseline_recall": baseline_recall,
                "random": summary["random"], "contiguous": summary["contiguous"],
            }
            if baseline is not None and baseline["case_detected"]:
                # Spread effect: positive means contiguous loss is the less predictable one.
                row["EV"] = summary["contiguous"]["RC_stdev"] - summary["random"]["RC_stdev"]
                row["EV_ratio"] = (summary["contiguous"]["RC_stdev"] / summary["random"]["RC_stdev"]
                                   if summary["random"]["RC_stdev"] > 0 else None)
                row["E_severe"] = (summary["contiguous"]["severe_seed_fraction"]
                                   - summary["random"]["severe_seed_fraction"])
                row["L_random"] = 1.0 - summary["random"]["R"]
                row["L_contiguous"] = 1.0 - summary["contiguous"]["R"]
                row["E"] = summary["random"]["R"] - summary["contiguous"]["R"]
                row["LC_random"] = recall(baseline) - summary["random"]["RC"]
                row["LC_contiguous"] = recall(baseline) - summary["contiguous"]["RC"]
                row["EC"] = summary["random"]["RC"] - summary["contiguous"]["RC"]
                evaluable.append(row)
            else:
                row["excluded_reason"] = "no baseline detection; loss effect is not defined"
            rows.append(row)

    primary_rate = json.loads((ROOT / "config" / "study_inputs.json").read_text(encoding="utf-8"))
    primary_rate = primary_rate["loss_conditions"]["primary_rate"]
    primary = [row for row in evaluable if row["requested_rate"] == primary_rate]
    saturated = bool(primary) and all(
        row["baseline_detected"] and row["random"]["R"] == 1.0 and row["contiguous"]["R"] == 1.0
        for row in primary
    )
    overall = {
        "primary_rate": primary_rate,
        "evaluable_cases": len(primary),
        "mean_E": statistics.fmean(row["E"] for row in primary) if primary else None,
        "mean_EC": statistics.fmean(row["EC"] for row in primary) if primary else None,
        "mean_EV": statistics.fmean(row["EV"] for row in primary) if primary else None,
        "mean_E_severe": statistics.fmean(row["E_severe"] for row in primary) if primary else None,
        "case_detection_saturated": saturated,
        "conclusion_metric": "frozen_label_node_recall" if saturated else "case_detection_rate",
        "severe_threshold": f"label node recall below {SEVERE_FRACTION_OF_BASELINE} x baseline",
    }
    return {
        "schema": "aggregate-results-v1",
        "runs_total": len(records), "runs_completed": len(completed), "runs_failed": len(failed),
        "failed_run_ids": [record["run_id"] for record in failed],
        "rows": rows,
        "overall_at_primary_rate": overall,
        "note": "Seeds vary the loss positions of one attack. They are not independent attack samples.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path, nargs="+", required=True, help="run record JSONL files")
    parser.add_argument("--output", type=Path, required=True, help="new JSON summary path")
    args = parser.parse_args()
    summary = aggregate(load_records(args.records))
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2)
        stream.write("\n")
    print(json.dumps(summary["overall_at_primary_rate"], indent=2), flush=True)


if __name__ == "__main__":
    main()
