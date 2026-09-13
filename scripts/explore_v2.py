"""Exploratory analyses the paper reports beside the pre-registered verdicts.

None of these were registered hypotheses; the paper labels them exploratory.

1. Subject loss by delay region under M1: does any detected subject, or any
   malicious subject, go undetected when the delay stays within the window?
2. Trace size: the late-drop count of every M1 run that let a malicious subject
   evade. The targeting sweep does not record drops, but the M1 ordering sweep
   delays exactly the same events for the same seed and condition, so its drop
   count is joined in.
3. Fine delay grid just below and above the window (h201, 20%, seeds 0-4), to
   check the within-window damage is not an edge artefact like the v1 bug.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from ordering_sweep import delayed, run_pairs
from sweep_common import read_cache

V2 = ROOT / "data" / "p1" / "v2"
FINE_MULTIPLES = (0.9, 0.95, 0.98, 0.99, 0.999, 1.0, 1.001, 1.01)


def load(path):
    with open(path, encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def run_key(r):
    return r["case"], r["rule"], r["delay_fraction"], r["delay_multiple"], r["delay_structure"], r["seed"]


def quantiles(values):
    v = sorted(values)
    pick = lambda q: v[int(q * (len(v) - 1))]
    return {"n": len(v), "zero": sum(1 for x in v if x == 0), "min": v[0], "p10": pick(0.1),
            "median": pick(0.5), "p90": pick(0.9), "max": v[-1]}


def subject_loss(ordering, targeting):
    out = {}
    for region, inside in (("within_window", True), ("beyond_window", False)):
        o = [r for r in ordering if r["delay_structure"] != "delete" and (r["delay_multiple"] <= 1.0) == inside]
        t = [r for r in targeting if (r["delay_multiple"] <= 1.0) == inside]
        out[region] = {"ordering_runs": len(o), "runs_losing_a_subject": sum(r["keys_lost"] > 0 for r in o),
                       "targeting_runs": len(t), "runs_with_malicious_evasion": sum(r["malicious_evaded"] > 0 for r in t)}
    lost = [r for r in ordering if r["delay_structure"] != "delete" and r["keys_lost"] > 0]
    out["subject_loss_runs_without_drops"] = sum(r["dropped_late"] == 0 for r in lost)
    return out


def trace_size(ordering, targeting):
    drops = {run_key(r): r["dropped_late"] for r in ordering if r["delay_structure"] != "delete"}
    evading = defaultdict(list)
    cells = defaultdict(lambda: defaultdict(list))
    for r in targeting:
        if r["delay_multiple"] <= 1.0:
            continue
        d = drops[run_key(r)]
        cells[(r["case"], r["rule"], r["delay_fraction"], r["delay_multiple"])][r["delay_structure"]].append((d, r["malicious_evasion_rate"]))
        if r["malicious_evaded"] > 0:
            evading[r["delay_structure"]].append(d)
    ratios = []
    for c in cells.values():
        if all(e == 0 for s in c.values() for _, e in s):
            continue
        ratios.append(statistics.median(d for d, _ in c["random"]) / statistics.median(d for d, _ in c["targeted"]))
    return {"evading_runs_drops": {s: quantiles(v) for s, v in evading.items()},
            "matched_random_over_targeted_median_drops": {"cells": len(ratios), "min": min(ratios),
                                                          "median": statistics.median(ratios), "max": max(ratios)}}


def fine_grid(catalogue, cache):
    rules = {r["name"]: r for r in catalogue["rules"]}
    out = {}
    for name in ("net_scan", "mass_file", "beacon"):
        rule = rules[name]
        projected, malicious = read_cache(cache, "h201", name)
        key, window, threshold = rule["key"], rule["window_seconds"], rule["threshold"]
        base = run_pairs([(t, v) for t, v, _ in projected], key, window, threshold)["alerts"]
        row = {}
        for mult in FINE_MULTIPLES:
            reductions, drops = [], []
            for seed in range(5):
                res = run_pairs(delayed(projected, 0.2, window * mult, "random", malicious, seed, "m1"), key, window, threshold)
                reductions.append((base - res["alerts"]) / base)
                drops.append(res["dropped_late"])
            row[str(mult)] = {"reduction": statistics.fmean(reductions), "dropped": statistics.fmean(drops)}
        out[name] = row
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=ROOT / "config" / "rule_catalog.json")
    parser.add_argument("--results", type=Path, default=V2)
    parser.add_argument("--cache", type=Path, default=ROOT / "data" / "p1" / "cache")
    parser.add_argument("--output", type=Path, default=V2 / "exploratory.json")
    parser.add_argument("--no-fine-grid", action="store_true",
                        help="skip part 3, which needs the projection cache built from the raw logs")
    args = parser.parse_args()
    ordering = load(args.results / "m1_ordering_sweep.jsonl")
    targeting = load(args.results / "m1_targeting_sweep.jsonl")
    catalogue = json.loads(args.catalog.read_text(encoding="utf-8"))
    result = {"schema": "v2-exploratory-v1",
              "subject_loss": subject_loss(ordering, targeting),
              "trace_size": trace_size(ordering, targeting),
              "fine_grid_h201_20pct": None if args.no_fine_grid else fine_grid(catalogue, args.cache)}
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
