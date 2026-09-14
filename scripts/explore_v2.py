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
4. Alert-state semantics: the engine resets a key after it fires. An engine that
   never resets detects a key once any window-long span holds the threshold, so
   without drops it cannot lose a subject. This compares detected subjects under
   both semantics (h201, 20%, seeds 0-2) to see whether the reset changes who is
   missed.
5. Sensitivity of the targeting equivalence verdict to the malicious-subject
   count, since one subject moves the evasion rate by 1/N.
"""
import argparse
import bisect
from collections import defaultdict
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from ordering_sweep import delayed, run_pairs
from rule_engine import SlidingWindowRule
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


def detected_with_reset(pairs, key, window, threshold):
    rule = SlidingWindowRule("r", key, window, threshold)
    fired = set()
    for t, value in pairs:
        if rule.process_key(t, value) is not None:
            fired.add(value)
    return fired, rule.dropped_late


def detected_without_reset(pairs, window, threshold):
    watermark, pending, detected, dropped = None, {}, set(), 0
    for t, key in pairs:
        if watermark is not None and t < watermark - window:
            dropped += 1
            continue
        if watermark is None or t > watermark:
            watermark = t
        if key in detected:
            continue
        times = pending.setdefault(key, [])
        cutoff = watermark - 2 * window
        if times and times[0] < cutoff:
            del times[:bisect.bisect_left(times, cutoff)]
        pos = bisect.bisect_right(times, t)
        times.insert(pos, t)
        best = 0
        for i in range(bisect.bisect_left(times, t - window), pos + 1):
            last = bisect.bisect_right(times, times[i] + window) - 1
            if last >= pos:
                best = max(best, last - i + 1)
        if best >= threshold:
            detected.add(key)
            del pending[key]
    return detected, dropped


def reset_semantics(catalogue, cache):
    rules = {r["name"]: r for r in catalogue["rules"]}
    out = {}
    for name in ("net_scan", "mass_file", "remote_thread", "module_load", "beacon"):
        rule = rules[name]
        projected, malicious = read_cache(cache, "h201", name)
        key, window, threshold = rule["key"], rule["window_seconds"], rule["threshold"]
        inorder = [(t, v) for t, v, _ in projected]
        base_reset, _ = detected_with_reset(inorder, key, window, threshold)
        base_keep, _ = detected_without_reset(inorder, window, threshold)
        row = {"baseline_subjects_equal": base_reset == base_keep, "baseline_subjects": len(base_reset)}
        for mult in (0.5, 0.9, 1.0, 1.1, 2.0):
            lost_reset, lost_keep, drops = [], [], []
            for seed in range(3):
                pairs = delayed(projected, 0.2, window * mult, "random", malicious, seed, "m1")
                fired_reset, dropped = detected_with_reset(pairs, key, window, threshold)
                fired_keep, _ = detected_without_reset(pairs, window, threshold)
                lost_reset.append(len(base_reset - fired_reset))
                lost_keep.append(len(base_keep - fired_keep))
                drops.append(dropped)
            row[str(mult)] = {"lost_with_reset": lost_reset, "lost_without_reset": lost_keep, "dropped": drops}
        out[name] = row
    return out


def equivalence_sensitivity(analysis):
    out = {}
    for model, verdict in analysis["H4"].items():
        bands = {}
        for label, low, high in (("n_at_least_20", 20, None), ("n_5_to_19", 5, 20), ("n_below_5", 0, 5)):
            cells = [c for c in verdict["cells_detail"]
                     if c["baseline_malicious"] >= low and (high is None or c["baseline_malicious"] < high)]
            bands[label] = {"cells": len(cells),
                            "equivalent_share": sum(c["equivalent"] for c in cells) / len(cells),
                            "targeted_advantage": [{k: c[k] for k in ("rule", "case", "fraction", "multiple", "baseline_malicious", "delta", "ci95")}
                                                   for c in cells if c["direction"] == "targeted"],
                            "random_advantage_cells": sum(c["direction"] == "random" for c in cells)}
        out[model] = bands
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=ROOT / "config" / "rule_catalog.json")
    parser.add_argument("--results", type=Path, default=V2)
    parser.add_argument("--cache", type=Path, default=ROOT / "data" / "p1" / "cache")
    parser.add_argument("--output", type=Path, default=V2 / "exploratory.json")
    parser.add_argument("--no-fine-grid", action="store_true",
                        help="skip parts 3 and 4, which need the projection cache built from the raw logs")
    args = parser.parse_args()
    ordering = load(args.results / "m1_ordering_sweep.jsonl")
    targeting = load(args.results / "m1_targeting_sweep.jsonl")
    catalogue = json.loads(args.catalog.read_text(encoding="utf-8"))
    result = {"schema": "v2-exploratory-v1",
              "subject_loss": subject_loss(ordering, targeting),
              "trace_size": trace_size(ordering, targeting),
              "fine_grid_h201_20pct": None if args.no_fine_grid else fine_grid(catalogue, args.cache),
              "reset_semantics_h201_20pct": None if args.no_fine_grid else reset_semantics(catalogue, args.cache),
              "equivalence_sensitivity": equivalence_sensitivity(
                  json.loads((args.results / "analysis.json").read_text(encoding="utf-8")))}
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
