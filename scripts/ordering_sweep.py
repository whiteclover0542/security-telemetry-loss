"""Sweep arrival-order distortion across rules, cases, delay sizes and structures.

For each rule in the catalogue and each case, this establishes the no-distortion
baseline, then delays a fraction of events and re-runs the rule. Two things are
being tested: whether a delay matched to the window is worse than a much larger
one (the P1 observation), and whether delaying only the attacker's own events
(targeted) evades with less delay than delaying at random.

No event is ever removed. Only arrival times move. Delayed events are re-sorted
into arrival order before the rule sees them, exactly as a pipeline would deliver
them.
"""
import argparse
from datetime import datetime
import gzip
import json
from pathlib import Path
import platform
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from rule_engine import SlidingWindowRule, run_rule

CASE_SOURCES = {
    "h201": ("data/inria_selected/2019-09-23/AIA-201-225.ecar-2019-09-23-sysclient0201.json.gz",
             "data/windows/scenario-1.json", "preliminary/data/labels/scenario-1.json"),
    "h501": ("data/inria_selected/2019-09-24/AIA-501-525.ecar-2019-09-24-sysclient0501.json.gz",
             "data/windows/scenario-2.json", "preliminary/data/labels/scenario-2.json"),
    "h051": ("data/inria_selected/2019-09-25/AIA-51-75.ecar-2019-09-25-sysclient0051.json.gz",
             "data/windows/scenario-3.json", "preliminary/data/labels/scenario-3.json"),
}


def load_case(case):
    rel, wpath, lpath = CASE_SOURCES[case]
    window = json.loads((ROOT / wpath).read_text())
    start = datetime.fromisoformat(window["window_start"]).timestamp()
    end = datetime.fromisoformat(window["window_end"]).timestamp()
    events = []
    with gzip.open(ROOT / rel, "rt", encoding="utf-8") as stream:
        for line in stream:
            e = json.loads(line)
            t = datetime.fromisoformat(e["timestamp"]).timestamp()
            if t >= end:
                break
            if t >= start:
                events.append((t, e))
    label = json.loads((ROOT / lpath).read_text())
    malicious_pids = {p for p in label["label_pids"] if p is not None}
    return events, malicious_pids


def project(events, rule):
    """Reduce events to (time, key) pairs this rule groups on."""
    actions = rule["action"] if isinstance(rule["action"], list) else [rule["action"]]
    obj, key = rule["object"], rule["key"]
    out = []
    for t, e in events:
        if e.get("object") != obj or e.get("action") not in actions:
            continue
        val = e.get("pid") if key == "pid" else e.get("properties", {}).get(key)
        if val is not None:
            out.append((t, val, e.get("pid")))
    return out


def run_pairs(pairs, key, window_seconds, threshold):
    """Run a rule over (time, key_value) pairs without rebuilding event dicts."""
    rule = SlidingWindowRule("r", key, window_seconds, threshold)
    for event_time, value in pairs:
        rule.process(event_time, {key: value})
    return {
        "alerts": len(rule.alerts),
        "alert_keys": {a["key"] for a in rule.alerts},
        "dropped_late": rule.dropped_late,
    }


def run(projected, key, window_seconds, threshold):
    result = run_pairs([(t, v) for t, v, _ in projected], key, window_seconds, threshold)
    return {"alerts": result["alerts"], "alert_keys": sorted(result["alert_keys"]),
            "dropped_late": result["dropped_late"]}


def delayed(projected, fraction, delay, structure, malicious_pids, seed):
    """Delay a fraction of events; targeted picks only malicious-pid events.

    Returns (time, key_value) pairs in arrival order, or None if nothing is
    eligible to delay.
    """
    rng = random.Random(seed)
    eligible = [i for i, (_, _, pid) in enumerate(projected)
                if structure == "random" or pid in malicious_pids]
    if not eligible:
        return None
    chosen = set(rng.sample(eligible, max(1, int(len(eligible) * fraction))))
    moved = [((t + delay if i in chosen else t), v)
             for i, (t, v, _) in enumerate(projected)]
    moved.sort(key=lambda row: row[0])
    return moved


def sweep(catalogue, stream):
    written = 0
    for case in catalogue["sweep"]["cases"]:
        events, malicious = load_case(case)
        for rule in catalogue["rules"]:
            projected = project(events, rule)
            key, w, thr = rule["key"], rule["window_seconds"], rule["threshold"]
            base = run(projected, key, w, thr)
            base_alerts, base_keys = base["alerts"], set(base["alert_keys"])

            for fraction in catalogue["sweep"]["delay_fractions"]:
                for mult in catalogue["sweep"]["delay_multiples_of_window"]:
                    delay = w * mult
                    for structure in catalogue["sweep"]["delay_structures"]:
                        for seed in range(catalogue["sweep"]["seeds"]):
                            moved = delayed(projected, fraction, delay, structure, malicious, seed)
                            if moved is None:
                                continue
                            res = run_pairs(moved, key, w, thr)
                            lost_keys = base_keys - res["alert_keys"]
                            stream.write(json.dumps({
                                "schema": "ordering-sweep-v1",
                                "case": case, "rule": rule["name"],
                                "window_seconds": w, "threshold": thr,
                                "delay_fraction": fraction,
                                "delay_multiple": mult, "delay_seconds": delay,
                                "delay_structure": structure, "seed": seed,
                                "baseline_alerts": base_alerts,
                                "alerts": res["alerts"],
                                "alerts_lost": base_alerts - res["alerts"],
                                "alert_reduction": (base_alerts - res["alerts"]) / base_alerts if base_alerts else None,
                                "baseline_keys": len(base_keys),
                                "keys_lost": len(lost_keys),
                                "dropped_late": res["dropped_late"],
                            }) + "\n")
                            written += 1
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=ROOT / "config" / "rule_catalog.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    catalogue = json.loads(args.catalog.read_text(encoding="utf-8"))

    began = time.time()
    with args.output.open("x", encoding="utf-8") as stream:
        written = sweep(catalogue, stream)
    elapsed = time.time() - began

    with args.output.with_suffix(".manifest.json").open("x", encoding="utf-8") as stream:
        json.dump({
            "schema": "ordering-sweep-manifest-v1",
            "python": platform.python_version(),
            "records_written": written,
            "seconds": round(elapsed, 1),
            "sweep": catalogue["sweep"],
            "note": "No event removed; only arrival order changes. Delayed events re-sorted into arrival order.",
        }, stream, indent=2)
        stream.write("\n")
    print(f"{written:,} records in {elapsed:.1f}s -> {args.output}", flush=True)


if __name__ == "__main__":
    main()
