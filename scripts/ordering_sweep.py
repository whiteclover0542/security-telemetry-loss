"""Sweep arrival-order distortion across rules, cases, delay sizes and structures.

For each rule in the catalogue and each case, this establishes the no-distortion
baseline, then delays a fraction of events and re-runs the rule. No event is
ever removed by a delay; only arrival times move.

Two distortion models are available, because pipelines differ in which clock the
detector sees:

- m2 (arrival-time stamping): the delayed arrival time becomes the event time.
  The rule sees a monotone stream, so nothing is ever late; an event is only
  displaced into a later window.
- m1 (occurrence time preserved): events arrive in arrival order but carry their
  original occurrence time, so the rule sees out-of-order input and drops events
  whose window the watermark has already retired.

The `delete` structure removes the same events random delay would have chosen,
as a control: under m1, a delay beyond the window should cost what deleting
those events costs.
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
from sweep_common import CaseSource, provenance, select, write_manifest

CASE_SOURCES = {
    "h201": ("data/inria_selected/2019-09-23/AIA-201-225.ecar-2019-09-23-sysclient0201.json.gz",
             "data/windows/scenario-1.json", "preliminary/data/labels/scenario-1.json"),
    "h501": ("data/inria_selected/2019-09-24/AIA-501-525.ecar-2019-09-24-sysclient0501.json.gz",
             "data/windows/scenario-2.json", "preliminary/data/labels/scenario-2.json"),
    "h051": ("data/inria_selected/2019-09-25/AIA-51-75.ecar-2019-09-25-sysclient0051.json.gz",
             "data/windows/scenario-3.json", "preliminary/data/labels/scenario-3.json"),
}
MODELS = ("m1", "m2")


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
    process = rule.process_key
    for event_time, value in pairs:
        if value is not None:
            process(event_time, value)
    return {
        "alerts": len(rule.alerts),
        "alert_keys": {a["key"] for a in rule.alerts},
        "dropped_late": rule.dropped_late,
    }


def run(projected, key, window_seconds, threshold):
    result = run_pairs([(t, v) for t, v, _ in projected], key, window_seconds, threshold)
    return {"alerts": result["alerts"], "alert_keys": sorted(result["alert_keys"]),
            "dropped_late": result["dropped_late"]}


def choose(projected, fraction, structure, malicious_pids, seed):
    """Indices to delay (or delete). None when targeting finds nothing to pick."""
    rng = random.Random(seed)
    eligible = [i for i, (_, _, pid) in enumerate(projected)
                if structure != "targeted" or pid in malicious_pids]
    if not eligible:
        return None
    return set(rng.sample(eligible, max(1, int(len(eligible) * fraction))))


def delayed(projected, fraction, delay, structure, malicious_pids, seed, model="m2"):
    """Distort the stream; return (time the rule sees, key_value) in arrival order.

    Returns None if nothing is eligible to delay.
    """
    chosen = choose(projected, fraction, structure, malicious_pids, seed)
    if chosen is None:
        return None
    if structure == "delete":
        return [(t, v) for i, (t, v, _) in enumerate(projected) if i not in chosen]
    moved = [((t + delay if i in chosen else t), t, v) for i, (t, v, _) in enumerate(projected)]
    moved.sort(key=lambda row: row[0])
    if model == "m2":
        return [(arrival, v) for arrival, _, v in moved]
    if model == "m1":
        return [(occurrence, v) for _, occurrence, v in moved]
    raise ValueError(f"unknown model {model!r}")


def sweep(catalogue, stream, model, cases, rules, fractions, multiples, structures, seeds, source):
    written = 0
    for case in cases:
        for rule in rules:
            projected, malicious = source.get(case, rule)
            key, w, thr = rule["key"], rule["window_seconds"], rule["threshold"]
            base = run(projected, key, w, thr)
            base_alerts, base_keys = base["alerts"], set(base["alert_keys"])

            for fraction in fractions:
                for mult in multiples:
                    delay = w * mult
                    for structure in structures:
                        if structure == "delete" and mult != multiples[0]:
                            continue  # deletion does not depend on delay size
                        for seed in range(seeds):
                            moved = delayed(projected, fraction, delay, structure, malicious, seed, model)
                            if moved is None:
                                continue
                            res = run_pairs(moved, key, w, thr)
                            lost_keys = base_keys - res["alert_keys"]
                            stream.write(json.dumps({
                                "schema": "ordering-sweep-v2",
                                "model": model,
                                "case": case, "rule": rule["name"],
                                "window_seconds": w, "threshold": thr,
                                "delay_fraction": fraction,
                                "delay_multiple": None if structure == "delete" else mult,
                                "delay_seconds": None if structure == "delete" else delay,
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
    parser.add_argument("--model", choices=MODELS, required=True)
    parser.add_argument("--cases", nargs="+", help="subset of catalogue cases")
    parser.add_argument("--rules", nargs="+", help="subset of catalogue rule names")
    parser.add_argument("--fractions", type=float, nargs="+")
    parser.add_argument("--multiples", type=float, nargs="+")
    parser.add_argument("--structures", nargs="+", choices=("random", "targeted", "delete"))
    parser.add_argument("--seeds", type=int)
    parser.add_argument("--cache", type=Path, help="projection cache directory")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    catalogue = json.loads(args.catalog.read_text(encoding="utf-8"))
    grid = catalogue["sweep"]
    cases = select(grid["cases"], args.cases)
    rules = [r for r in catalogue["rules"] if not args.rules or r["name"] in args.rules]
    fractions = args.fractions or grid["delay_fractions"]
    multiples = args.multiples or grid["delay_multiples_of_window"]
    structures = args.structures or grid["delay_structures"]
    seeds = args.seeds or grid["seeds"]

    began = time.time()
    with args.output.open("x", encoding="utf-8") as stream:
        written = sweep(catalogue, stream, args.model, cases, rules, fractions, multiples,
                        structures, seeds, CaseSource(args.cache))
    elapsed = time.time() - began

    write_manifest(args.output, provenance({
        "schema": "ordering-sweep-manifest-v2",
        "python": platform.python_version(),
        "records_written": written,
        "seconds": round(elapsed, 1),
        "model": args.model,
        "sweep": {"cases": cases, "rules": [r["name"] for r in rules], "delay_fractions": fractions,
                  "delay_multiples_of_window": multiples, "delay_structures": structures, "seeds": seeds},
        "note": "Delays remove no event; delete is a control that removes the events random delay would pick.",
    }))
    print(f"{written:,} records in {elapsed:.1f}s -> {args.output}", flush=True)


if __name__ == "__main__":
    main()
