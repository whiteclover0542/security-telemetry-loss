"""Re-measure targeted delay by whether the attacker's own detection is evaded.

The main sweep measured total alert reduction, which dilutes a targeted delay:
the attacker's events are a small share of all alerts. Here the dependent variable
is malicious-subject detection - whether a pid on the malicious list still raises
an alert - so random and targeted delay are compared on the thing an attacker
actually cares about.

Only pid-keyed rules are meaningful here, since the malicious label is a set of
pids. Delaying only malicious-pid events (targeted) is compared against delaying a
random fraction, at matched fraction and delay size.
"""
import argparse
from datetime import datetime
import json
from pathlib import Path
import platform
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from rule_engine import SlidingWindowRule
from ordering_sweep import CASE_SOURCES, load_case, project


def alerting_malicious(pairs_with_pid, key, window_seconds, threshold, malicious):
    """Return the set of malicious pids that raise at least one alert."""
    rule = SlidingWindowRule("r", key, window_seconds, threshold)
    fired = set()
    for event_time, value, pid in pairs_with_pid:
        alert = rule.process(event_time, {key: value})
        if alert is not None and pid in malicious:
            fired.add(pid)
    return fired


def delayed_with_pid(projected, fraction, delay, structure, malicious, seed):
    rng = random.Random(seed)
    eligible = [i for i, (_, _, pid) in enumerate(projected)
                if structure == "random" or pid in malicious]
    if not eligible:
        return None
    chosen = set(rng.sample(eligible, max(1, int(len(eligible) * fraction))))
    moved = [((t + delay if i in chosen else t), v, pid)
             for i, (t, v, pid) in enumerate(projected)]
    moved.sort(key=lambda row: row[0])
    return moved


def sweep(catalogue, stream):
    written = 0
    pid_rules = [r for r in catalogue["rules"] if r["key"] == "pid"]
    for case in catalogue["sweep"]["cases"]:
        events, malicious = load_case(case)
        for rule in pid_rules:
            projected = project(events, rule)
            key, w, thr = rule["key"], rule["window_seconds"], rule["threshold"]
            base_fired = alerting_malicious(projected, key, w, thr, malicious)
            if not base_fired:
                continue  # no malicious subject detected at baseline; nothing to evade
            for fraction in catalogue["sweep"]["delay_fractions"]:
                for mult in catalogue["sweep"]["delay_multiples_of_window"]:
                    delay = w * mult
                    for structure in ("random", "targeted"):
                        for seed in range(catalogue["sweep"]["seeds"]):
                            moved = delayed_with_pid(projected, fraction, delay, structure, malicious, seed)
                            if moved is None:
                                continue
                            fired = alerting_malicious(moved, key, w, thr, malicious)
                            evaded = base_fired - fired
                            stream.write(json.dumps({
                                "schema": "targeting-sweep-v1",
                                "case": case, "rule": rule["name"],
                                "delay_fraction": fraction, "delay_multiple": mult,
                                "delay_seconds": delay, "delay_structure": structure,
                                "seed": seed,
                                "baseline_malicious_detected": len(base_fired),
                                "malicious_detected": len(fired),
                                "malicious_evaded": len(evaded),
                                "malicious_evasion_rate": len(evaded) / len(base_fired),
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
            "schema": "targeting-sweep-manifest-v1",
            "python": platform.python_version(),
            "records_written": written,
            "seconds": round(elapsed, 1),
            "dependent_variable": "malicious-subject evasion rate",
            "note": "Only pid-keyed rules; malicious label is a set of pids.",
        }, stream, indent=2)
        stream.write("\n")
    print(f"{written:,} records in {elapsed:.1f}s -> {args.output}", flush=True)


if __name__ == "__main__":
    main()
