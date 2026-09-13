"""Re-measure targeted delay by whether the attacker's own detection is evaded.

The main sweep measured total alert reduction, which dilutes a targeted delay:
the attacker's events are a small share of all alerts. Here the dependent variable
is malicious-subject detection - whether a pid on the malicious list still raises
an alert - so random and targeted delay are compared on the thing an attacker
actually cares about.

Only pid-keyed rules are meaningful here, since the malicious label is a set of
pids. Delaying only malicious-pid events (targeted) is compared against delaying a
random fraction, at matched fraction and delay size, under either distortion
model (see ordering_sweep).
"""
import argparse
import json
from pathlib import Path
import platform
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from rule_engine import SlidingWindowRule
from ordering_sweep import MODELS, choose
from sweep_common import CaseSource, provenance, select, write_manifest


def alerting_malicious(pairs_with_pid, key, window_seconds, threshold, malicious):
    """Return the set of malicious pids that raise at least one alert."""
    rule = SlidingWindowRule("r", key, window_seconds, threshold)
    fired = set()
    for event_time, value, pid in pairs_with_pid:
        alert = rule.process(event_time, {key: value})
        if alert is not None and pid in malicious:
            fired.add(pid)
    return fired


def delayed_with_pid(projected, fraction, delay, structure, malicious, seed, model="m2"):
    chosen = choose(projected, fraction, structure, malicious, seed)
    if chosen is None:
        return None
    moved = [((t + delay if i in chosen else t), t, v, pid)
             for i, (t, v, pid) in enumerate(projected)]
    moved.sort(key=lambda row: row[0])
    if model == "m2":
        return [(arrival, v, pid) for arrival, _, v, pid in moved]
    if model == "m1":
        return [(occurrence, v, pid) for _, occurrence, v, pid in moved]
    raise ValueError(f"unknown model {model!r}")


def sweep(stream, model, cases, rules, fractions, multiples, seeds, source):
    written = 0
    for case in cases:
        for rule in rules:
            projected, malicious = source.get(case, rule)
            key, w, thr = rule["key"], rule["window_seconds"], rule["threshold"]
            base_fired = alerting_malicious(projected, key, w, thr, malicious)
            if not base_fired:
                continue  # no malicious subject detected at baseline; nothing to evade
            for fraction in fractions:
                for mult in multiples:
                    delay = w * mult
                    for structure in ("random", "targeted"):
                        for seed in range(seeds):
                            moved = delayed_with_pid(projected, fraction, delay, structure, malicious, seed, model)
                            if moved is None:
                                continue
                            fired = alerting_malicious(moved, key, w, thr, malicious)
                            evaded = base_fired - fired
                            stream.write(json.dumps({
                                "schema": "targeting-sweep-v2",
                                "model": model,
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
    parser.add_argument("--model", choices=MODELS, required=True)
    parser.add_argument("--cases", nargs="+")
    parser.add_argument("--rules", nargs="+")
    parser.add_argument("--fractions", type=float, nargs="+")
    parser.add_argument("--multiples", type=float, nargs="+")
    parser.add_argument("--seeds", type=int)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    catalogue = json.loads(args.catalog.read_text(encoding="utf-8"))
    grid = catalogue["sweep"]
    cases = select(grid["cases"], args.cases)
    rules = [r for r in catalogue["rules"] if r["key"] == "pid" and (not args.rules or r["name"] in args.rules)]
    fractions = args.fractions or grid["delay_fractions"]
    multiples = args.multiples or grid["delay_multiples_of_window"]
    seeds = args.seeds or grid["seeds"]

    began = time.time()
    with args.output.open("x", encoding="utf-8") as stream:
        written = sweep(stream, args.model, cases, rules, fractions, multiples, seeds, CaseSource(args.cache))
    elapsed = time.time() - began

    write_manifest(args.output, provenance({
        "schema": "targeting-sweep-manifest-v2",
        "python": platform.python_version(),
        "records_written": written,
        "seconds": round(elapsed, 1),
        "model": args.model,
        "dependent_variable": "malicious-subject evasion rate",
        "sweep": {"cases": cases, "rules": [r["name"] for r in rules], "delay_fractions": fractions,
                  "delay_multiples_of_window": multiples, "seeds": seeds},
        "note": "Only pid-keyed rules; malicious label is a set of pids.",
    }))
    print(f"{written:,} records in {elapsed:.1f}s -> {args.output}", flush=True)


if __name__ == "__main__":
    main()
