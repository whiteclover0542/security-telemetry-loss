"""Measure the reorder-buffer mitigation: evasion blocked versus detection delay.

For each pid-keyed rule and case, an attacker delays a fraction of events. A
reorder buffer of increasing size sits in front of the rule. This records, per
buffer size, how much of the evasion is undone. The cost of a buffer of size B is
exactly B seconds of detection latency.

Occurrence time is preserved through the delay (only arrival moves), which is
the m1 model: the buffer can only sort events back because they still carry it.

Delay shapes, each with mean D (the delay multiple times the window):

- fixed: every chosen event is delayed by exactly D.
- uniform: delay drawn from U(0, 2D), so the largest delay is 2D.
- lognormal: delay drawn from a lognormal with mean D and sigma 1; no upper bound.
- burst: the stream is cut into window-length slots and whole slots are delayed by
  D until the fraction is covered, as a backpressure episode would.

A buffer at least as large as every delay restores occurrence order exactly, so
fixed and burst are fully undone at B >= D and uniform at B >= 2D by
construction. What the sweep measures is everything below that.
"""
import argparse
import json
import math
from pathlib import Path
import platform
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from ordering_sweep import run_pairs
from reorder_buffer import reorder
from sweep_common import CaseSource, provenance, select, write_manifest

DISTRIBUTIONS = ("fixed", "uniform", "lognormal", "burst")
LOGNORMAL_SIGMA = 1.0


def _delay_rng(seed):
    # Separate stream so the chosen events match fixed delay for the same seed.
    return random.Random(seed * 1_000_003 + 17)


def distort(projected, fraction, delay, seed, dist="fixed", window=None):
    """Delay a fraction of events; return (arrival, occurrence, key) in arrival order."""
    n = len(projected)
    k = max(1, int(n * fraction))
    rng = random.Random(seed)
    if dist == "burst":
        start = projected[0][0]
        slots = {}
        for i, (t, _, _) in enumerate(projected):
            slots.setdefault(int((t - start) // window), []).append(i)
        order = list(slots)
        rng.shuffle(order)
        chosen = set()
        for slot in order:
            if len(chosen) >= k:
                break
            chosen.update(slots[slot])
        delays = dict.fromkeys(chosen, delay)
    else:
        chosen = rng.sample(range(n), k)
        if dist == "fixed":
            delays = dict.fromkeys(chosen, delay)
        else:
            drng = _delay_rng(seed)
            if dist == "uniform":
                delays = {i: drng.uniform(0, 2 * delay) for i in sorted(chosen)}
            elif dist == "lognormal":
                mu = math.log(delay) - LOGNORMAL_SIGMA ** 2 / 2
                delays = {i: drng.lognormvariate(mu, LOGNORMAL_SIGMA) for i in sorted(chosen)}
            else:
                raise ValueError(f"unknown distribution {dist!r}")
    moved = [((t + delays[i] if i in delays else t), t, v) for i, (t, v, _) in enumerate(projected)]
    moved.sort(key=lambda row: row[0])
    return moved


def sweep(stream, cases, rules, fractions, multiples, buffer_multiples, seeds, dist, source):
    written = 0
    for case in cases:
        for rule in rules:
            projected, _ = source.get(case, rule)
            key, w, thr = rule["key"], rule["window_seconds"], rule["threshold"]
            base = run_pairs([(t, v) for t, v, _ in projected], key, w, thr)
            base_alerts = base["alerts"]
            if not base_alerts:
                continue
            for fraction in fractions:
                for delay_mult in multiples:
                    delay = w * delay_mult
                    for seed in range(seeds):
                        moved = distort(projected, fraction, delay, seed, dist, w)
                        max_delay = max(a - o for a, o, _ in moved)
                        for buf_mult in buffer_multiples:
                            buffer_seconds = w * buf_mult
                            released = reorder(
                                [(a, o, {key: v}) for a, o, v in moved], buffer_seconds)
                            res = run_pairs([(o, e[key]) for o, e in released], key, w, thr)
                            stream.write(json.dumps({
                                "schema": "mitigation-sweep-v2",
                                "delay_distribution": dist,
                                "case": case, "rule": rule["name"],
                                "delay_fraction": fraction,
                                "delay_multiple": delay_mult, "delay_seconds": delay,
                                "max_delay_seconds": max_delay,
                                "buffer_multiple": buf_mult, "buffer_seconds": buffer_seconds,
                                "seed": seed,
                                "baseline_alerts": base_alerts,
                                "alerts": res["alerts"],
                                "alerts_evaded": base_alerts - res["alerts"],
                                "evasion_remaining": (base_alerts - res["alerts"]) / base_alerts,
                                "dropped_late": res["dropped_late"],
                                "detection_delay_seconds": buffer_seconds,
                            }) + "\n")
                            written += 1
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=ROOT / "config" / "rule_catalog.json")
    parser.add_argument("--buffer-multiples", type=float, nargs="+",
                        default=[0, 0.5, 1, 2, 5, 10], help="buffer sizes as window multiples")
    parser.add_argument("--distribution", choices=DISTRIBUTIONS, default="fixed")
    parser.add_argument("--cases", nargs="+")
    parser.add_argument("--rules", nargs="+")
    parser.add_argument("--fractions", type=float, nargs="+")
    parser.add_argument("--multiples", type=float, nargs="+")
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    catalogue = json.loads(args.catalog.read_text(encoding="utf-8"))
    grid = catalogue["sweep"]
    cases = select(grid["cases"], args.cases)
    rules = [r for r in catalogue["rules"] if r["key"] == "pid" and (not args.rules or r["name"] in args.rules)]
    fractions = args.fractions or grid["delay_fractions"]
    multiples = args.multiples or grid["delay_multiples_of_window"]

    began = time.time()
    with args.output.open("x", encoding="utf-8") as stream:
        written = sweep(stream, cases, rules, fractions, multiples, args.buffer_multiples,
                        args.seeds, args.distribution, CaseSource(args.cache))
    elapsed = time.time() - began

    write_manifest(args.output, provenance({
        "schema": "mitigation-sweep-manifest-v2",
        "python": platform.python_version(),
        "records_written": written, "seconds": round(elapsed, 1),
        "delay_distribution": args.distribution,
        "sweep": {"cases": cases, "rules": [r["name"] for r in rules], "delay_fractions": fractions,
                  "delay_multiples_of_window": multiples, "buffer_multiples": args.buffer_multiples,
                  "seeds": args.seeds},
        "note": "m1 model: occurrence time preserved, buffer sorts toward occurrence order. Buffer cost is equal detection latency.",
    }))
    print(f"{written:,} records in {elapsed:.1f}s -> {args.output}", flush=True)


if __name__ == "__main__":
    main()
