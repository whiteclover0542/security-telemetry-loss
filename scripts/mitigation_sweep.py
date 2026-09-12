"""Measure the reorder-buffer mitigation: evasion blocked versus detection delay.

For each pid-keyed rule and case, an attacker delays a fraction of events by a
fixed amount. A reorder buffer of increasing size sits in front of the rule. This
records, per buffer size, how much of the evasion is undone. The cost of a buffer
of size B is exactly B seconds of detection latency, so the result is read as:
to defend against a delay of D, the buffer must reach D, and every detection is
then held back by D.

Occurrence time is preserved through the delay (only arrival moves), matching P2,
so the buffer can sort events back toward occurrence order.
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
from ordering_sweep import CASE_SOURCES, load_case, project, run_pairs
from reorder_buffer import reorder


def distort(projected, fraction, delay, seed):
    """Delay a fraction of events; return (arrival, occurrence, key) in arrival order."""
    rng = random.Random(seed)
    chosen = set(rng.sample(range(len(projected)), max(1, int(len(projected) * fraction))))
    moved = [((t + delay if i in chosen else t), t, v) for i, (t, v, _) in enumerate(projected)]
    moved.sort(key=lambda row: row[0])
    return moved


def sweep(catalogue, buffer_multiples, stream):
    written = 0
    pid_rules = [r for r in catalogue["rules"] if r["key"] == "pid"]
    for case in catalogue["sweep"]["cases"]:
        events, _ = load_case(case)
        for rule in pid_rules:
            projected = project(events, rule)
            key, w, thr = rule["key"], rule["window_seconds"], rule["threshold"]
            base = run_pairs([(t, v) for t, v, _ in projected], key, w, thr)
            base_alerts = base["alerts"]
            if not base_alerts:
                continue
            for fraction in catalogue["sweep"]["delay_fractions"]:
                for delay_mult in catalogue["sweep"]["delay_multiples_of_window"]:
                    delay = w * delay_mult
                    for seed in range(5):  # fewer seeds; the effect is a sharp threshold
                        moved = distort(projected, fraction, delay, seed)
                        for buf_mult in buffer_multiples:
                            buffer_seconds = w * buf_mult
                            released = reorder(
                                [(a, o, {key: v}) for a, o, v in moved], buffer_seconds)
                            res = run_pairs([(o, e[key]) for o, e in released], key, w, thr)
                            stream.write(json.dumps({
                                "schema": "mitigation-sweep-v1",
                                "case": case, "rule": rule["name"],
                                "delay_fraction": fraction,
                                "delay_multiple": delay_mult, "delay_seconds": delay,
                                "buffer_multiple": buf_mult, "buffer_seconds": buffer_seconds,
                                "seed": seed,
                                "baseline_alerts": base_alerts,
                                "alerts": res["alerts"],
                                "alerts_evaded": base_alerts - res["alerts"],
                                "evasion_remaining": (base_alerts - res["alerts"]) / base_alerts,
                                "detection_delay_seconds": buffer_seconds,
                            }) + "\n")
                            written += 1
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=ROOT / "config" / "rule_catalog.json")
    parser.add_argument("--buffer-multiples", type=float, nargs="+",
                        default=[0, 0.5, 1, 2, 5, 10], help="buffer sizes as window multiples")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    catalogue = json.loads(args.catalog.read_text(encoding="utf-8"))

    began = time.time()
    with args.output.open("x", encoding="utf-8") as stream:
        written = sweep(catalogue, args.buffer_multiples, stream)
    elapsed = time.time() - began

    with args.output.with_suffix(".manifest.json").open("x", encoding="utf-8") as stream:
        json.dump({
            "schema": "mitigation-sweep-manifest-v1",
            "python": platform.python_version(),
            "records_written": written, "seconds": round(elapsed, 1),
            "buffer_multiples": args.buffer_multiples,
            "note": "Occurrence time preserved through delay; buffer sorts toward occurrence order. Buffer cost is equal detection latency.",
        }, stream, indent=2)
        stream.write("\n")
    print(f"{written:,} records in {elapsed:.1f}s -> {args.output}", flush=True)


if __name__ == "__main__":
    main()
