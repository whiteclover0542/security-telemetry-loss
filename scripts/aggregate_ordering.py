"""Aggregate the ordering-distortion sweep into the two questions it was built for.

Q1: is a delay matched to the rule window worse than a much larger one, and does
    that depend on rule density? For each rule and case, report mean alert
    reduction against delay size, and flag whether the worst delay is interior
    (a peak near the window) or at the largest size (monotone).

Q2: does targeting the attacker's own events evade with less delay than random?
    Compare targeted against random at the same fraction and delay size.

Seeds are averaged; their spread is reported so a small mean with large spread is
not read as a stable effect.
"""
import argparse
import json
from collections import defaultdict
from pathlib import Path
import statistics


def load(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def summarise(values):
    clean = [v for v in values if v is not None]
    if not clean:
        return None
    return {
        "n": len(clean),
        "mean": statistics.fmean(clean),
        "sd": statistics.stdev(clean) if len(clean) > 1 else 0.0,
        "max": max(clean),
    }


def aggregate(records):
    # key: (case, rule, structure, fraction, multiple) -> list of reductions
    cells = defaultdict(list)
    keys_lost = defaultdict(list)
    dropped = defaultdict(list)
    meta = {}
    for r in records:
        k = (r["case"], r["rule"], r["delay_structure"], r["delay_fraction"], r["delay_multiple"])
        cells[k].append(r["alert_reduction"])
        keys_lost[k].append(r["keys_lost"])
        dropped[k].append(r["dropped_late"])
        meta[(r["case"], r["rule"])] = {
            "baseline_alerts": r["baseline_alerts"],
            "baseline_keys": r["baseline_keys"],
            "window_seconds": r["window_seconds"],
            "threshold": r["threshold"],
        }

    rows = []
    for k, reductions in cells.items():
        case, rule, structure, fraction, mult = k
        rows.append({
            "case": case, "rule": rule, "structure": structure,
            "fraction": fraction, "multiple": mult,
            "reduction": summarise(reductions),
            "keys_lost": summarise(keys_lost[k]),
            "dropped_late": summarise(dropped[k]),
            **meta[(case, rule)],
        })

    # Q1: shape of reduction vs delay size, per rule/case/structure/fraction.
    curves = defaultdict(dict)
    for row in rows:
        ck = (row["case"], row["rule"], row["structure"], row["fraction"])
        curves[ck][row["multiple"]] = row["reduction"]["mean"] if row["reduction"] else 0.0
    q1 = []
    for ck, by_mult in curves.items():
        case, rule, structure, fraction = ck
        mults = sorted(by_mult)
        means = [by_mult[m] for m in mults]
        peak_i = max(range(len(means)), key=lambda i: means[i])
        q1.append({
            "case": case, "rule": rule, "structure": structure, "fraction": fraction,
            "by_multiple": {str(m): round(by_mult[m], 4) for m in mults},
            "worst_multiple": mults[peak_i],
            "worst_is_interior": 0 < peak_i < len(means) - 1,
            "worst_is_largest": peak_i == len(means) - 1,
        })

    # Q2: targeted vs random at matched fraction and delay size.
    q2 = []
    by_cell = {(r["case"], r["rule"], r["structure"], r["fraction"], r["multiple"]):
               (r["reduction"]["mean"] if r["reduction"] else 0.0) for r in rows}
    seen = {(c, ru, f, m) for (c, ru, s, f, m) in by_cell}
    for (case, rule, fraction, mult) in sorted(seen):
        rnd = by_cell.get((case, rule, "random", fraction, mult))
        tgt = by_cell.get((case, rule, "targeted", fraction, mult))
        if rnd is None or tgt is None:
            continue
        q2.append({
            "case": case, "rule": rule, "fraction": fraction, "multiple": mult,
            "random_reduction": round(rnd, 4),
            "targeted_reduction": round(tgt, 4),
            "targeted_advantage": round(tgt - rnd, 4),
        })

    return {"schema": "ordering-aggregate-v1", "records": len(records),
            "rows": rows, "q1_delay_shape": q1, "q2_targeting": q2}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = aggregate(load(args.records))
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2)
        stream.write("\n")

    # Console overview.
    print(f"records: {summary['records']:,}\n")
    print("Q1 worst delay size (interior peak = 'small delay worst'):")
    for q in summary["q1_delay_shape"]:
        if q["structure"] == "random" and q["fraction"] == 0.20:
            shape = "INTERIOR" if q["worst_is_interior"] else ("largest" if q["worst_is_largest"] else "smallest")
            print(f"  {q['case']:<5} {q['rule']:<14} worst={q['worst_multiple']:>4}x [{shape}]  {q['by_multiple']}")
    print("\nQ2 targeted advantage (mean over cases, fraction 0.20, multiple 1):")
    adv = defaultdict(list)
    for q in summary["q2_targeting"]:
        if q["fraction"] == 0.20 and q["multiple"] == 1:
            adv[q["rule"]].append(q["targeted_advantage"])
    for rule, vals in adv.items():
        print(f"  {rule:<14} random->targeted advantage {statistics.fmean(vals):+.4f}")


if __name__ == "__main__":
    main()
