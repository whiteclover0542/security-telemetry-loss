"""Evaluate the pre-registered v2 hypotheses (research/PREREGISTRATION_V2.md).

Written before the E1-E6 results were read. Every threshold below is the one the
registration fixes; changing any of them after seeing results is not allowed.
Standard library only, so the reproduction package needs nothing beyond Python.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import random
import statistics

ROOT = Path(__file__).resolve().parents[1]
V1 = ROOT / "data" / "p1"
V2 = V1 / "v2"
ZERO_DROP_MULTIPLES = (0.5, 0.75, 0.9, 1.0)
BEYOND_MULTIPLES = (2.0, 5.0, 10.0)
BOOT_SEED, BOOT_N, MARGIN = 20260913, 10_000, 0.05
PRIMARY_MIN_MALICIOUS = 5
DISTRIBUTIONS = ("fixed", "uniform", "lognormal", "burst")


def load(path):
    with open(path, encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def mean(values):
    return statistics.fmean(values)


def spearman(xs, ys):
    def ranks(values):
        order = sorted(range(len(values)), key=lambda i: values[i])
        out = [0.0] * len(values)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
                j += 1
            for k in range(i, j + 1):
                out[order[k]] = (i + j) / 2 + 1
            i = j + 1
        return out
    rx, ry = ranks(xs), ranks(ys)
    mx, my = mean(rx), mean(ry)
    cov = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    spread = (sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry)) ** 0.5
    return cov / spread if spread else None


def percentile(sorted_values, q):
    pos = (len(sorted_values) - 1) * q
    lo, hi = int(pos), min(int(pos) + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def bootstrap_diff(treated, control, rng):
    nt, nc = len(treated), len(control)
    diffs = sorted(sum(rng.choices(treated, k=nt)) / nt - sum(rng.choices(control, k=nc)) / nc
                   for _ in range(BOOT_N))
    return {q: percentile(diffs, q) for q in (0.025, 0.05, 0.95, 0.975)}


def check_propositions(m1, mitigation):
    pa = [r for r in m1 if r["delay_structure"] != "delete" and r["delay_multiple"] <= 1.0 and r["dropped_late"]]
    pb = [r for r in mitigation if r["buffer_seconds"] >= r["max_delay_seconds"] - 1e-6 and r["alerts_evaded"] != 0]
    return {"P-A_violations": len(pa), "P-B_violations": len(pb),
            "P-B_examples": [{k: r[k] for k in ("delay_distribution", "case", "rule", "delay_multiple", "buffer_multiple", "seed")}
                             for r in pb[:5]]}


def h0(pairs):
    fields = {"ordering": ("case", "rule", "delay_fraction", "delay_multiple", "delay_structure", "seed",
                           "baseline_alerts", "alerts", "alerts_lost", "keys_lost", "dropped_late"),
              "targeting": ("case", "rule", "delay_fraction", "delay_multiple", "delay_structure", "seed",
                            "baseline_malicious_detected", "malicious_detected", "malicious_evaded")}
    out = {}
    for name, (old, new) in pairs.items():
        mismatches = [i for i, (a, b) in enumerate(zip(old, new)) if any(a[f] != b[f] for f in fields[name])]
        out[name] = {"v1_records": len(old), "v2_records": len(new), "mismatches": len(mismatches),
                     "first_mismatches": mismatches[:5]}
    out["adopted"] = all(v["mismatches"] == 0 and v["v1_records"] == v["v2_records"] for v in out.values())
    return out


def cell_means(records, value, *keys):
    groups = defaultdict(list)
    for r in records:
        groups[tuple(r[k] for k in keys)].append(r[value])
    return {k: mean(v) for k, v in groups.items()}


def h1_h2_h3(m1, m2):
    delay = [r for r in m1 if r["delay_structure"] == "random"]
    delete = cell_means([r for r in m1 if r["delay_structure"] == "delete"], "alert_reduction", "rule", "case", "delay_fraction")
    m1_means = cell_means(delay, "alert_reduction", "rule", "case", "delay_fraction", "delay_multiple")
    drops = cell_means(delay, "dropped_late", "rule", "case", "delay_fraction", "delay_multiple")
    units = sorted({(r["rule"], r["case"]) for r in delay})

    h1_cells = []
    for (rule, case, fraction, mult), value in sorted(m1_means.items()):
        if mult in BEYOND_MULTIPLES:
            diff = value - delete[(rule, case, fraction)]
            h1_cells.append({"rule": rule, "case": case, "fraction": fraction, "multiple": mult,
                             "m1": value, "delete": delete[(rule, case, fraction)], "diff": diff,
                             "holds": abs(diff) <= 0.01})
    h1_share = sum(c["holds"] for c in h1_cells) / len(h1_cells)

    h2_units, zero_drop_max = [], {}
    for rule, case in units:
        hidden = max(m1_means[(rule, case, 0.2, m)] for m in ZERO_DROP_MULTIPLES)
        visible = m1_means[(rule, case, 0.2, 2.0)]
        zero_drop_max[(rule, case)] = hidden
        h2_units.append({"rule": rule, "case": case, "zero_drop_max": hidden, "at_2x": visible, "holds": hidden < visible})
    zero_drop_cells = [(v, k) for k, v in m1_means.items() if drops[k] == 0]
    top = max(zero_drop_cells)

    m2_means = cell_means([r for r in m2 if r["delay_structure"] == "random"], "alert_reduction",
                          "rule", "case", "delay_fraction", "delay_multiple")
    xs = [m2_means[(rule, case, 0.2, 10)] for rule, case in units]
    ys = [zero_drop_max[u] for u in units]
    rho = spearman(xs, ys)
    immune = [u for u in units if u[0] in ("net_scan", "beacon")]
    h3b_hits = [u for u in immune if zero_drop_max[u] >= 0.02]

    table = {f"{rule}|{case}": {str(m): {"reduction": m1_means[(rule, case, 0.2, m)], "dropped": drops[(rule, case, 0.2, m)]}
                                for m in sorted({k[3] for k in m1_means})}
             for rule, case in units}
    for rule, case in units:
        table[f"{rule}|{case}"]["delete"] = delete[(rule, case, 0.2)]
        table[f"{rule}|{case}"]["m2_10x"] = m2_means[(rule, case, 0.2, 10)]

    return (
        {"cells": len(h1_cells), "holding_share": h1_share, "adopted": h1_share >= 0.9,
         "failing": [c for c in h1_cells if not c["holds"]]},
        {"units": h2_units, "holding": sum(u["holds"] for u in h2_units), "adopted": sum(u["holds"] for u in h2_units) >= 13,
         "max_zero_drop_reduction": {"value": top[0], "rule": top[1][0], "case": top[1][1],
                                     "fraction": top[1][2], "multiple": top[1][3]}},
        {"H3a_spearman": rho, "H3a_adopted": rho is not None and rho < 0.5,
         "H3b_units": {f"{r}|{c}": zero_drop_max[(r, c)] for r, c in immune},
         "H3b_hits": len(h3b_hits), "H3b_adopted": len(h3b_hits) >= 4},
        table,
    )


def h4(records_by_model):
    rng = random.Random(BOOT_SEED)
    out = {}
    for model, records in records_by_model.items():
        groups = defaultdict(lambda: {"random": [], "targeted": []})
        base = {}
        for r in records:
            key = (r["rule"], r["case"], r["delay_fraction"], r["delay_multiple"])
            groups[key][r["delay_structure"]].append(r["malicious_evasion_rate"])
            base[key] = r["baseline_malicious_detected"]
        cells = []
        for key in sorted(groups):
            g = groups[key]
            ci = bootstrap_diff(g["targeted"], g["random"], rng)
            delta = mean(g["targeted"]) - mean(g["random"])
            equivalent = -MARGIN <= ci[0.05] and ci[0.95] <= MARGIN
            direction = "targeted" if ci[0.025] > 0 else "random" if ci[0.975] < 0 else None
            cells.append({"rule": key[0], "case": key[1], "fraction": key[2], "multiple": key[3],
                          "baseline_malicious": base[key], "primary": base[key] >= PRIMARY_MIN_MALICIOUS,
                          "delta": delta, "ci90": [ci[0.05], ci[0.95]], "ci95": [ci[0.025], ci[0.975]],
                          "equivalent": equivalent, "direction": direction,
                          "targeted_beyond_margin": ci[0.025] > MARGIN})
        primary = [c for c in cells if c["primary"]]
        share = sum(c["equivalent"] for c in primary) / len(primary) if primary else None
        beyond = [c for c in primary if c["targeted_beyond_margin"]]
        out[model] = {"cells": len(cells), "primary_cells": len(primary), "equivalent_share": share,
                      "targeted_advantage_cells": sum(c["direction"] == "targeted" for c in primary),
                      "random_advantage_cells": sum(c["direction"] == "random" for c in primary),
                      "targeted_beyond_margin": beyond,
                      "adopted": bool(primary) and not beyond and share >= 0.7,
                      "low_n_cells": [c for c in cells if not c["primary"]]}
    return out


def h5_h6(mitigation):
    means = cell_means(mitigation, "evasion_remaining", "delay_distribution", "rule", "case",
                       "delay_fraction", "delay_multiple", "buffer_multiple")
    h5 = {}
    for dist in ("uniform", "lognormal"):
        units = []
        for (d, rule, case, fraction, mult, buf), r0 in sorted(means.items()):
            if d != dist or buf != 0 or r0 < 0.02:
                continue
            rd = means[(d, rule, case, fraction, mult, mult)]
            units.append({"rule": rule, "case": case, "delay_multiple": mult, "R0": r0, "R_at_D": rd,
                          "holds": 0.1 * r0 < rd < 0.9 * r0})
        share = sum(u["holds"] for u in units) / len(units) if units else None
        h5[dist] = {"units": units, "holding_share": share, "adopted": share is not None and share >= 0.75}

    violations = []
    for (d, rule, case, fraction, mult, buf), value in sorted(means.items()):
        if buf == 0:
            continue
        r0 = means[(d, rule, case, fraction, mult, 0)]
        if value - r0 > 0.01:
            violations.append({"distribution": d, "rule": rule, "case": case, "fraction": fraction,
                               "delay_multiple": mult, "buffer_multiple": buf, "R0": r0, "R": value})
    shape = {}
    for (d, rule, case, fraction, mult, buf), value in sorted(means.items()):
        shape.setdefault(f"{d}|{rule}|{case}|{fraction}|{mult}", {})[str(buf)] = value
    return h5, {"violations": violations, "adopted": not violations}, shape


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=V2 / "analysis.json")
    args = parser.parse_args()

    m1 = load(V2 / "m1_ordering_sweep.jsonl")
    m2 = load(V2 / "ordering_sweep.jsonl")
    e5 = load(V2 / "mitigation_sweep.jsonl")
    e6 = [r for dist in DISTRIBUTIONS for r in load(V2 / f"mitigation_dist_{dist}.jsonl")]
    mitigation = e5 + e6

    result = {"schema": "v2-analysis-v1"}
    result["propositions"] = check_propositions(m1, mitigation)
    result["H0"] = h0({"ordering": (load(V1 / "ordering_sweep.jsonl"), m2),
                       "targeting": (load(V1 / "targeting_sweep.jsonl"), load(V2 / "targeting_sweep.jsonl"))})
    result["H1"], result["H2"], result["H3"], result["m1_table"] = h1_h2_h3(m1, m2)
    result["H4"] = h4({"m2": load(V2 / "targeting_sweep.jsonl"), "m1": load(V2 / "m1_targeting_sweep.jsonl")})
    # E5 (5 seeds) and E6-fixed (10 seeds) share fixed-delay cells and seeds 0-4;
    # relabelling E5 keeps their cell means from mixing.
    relabelled = [dict(r, delay_distribution="fixed-e5") for r in e5]
    result["H5"], result["H6"], result["mitigation_shape"] = h5_h6(relabelled + e6)

    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")

    p = result["propositions"]
    print(f"P-A violations {p['P-A_violations']}, P-B violations {p['P-B_violations']}")
    print(f"H0 adopted={result['H0']['adopted']} "
          f"ordering mismatches={result['H0']['ordering']['mismatches']} targeting mismatches={result['H0']['targeting']['mismatches']}")
    print(f"H1 adopted={result['H1']['adopted']} share={result['H1']['holding_share']:.3f} of {result['H1']['cells']}")
    print(f"H2 adopted={result['H2']['adopted']} holding={result['H2']['holding']}/15 max zero-drop={result['H2']['max_zero_drop_reduction']}")
    print(f"H3a adopted={result['H3']['H3a_adopted']} rho={result['H3']['H3a_spearman']}; "
          f"H3b adopted={result['H3']['H3b_adopted']} hits={result['H3']['H3b_hits']}/6")
    for model, h in result["H4"].items():
        print(f"H4[{model}] adopted={h['adopted']} primary={h['primary_cells']} equivalent={h['equivalent_share']} "
              f"targeted_adv={h['targeted_advantage_cells']} random_adv={h['random_advantage_cells']} beyond_margin={len(h['targeted_beyond_margin'])}")
    for dist, h in result["H5"].items():
        print(f"H5[{dist}] adopted={h['adopted']} share={h['holding_share']} units={len(h['units'])}")
    print(f"H6 adopted={result['H6']['adopted']} violations={len(result['H6']['violations'])}")


if __name__ == "__main__":
    main()
