"""Run the full loss sweep and record evidence loss for every seed.

Masks are regenerated from seed, rate and window rather than stored: they are
deterministic, so keeping 7,200 position files would add nothing a reader could
not reproduce. Only the per-seed measurements are written, one JSON object per
line, which is what the aggregation reads.
"""
import argparse
from decimal import Decimal
import json
from pathlib import Path
import platform
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evidence_loss import load_label_index, measure
from loss_masks import make_mask

ROOT = Path(__file__).resolve().parents[1]


def sweep(indexes, rates, patterns, seeds, stream):
    written = 0
    for case, index in indexes.items():
        selection = (index["selection_start"], index["selection_end"])
        events = index["selection_end"]  # positions are absolute in the input
        for rate in rates:
            for pattern in patterns:
                for seed in seeds:
                    positions = make_mask(index["input_event_count"], rate, seed, pattern, selection)
                    result = measure(index, set(positions))
                    record = {
                        "schema": "evidence-loss-v1",
                        "case": case,
                        "pattern": pattern,
                        "seed": seed,
                        "requested_rate": str(Decimal(rate)),
                        "deleted_count": len(positions),
                        "realized_rate": len(positions) / (selection[1] - selection[0]),
                        "input_sha256": index["input_sha256"],
                        **result,
                    }
                    stream.write(json.dumps(record) + "\n")
                    written += 1
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label-index", type=Path, nargs="+", required=True)
    parser.add_argument("--rates", nargs="+", default=["0.01", "0.05", "0.10", "0.20"])
    parser.add_argument("--seeds", type=int, default=300, help="seeds 0..N-1 per condition")
    parser.add_argument("--output", type=Path, required=True, help="new JSONL path")
    args = parser.parse_args()

    indexes = {}
    for path in args.label_index:
        index = load_label_index(path)
        # The mask generator needs the full input length, not just the window.
        window = json.loads((ROOT / "data" / "windows" / f"{index['case']}.json").read_text(encoding="utf-8"))
        if window["input_sha256"] != index["input_sha256"]:
            raise ValueError(f"window and label index disagree for {index['case']}")
        index["input_event_count"] = window["event_count"]
        indexes[index["case"]] = index

    began = time.time()
    with args.output.open("x", encoding="utf-8") as stream:
        written = sweep(indexes, args.rates, ["random", "contiguous"], range(args.seeds), stream)
    elapsed = time.time() - began

    manifest = args.output.with_suffix(".manifest.json")
    with manifest.open("x", encoding="utf-8") as stream:
        json.dump({
            "schema": "evidence-sweep-v1",
            "python": platform.python_version(),
            "cases": sorted(indexes),
            "rates": args.rates,
            "patterns": ["random", "contiguous"],
            "seeds": args.seeds,
            "records_written": written,
            "seconds": round(elapsed, 1),
            "note": "Masks are regenerated from seed, rate and window; they are not stored.",
        }, stream, indent=2)
        stream.write("\n")
    print(f"{written:,} records in {elapsed:.1f}s -> {args.output}", flush=True)


if __name__ == "__main__":
    main()
