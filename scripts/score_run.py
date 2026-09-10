"""Turn one detector run's node scores into a run record.

The denominator is the label node set frozen on the complete no-loss input, not
whatever survives in this run. A loss variant can delete label nodes outright,
and scoring against the survivors would silently raise recall exactly where the
loss did most damage. Label nodes missing from the predictions count as
undetected, which is what the analysis plan requires.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


def load_frozen_labels(path):
    body = json.loads(path.read_text(encoding="utf-8"))
    if body.get("schema") != "frozen-labels-v1":
        raise ValueError("unsupported frozen label schema")
    nodes = body["node_ids"]
    if not isinstance(nodes, list) or not nodes:
        raise ValueError("frozen label set is empty")
    if len(set(nodes)) != len(nodes):
        raise ValueError("frozen label set contains duplicates")
    return body, set(nodes)


def load_predictions(path):
    scores = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        node_id = row["node_id"]
        if node_id in scores:
            raise ValueError(f"duplicate node score for {node_id!r}")
        scores[node_id] = float(row["pred_score"])
    if not scores:
        raise ValueError("no node predictions found")
    return scores


def score(scores, label_nodes, threshold):
    """A node counts as detected only when its score is strictly above threshold."""
    alerted = {node for node, value in scores.items() if value > threshold}
    detected = label_nodes & alerted
    missing = label_nodes - scores.keys()
    return {
        "total_label_nodes": len(label_nodes),
        "detected_label_nodes": len(detected),
        "label_nodes_absent_from_input": len(missing),
        "case_detected": len(detected) > 0,
        "alerted_nodes": len(alerted),
        "node_precision": len(detected) / len(alerted) if alerted else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", type=Path, required=True, help="JSONL of node_id and pred_score")
    parser.add_argument("--labels", type=Path, required=True, help="frozen label node set")
    parser.add_argument("--threshold", type=float, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--pattern", required=True, choices=["baseline", "random", "contiguous"])
    parser.add_argument("--requested-rate", required=True)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--mask-sha256")
    parser.add_argument("--selection-start", type=int, required=True)
    parser.add_argument("--selection-end", type=int, required=True)
    parser.add_argument("--deleted-count", type=int, required=True)
    parser.add_argument("--detector-commit", required=True)
    parser.add_argument("--checkpoint-sha256", required=True)
    parser.add_argument("--started-at-utc", required=True)
    parser.add_argument("--output", type=Path, required=True, help="new JSON run record path")
    args = parser.parse_args()
    if (args.pattern == "baseline") != (args.seed is None):
        parser.error("--seed is required for loss runs and forbidden for the baseline")
    if (args.pattern == "baseline") != (args.mask_sha256 is None):
        parser.error("--mask-sha256 is required for loss runs and forbidden for the baseline")

    frozen, label_nodes = load_frozen_labels(args.labels)
    measured = score(load_predictions(args.predictions), label_nodes, args.threshold)
    record = {
        "run_id": args.run_id, "case": args.case, "host": args.host,
        "pattern": args.pattern, "requested_rate": args.requested_rate, "seed": args.seed,
        "input_sha256": args.input_sha256, "mask_sha256": args.mask_sha256,
        "selection_start": args.selection_start, "selection_end": args.selection_end,
        "deleted_count": args.deleted_count,
        "detector_commit": args.detector_commit, "checkpoint_sha256": args.checkpoint_sha256,
        "threshold": args.threshold,
        "frozen_label_sha256": frozen["label_sha256"],
        "predictions_sha256": hashlib.sha256(args.predictions.read_bytes()).hexdigest(),
        **measured,
        "started_at_utc": args.started_at_utc,
        "finished_at_utc": datetime.now(timezone.utc).isoformat(),
        "exit_status": "completed",
    }
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    print(json.dumps(record), flush=True)


if __name__ == "__main__":
    main()
