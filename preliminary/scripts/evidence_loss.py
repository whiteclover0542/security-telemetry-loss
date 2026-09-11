"""Measure how much attack evidence one loss mask removes.

Three levels, from the shallowest to the one that matters most for tracing:

  event      how many labelled malicious events the mask deletes
  process    how many malicious processes lose every event they had in the window
  creation   how many PROCESS/CREATE events are deleted, each of which severs a
             parent-child link a later investigation would have followed

A-v2 predicts contiguous loss is not worse on average but less predictable, so
these are reported per seed and their spread across seeds is the dependent
variable. Reading the label index is a set operation, which is why this scales to
hundreds of seeds where replaying the detector does not.
"""
import argparse
import json
from pathlib import Path


def load_label_index(path):
    record = json.loads(path.read_text(encoding="utf-8"))
    if record.get("schema") != "label-positions-v1":
        raise ValueError("unsupported label index schema")
    return record


def load_mask(path):
    mask = json.loads(path.read_text(encoding="utf-8"))
    if mask.get("schema") != "loss-mask-v2":
        raise ValueError("unsupported mask schema")
    return mask


def measure(index, deleted):
    positions = index["label_positions"]
    pids = index["label_pids"]
    creates = index["label_is_process_create"]
    total = len(positions)

    surviving_by_pid, total_by_pid = {}, {}
    lost_events = lost_creates = 0
    for position, pid, is_create in zip(positions, pids, creates):
        gone = position in deleted
        lost_events += gone
        lost_creates += gone and is_create
        if pid is not None:
            total_by_pid[pid] = total_by_pid.get(pid, 0) + 1
            if not gone:
                surviving_by_pid[pid] = surviving_by_pid.get(pid, 0) + 1

    silenced = [pid for pid in total_by_pid if surviving_by_pid.get(pid, 0) == 0]
    total_creates = sum(creates)
    return {
        "label_events_in_window": total,
        "label_events_deleted": lost_events,
        "event_loss_rate": lost_events / total if total else None,
        "processes_in_window": len(total_by_pid),
        "processes_fully_silenced": len(silenced),
        "process_silence_rate": len(silenced) / len(total_by_pid) if total_by_pid else None,
        "process_creates_in_window": total_creates,
        "process_creates_deleted": lost_creates,
        "creation_loss_rate": lost_creates / total_creates if total_creates else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label-index", type=Path, required=True)
    parser.add_argument("--mask", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="new JSON record path; omit to print")
    args = parser.parse_args()

    index = load_label_index(args.label_index)
    mask = load_mask(args.mask)
    if mask["source_sha256"] != index["input_sha256"]:
        raise ValueError("mask and label index refer to different inputs")
    if (mask["selection_start"], mask["selection_end"]) != (index["selection_start"], index["selection_end"]):
        raise ValueError("mask and label index use different evaluation windows")

    record = {
        "schema": "evidence-loss-v1",
        "case": index["case"],
        "pattern": mask["pattern"],
        "seed": mask["seed"],
        "requested_rate": mask["requested_rate"],
        "realized_rate": mask["realized_rate"],
        "deleted_count": mask["deleted_count"],
        "input_sha256": index["input_sha256"],
        **measure(index, set(mask["positions"])),
    }
    rendered = json.dumps(record)
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(rendered + "\n")
    print(rendered, flush=True)


if __name__ == "__main__":
    main()
