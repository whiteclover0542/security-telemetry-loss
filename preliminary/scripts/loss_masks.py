"""Generate reproducible position masks for an already frozen, ordered event stream.

Positions are zero based and absolute within the input file. Deletions are drawn
only from an eligible selection window, so the random and contiguous conditions
remove the same number of events from the same evaluation range. This module
never receives attack labels. It does not run a detector or reconstruct node
attributes; those integration steps are pending.
"""
import argparse
from decimal import Decimal, ROUND_FLOOR
import hashlib
import json
from pathlib import Path
import platform
import random


def deletion_count(event_count, rate):
    if isinstance(event_count, bool) or not isinstance(event_count, int) or event_count < 0:
        raise ValueError("event_count must be a nonnegative integer")
    rate = Decimal(str(rate))
    if not rate.is_finite() or not 0 <= rate <= 1:
        raise ValueError("rate must be finite and between 0 and 1")
    return int((event_count * rate).to_integral_value(rounding=ROUND_FLOOR))


def selection_bounds(event_count, selection):
    """Resolve the half-open [start, end) range eligible for deletion."""
    if selection is None:
        return 0, event_count
    start, end = selection
    for value in (start, end):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("selection bounds must be integers")
    if not 0 <= start < end <= event_count:
        raise ValueError("selection must satisfy 0 <= start < end <= event_count")
    return start, end


def make_mask(event_count, rate, seed, pattern, selection=None):
    if isinstance(event_count, bool) or not isinstance(event_count, int) or event_count < 0:
        raise ValueError("event_count must be a nonnegative integer")
    start, end = selection_bounds(event_count, selection)
    k = deletion_count(end - start, rate)
    if pattern not in ("random", "contiguous"):
        raise ValueError("unknown pattern")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    # Separate deterministic RNG streams across patterns; no global RNG mutation.
    # The v1 label stays: it seeds the stream, so changing it would silently
    # change every mask a given seed produces.
    digest = hashlib.sha256(f"loss-mask-v1:{seed}:{pattern}".encode()).digest()
    rng = random.Random(int.from_bytes(digest, "big"))
    if k == 0:
        return []
    if pattern == "random":
        return sorted(rng.sample(range(start, end), k))
    first = rng.randrange(start, end - k + 1)
    return list(range(first, first + k))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, required=True)
    parser.add_argument("--rate", required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--pattern", choices=["random", "contiguous"], required=True)
    parser.add_argument("--source-sha256", required=True, help="SHA-256 of frozen ordered input")
    parser.add_argument("--selection-start", type=int,
                        help="first absolute position eligible for deletion; use with --selection-end")
    parser.add_argument("--selection-end", type=int,
                        help="one past the last eligible position; from window_positions.py")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if len(args.source_sha256) != 64 or any(c not in "0123456789abcdef" for c in args.source_sha256):
        parser.error("source-sha256 must be 64 lowercase hex characters")
    if (args.selection_start is None) != (args.selection_end is None):
        parser.error("--selection-start and --selection-end must be given together")
    selection = None if args.selection_start is None else (args.selection_start, args.selection_end)
    mask = make_mask(args.events, args.rate, args.seed, args.pattern, selection)
    start, end = selection_bounds(args.events, selection)
    metadata = {
        "schema": "loss-mask-v2", "python": platform.python_version(),
        "source_sha256": args.source_sha256, "event_count": args.events,
        "selection_start": start, "selection_end": end, "selection_event_count": end - start,
        "selection_given": selection is not None,
        "requested_rate": str(Decimal(args.rate)), "deleted_count": len(mask),
        "realized_rate": len(mask) / (end - start) if end > start else None,
        "deleted_fraction_of_input": len(mask) / args.events if args.events else None,
        "seed": args.seed, "pattern": args.pattern, "positions": mask,
    }
    # Refuse to overwrite existing evidence. The caller creates the output parent.
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(metadata, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
