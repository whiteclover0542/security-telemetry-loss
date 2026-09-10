"""Generate reproducible position masks for an already frozen, ordered event stream.

Positions are zero based. This module never receives attack labels. It does not
run a detector or reconstruct node attributes; those integration steps are pending.
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


def make_mask(event_count, rate, seed, pattern):
    k = deletion_count(event_count, rate)
    if pattern not in ("random", "contiguous"):
        raise ValueError("unknown pattern")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    # Separate deterministic RNG streams across patterns; no global RNG mutation.
    digest = hashlib.sha256(f"loss-mask-v1:{seed}:{pattern}".encode()).digest()
    rng = random.Random(int.from_bytes(digest, "big"))
    if k == 0:
        return []
    if pattern == "random":
        return sorted(rng.sample(range(event_count), k))
    start = rng.randrange(event_count - k + 1)
    return list(range(start, start + k))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, required=True)
    parser.add_argument("--rate", required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--pattern", choices=["random", "contiguous"], required=True)
    parser.add_argument("--source-sha256", required=True, help="SHA-256 of frozen ordered input")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if len(args.source_sha256) != 64 or any(c not in "0123456789abcdef" for c in args.source_sha256):
        parser.error("source-sha256 must be 64 lowercase hex characters")
    mask = make_mask(args.events, args.rate, args.seed, args.pattern)
    metadata = {
        "schema": "loss-mask-v1", "python": platform.python_version(),
        "source_sha256": args.source_sha256, "event_count": args.events,
        "requested_rate": str(Decimal(args.rate)), "deleted_count": len(mask),
        "realized_rate": len(mask) / args.events if args.events else None,
        "seed": args.seed, "pattern": args.pattern, "positions": mask,
    }
    # Refuse to overwrite existing evidence. The caller creates the output parent.
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(metadata, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
