"""Build the per-(case, rule) projection cache the sharded sweeps read.

Each case is parsed once; every rule's projection and the case's malicious pid
set are pickled next to each other. A projection read back from the cache is the
exact list `project()` returns, so sweeps give identical records either way.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from ordering_sweep import load_case, project
from sweep_common import read_cache, write_cache


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=ROOT / "config" / "rule_catalog.json")
    parser.add_argument("--cases", nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    catalogue = json.loads(args.catalog.read_text(encoding="utf-8"))
    for case in args.cases or catalogue["sweep"]["cases"]:
        events, malicious = load_case(case)
        for rule in catalogue["rules"]:
            projected = project(events, rule)
            write_cache(args.output, case, rule["name"], projected, malicious)
            back, back_mal = read_cache(args.output, case, rule["name"])
            assert back == projected and back_mal == malicious
            print(f"{case} {rule['name']}: {len(projected):,} events", flush=True)
        del events


if __name__ == "__main__":
    main()
