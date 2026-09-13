"""Run a sweep as one process per (case, rule) and stitch the shards together.

Each sweep iterates case then rule in catalogue order, so concatenating the
shards in that same order yields exactly the records a single process would
write, in the same order. Shard outputs and manifests are kept for audit.

Example:
    python scripts/run_sharded.py --workers 10 --output data/p1/v2/m1_ordering.jsonl -- \
        scripts/ordering_sweep.py --model m1 --cache data/p1/cache
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PID_ONLY = {"targeting_sweep.py", "mitigation_sweep.py"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=ROOT / "config" / "rule_catalog.json")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("sweep", nargs=argparse.REMAINDER, help="-- script.py [sweep args]")
    args = parser.parse_args()
    command = args.sweep[1:] if args.sweep and args.sweep[0] == "--" else args.sweep
    script, sweep_args = command[0], command[1:]

    catalogue = json.loads(args.catalog.read_text(encoding="utf-8"))
    rules = [r["name"] for r in catalogue["rules"]
             if Path(script).name not in PID_ONLY or r["key"] == "pid"]
    if args.output.exists():
        raise FileExistsError(args.output)
    shard_dir = args.output.parent / (args.output.stem + ".shards")
    shard_dir.mkdir(parents=True, exist_ok=False)
    shards = [(case, rule, shard_dir / f"{case}__{rule}.jsonl")
              for case in catalogue["sweep"]["cases"] for rule in rules]

    def run(shard):
        case, rule, out = shard
        cmd = [sys.executable, script, *sweep_args, "--cases", case, "--rules", rule, "--output", str(out)]
        began = time.time()
        done = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        (shard_dir / f"{case}__{rule}.log").write_text(done.stdout + done.stderr, encoding="utf-8")
        print(f"[{'ok' if done.returncode == 0 else 'FAIL'}] {case} {rule} {time.time() - began:.0f}s", flush=True)
        return done.returncode

    began = time.time()
    with ThreadPoolExecutor(args.workers) as pool:
        codes = list(pool.map(run, shards))
    if any(codes):
        raise SystemExit(f"{sum(1 for c in codes if c)} shard(s) failed; see {shard_dir}")

    records = 0
    with args.output.open("x", encoding="utf-8") as merged:
        for _, _, out in shards:
            text = out.read_text(encoding="utf-8")
            merged.write(text)
            records += text.count("\n")
    manifests = [json.loads(out.with_suffix(".manifest.json").read_text(encoding="utf-8")) for _, _, out in shards]
    with args.output.with_suffix(".manifest.json").open("x", encoding="utf-8") as stream:
        json.dump({
            "schema": "sharded-run-manifest-v1",
            "command": [script, *sweep_args],
            "workers": args.workers,
            "records_written": records,
            "wall_seconds": round(time.time() - began, 1),
            "cpu_seconds": round(sum(m["seconds"] for m in manifests), 1),
            "engine_version": manifests[0]["engine_version"],
            "git_commit": manifests[0]["git_commit"],
            "scripts_dirty": any(m["scripts_dirty"] for m in manifests),
            "shards": [{"case": c, "rule": r, "records": m["records_written"]}
                       for (c, r, _), m in zip(shards, manifests)],
        }, stream, indent=2)
        stream.write("\n")
    print(f"{records:,} records -> {args.output}", flush=True)


if __name__ == "__main__":
    main()
