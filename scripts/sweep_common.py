"""Shared plumbing for the sweeps: projection cache, run filters, provenance.

Loading a case parses up to 1.3M events and holds several GiB, which caps how
many sweep shards can run at once. The cache stores each rule's projection once,
so a shard loads tens of megabytes and many shards fit in memory together.
"""
import json
import pickle
import subprocess
from pathlib import Path

from rule_engine import ENGINE_VERSION

ROOT = Path(__file__).resolve().parents[1]


def cache_path(cache_dir, case, rule_name):
    return Path(cache_dir) / f"{case}__{rule_name}.pkl"


def write_cache(cache_dir, case, rule_name, projected, malicious):
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    with cache_path(cache_dir, case, rule_name).open("xb") as stream:
        pickle.dump({"projected": projected, "malicious": sorted(malicious)}, stream)


def read_cache(cache_dir, case, rule_name):
    with cache_path(cache_dir, case, rule_name).open("rb") as stream:
        blob = pickle.load(stream)
    return blob["projected"], set(blob["malicious"])


class CaseSource:
    """Yields (projected, malicious) per rule, from the cache or the raw log."""

    def __init__(self, cache_dir=None):
        self.cache_dir = cache_dir
        self._case = self._events = self._malicious = None

    def get(self, case, rule):
        if self.cache_dir is not None:
            return read_cache(self.cache_dir, case, rule["name"])
        from ordering_sweep import load_case, project
        if case != self._case:
            self._events, self._malicious = load_case(case)
            self._case = case
        return project(self._events, rule), self._malicious


def select(items, allowed):
    return [x for x in items if not allowed or x in allowed]


def provenance(extra):
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                text=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain", "scripts", "config"], cwd=ROOT,
                                    capture_output=True, text=True, check=True).stdout.strip())
    except (OSError, subprocess.CalledProcessError):
        commit, dirty = None, None
    return {"engine_version": ENGINE_VERSION, "git_commit": commit, "scripts_dirty": dirty, **extra}


def write_manifest(output, payload):
    with Path(output).with_suffix(".manifest.json").open("x", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2)
        stream.write("\n")
