"""Apply a checked position mask to a JSONL or JSONL.GZ event stream.

This is deliberately a stream transformation: it does not inspect attack labels,
reorder records, or reconstruct detector features.  It preserves every retained
JSON line exactly and writes a manifest for the later preprocessing stage.
"""
import argparse
from contextlib import ExitStack
import gzip
import hashlib
import io
import json
from pathlib import Path


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def open_input(path):
    return gzip.open(path, "rt", encoding="utf-8") if path.suffix == ".gz" else path.open("r", encoding="utf-8")


def load_mask(path, source_sha256):
    mask = json.loads(path.read_text(encoding="utf-8"))
    if mask.get("schema") != "loss-mask-v1":
        raise ValueError("unsupported mask schema")
    if mask.get("source_sha256") != source_sha256:
        raise ValueError("mask source SHA-256 does not match input")
    positions = mask.get("positions")
    if not isinstance(positions, list) or positions != sorted(set(positions)):
        raise ValueError("mask positions must be sorted and unique")
    if any(isinstance(i, bool) or not isinstance(i, int) or i < 0 for i in positions):
        raise ValueError("mask contains an invalid position")
    return mask, set(positions)


def apply(input_path, mask_path, output_path, manifest_path):
    source_sha256 = sha256_file(input_path)
    mask, deleted = load_mask(mask_path, source_sha256)
    if output_path.exists() or manifest_path.exists():
        raise FileExistsError("refusing to overwrite output or manifest")

    input_count = output_count = 0
    with ExitStack() as stack:
        source = stack.enter_context(open_input(input_path))
        if output_path.suffix == ".gz":
            raw = stack.enter_context(output_path.open("xb"))
            compressed = stack.enter_context(gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0))
            destination = stack.enter_context(io.TextIOWrapper(compressed, encoding="utf-8"))
        else:
            destination = stack.enter_context(output_path.open("x", encoding="utf-8"))
        for position, line in enumerate(source):
            if not line.strip():
                raise ValueError(f"blank line at event position {position}")
            json.loads(line)
            input_count += 1
            if position not in deleted:
                destination.write(line if line.endswith("\n") else line + "\n")
                output_count += 1
    if input_count != mask["event_count"]:
        output_path.unlink(missing_ok=True)
        raise ValueError("mask event count does not match input")
    if deleted and max(deleted) >= input_count:
        output_path.unlink(missing_ok=True)
        raise ValueError("mask position is outside input")

    manifest = {
        "schema": "loss-application-v1",
        "input_path": str(input_path),
        "input_sha256": source_sha256,
        "input_event_count": input_count,
        "mask_path": str(mask_path),
        "mask_sha256": sha256_file(mask_path),
        "deleted_count": len(deleted),
        "output_path": str(output_path),
        "output_sha256": sha256_file(output_path),
        "output_event_count": output_count,
    }
    with manifest_path.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2)
        stream.write("\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--mask", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.input, args.mask, args.output, args.manifest)), flush=True)


if __name__ == "__main__":
    main()
