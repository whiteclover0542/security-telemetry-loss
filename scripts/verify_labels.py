"""Check the ground truth label files against the hashes pinned in study_inputs.json.

Hashes are taken over line-ending-normalised bytes. The label repository stores
LF, but Git checks these files out as CRLF wherever core.autocrlf is enabled, so
hashing the file as it sits on disk makes the same commit verify on Linux and
fail on Windows. Normalising keeps the pinned value meaningful on either.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def normalised_sha256(path):
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def verify(config, review_root):
    results = []
    for case in config["primary_cases"]:
        path = review_root / case["label_file"]
        if not path.exists():
            results.append({"case": case["case"], "status": "missing",
                            "label_file": case["label_file"]})
            continue
        actual = normalised_sha256(path)
        results.append({
            "case": case["case"], "label_file": case["label_file"],
            "expected_sha256": case["label_sha256"], "actual_sha256": actual,
            "status": "ok" if actual == case["label_sha256"] else "mismatch",
        })
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-root", type=Path,
                        default=ROOT / "external" / "corrected-optc-review",
                        help="checkout of the correction and labelling repository")
    parser.add_argument("--output", type=Path, help="new JSON result path; omit to print")
    args = parser.parse_args()
    config = json.loads((ROOT / "config" / "study_inputs.json").read_text(encoding="utf-8"))
    results = verify(config, args.review_root)
    record = {
        "schema": "label-verification-v1",
        "hash_rule": "sha256 over bytes with CRLF normalised to LF",
        "review_root": args.review_root.as_posix(),
        "correction_commit": config["correction_and_label_code"]["commit"],
        "all_ok": all(item["status"] == "ok" for item in results),
        "results": results,
    }
    rendered = json.dumps(record, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(rendered)
    else:
        print(rendered, end="")
    raise SystemExit(0 if record["all_ok"] else 1)


if __name__ == "__main__":
    main()
