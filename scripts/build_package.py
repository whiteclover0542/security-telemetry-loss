"""Bundle the submission into reproduction_package.zip at the repository root.

The package holds what a reader needs to read the paper, check its verdicts and
rerun the study: the paper and its sources, the research records it cites, the
raw results of both engine versions, the scripts on the reproduction path and
their tests, and the inputs that locate the OpTC logs again. Tools used only by
the abandoned preliminary study stay in the repository but out of the package.
"""
import argparse
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASE_DATES = ["2019-09-23", "2019-09-24", "2019-09-25"]

FILES = [
    "README.md",
    "paper/PAPER.md",
    "paper/PAPER.pdf",
    "paper/make_figures.py",
    "paper/build_pdf.py",
    "paper/figures/*.svg",
    "docs/AI_AND_MY_JUDGMENT.md",
    "docs/ASSIGNMENT.md",
    "docs/TOPIC_SELECTION.md",
    "docs/PROGRESS.md",
    "docs/overview.html",
    "research/*.md",
    "config/rule_catalog.json",
    # Reproduction path: engine, buffer, sweeps, judging, premise checks.
    "scripts/rule_engine.py",
    "scripts/reorder_buffer.py",
    "scripts/sweep_common.py",
    "scripts/cache_projections.py",
    "scripts/ordering_sweep.py",
    "scripts/targeting_sweep.py",
    "scripts/mitigation_sweep.py",
    "scripts/run_sharded.py",
    "scripts/analyze_v2.py",
    "scripts/explore_v2.py",
    "scripts/verify_p1.py",
    "scripts/verify_p2.py",
    # Engine v1 summaries linked from the superseded result documents.
    "scripts/aggregate_ordering.py",
    # Retrieval of the host logs by verified byte range.
    "scripts/index_inria_tar.py",
    "scripts/fetch_inria_members.py",
    "tests/test_rule_engine.py",
    "tests/test_reorder_buffer.py",
    "tests/test_ordering_sweep.py",
    "tests/test_fetch_inria_members.py",
    # Raw results: engine v2 (paper) and engine v1 (kept as correction evidence).
    "data/p1/v2/*.json",
    "data/p1/v2/*.jsonl",
    "data/p1/*.json",
    "data/p1/*.jsonl",
    "data/windows/*.json",
    *[f"data/inria_index/{d}/index.jsonl" for d in CASE_DATES],
    *[f"data/inria_selected/{d}/{n}.jsonl" for d in CASE_DATES for n in ("manifest", "attempts")],
    # Inputs carried over from the preliminary study: labels, their pinned hashes
    # and review, how the data was obtained, and why that topic was dropped.
    "preliminary/data/labels/*.json",
    "preliminary/config/study_inputs.json",
    "preliminary/research/DATA_ACCESS.md",
    "preliminary/research/LABEL_AND_CORRECTION_REVIEW.md",
    "preliminary/research/EXPERIMENT_DESIGN.md",
    "preliminary/research/RESULTS.md",
]


def collect():
    paths = []
    for pattern in FILES:
        matches = sorted(ROOT.glob(pattern))
        if not matches and "attempts" not in pattern:
            raise SystemExit(f"nothing matches {pattern}")
        paths.extend(m for m in matches if m.is_file())
    return sorted(set(paths))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "reproduction_package.zip")
    args = parser.parse_args()
    paths = collect()
    tmp = args.output.with_suffix(".tmp")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for path in paths:
            z.write(path, path.relative_to(ROOT).as_posix())
    tmp.replace(args.output)
    print(f"wrote {args.output} ({len(paths)} files, {args.output.stat().st_size / 1e6:.2f} MB)")


if __name__ == "__main__":
    main()
