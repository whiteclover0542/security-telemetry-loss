# -*- coding: utf-8 -*-
"""제출용 재현 패키지 ZIP을 만든다.

포함: paper/, data/raw/, data/processed/, scripts/, REPRODUCE.md, PROGRESS.md
제외: .git, __pycache__, submission/, ASSIGNMENT.md(과제 안내문이라 제출물이 아님)

실행: python scripts/make_package.py
"""
import os
import sys
import zipfile

try:
    sys.stdout.reconfigure(encoding="utf-8")
except AttributeError:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "submission")
SNAPSHOT = "2026-09-08"
ZIP_NAME = "과제10_재현패키지_%s.zip" % SNAPSHOT
TOP = "cvss-kev-study"  # 압축을 풀면 이 폴더 하나가 생긴다

INCLUDE_FILES = ["REPRODUCE.md", "PROGRESS.md"]
INCLUDE_DIRS = ["paper", "data", "scripts"]
SKIP_DIRS = {".git", "__pycache__", "submission", ".idea", ".vscode"}
SKIP_EXT = {".pyc", ".pyo"}


def collect():
    items = []
    for name in INCLUDE_FILES:
        p = os.path.join(ROOT, name)
        if os.path.exists(p):
            items.append((p, "%s/%s" % (TOP, name)))
    for d in INCLUDE_DIRS:
        base = os.path.join(ROOT, d)
        for cur, dirs, files in os.walk(base):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
            for f in sorted(files):
                if os.path.splitext(f)[1] in SKIP_EXT:
                    continue
                full = os.path.join(cur, f)
                rel = os.path.relpath(full, ROOT).replace("\\", "/")
                items.append((full, "%s/%s" % (TOP, rel)))
    return sorted(items, key=lambda x: x[1])


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, ZIP_NAME)
    items = collect()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for full, arc in items:
            z.write(full, arc)

    total = os.path.getsize(out)
    print("만든 파일: %s" % out)
    print("담긴 파일: %d개, 압축 후 %.1f MB\n" % (len(items), total / 1024.0 / 1024.0))
    for _, arc in items:
        print("  ", arc)


if __name__ == "__main__":
    main()
