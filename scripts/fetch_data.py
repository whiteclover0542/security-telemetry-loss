# -*- coding: utf-8 -*-
"""원자료 수집 스크립트.

CISA KEV 카탈로그와 NVD CVE API 2.0(hasKev 필터)에서 원자료를 받아
data/raw/ 아래에 '수집 날짜'를 파일명에 박아 저장한다.

두 소스 모두 API 키나 로그인이 필요 없다.

사용:
    python scripts/fetch_data.py            # 오늘 날짜로 새로 받기
    python scripts/fetch_data.py --check    # 저장된 스냅샷만 검사(네트워크 미사용)

주의: KEV 카탈로그는 계속 갱신된다. 논문의 수치는 2026-09-08 스냅샷 기준이며,
새로 받으면 건수와 결과가 달라진다. 논문을 그대로 재현하려면 저장소에 포함된
data/raw/*_2026-09-08.json 을 쓰고 이 스크립트를 실행하지 않으면 된다.
"""
import argparse
import datetime
import json
import os
import sys
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev&resultsPerPage=2000"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "data", "raw")


def download(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "kev-cvss-study/1.0 (academic)"})
    with urllib.request.urlopen(req, timeout=180) as r:
        body = r.read()
    with open(dest, "wb") as f:
        f.write(body)
    return len(body)


def summarize(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    if "vulnerabilities" in d and isinstance(d["vulnerabilities"], list):
        items = d["vulnerabilities"]
        if items and "cveID" in items[0]:
            return "KEV", len(items), d.get("catalogVersion", "?")
        return "NVD", len(items), "totalResults=%s" % d.get("totalResults")
    return "?", 0, "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="네트워크를 쓰지 않고 저장된 스냅샷만 검사")
    ap.add_argument("--date", default=datetime.date.today().isoformat(), help="파일명에 쓸 날짜 (YYYY-MM-DD)")
    args = ap.parse_args()

    os.makedirs(RAW, exist_ok=True)
    kev_path = os.path.join(RAW, "kev_%s.json" % args.date)
    nvd_path = os.path.join(RAW, "nvd_kev_%s.json" % args.date)

    if not args.check:
        print("[1/2] CISA KEV 내려받는 중 ...")
        print("      %d bytes -> %s" % (download(KEV_URL, kev_path), kev_path))
        print("[2/2] NVD CVE API 2.0 (hasKev) 내려받는 중 ...")
        print("      %d bytes -> %s" % (download(NVD_URL, nvd_path), nvd_path))

    missing = [p for p in (kev_path, nvd_path) if not os.path.exists(p)]
    if missing:
        sys.exit("스냅샷이 없다: %s" % ", ".join(missing))

    for p in (kev_path, nvd_path):
        kind, n, ver = summarize(p)
        print("%-4s %5d건  (%s)  %s" % (kind, n, ver, os.path.basename(p)))


if __name__ == "__main__":
    main()
