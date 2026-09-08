# -*- coding: utf-8 -*-
"""원자료 두 개를 결합해 분석용 CSV를 만든다.

입력 : data/raw/kev_YYYY-MM-DD.json, data/raw/nvd_kev_YYYY-MM-DD.json
출력 : data/processed/kev_delay.csv, data/processed/build_report.json

CSV 열
    cve_id                CVE 식별자
    published             NVD 공개일 (YYYY-MM-DD)
    date_added            KEV 등재일 (YYYY-MM-DD)
    delay_days            등재 지연 = date_added - published (일)
    cvss_v31_score        CVSS v3.1 기본점수 (0.0~10.0)
    cvss_v31_severity     LOW / MEDIUM / HIGH / CRITICAL
    cvss_source           점수를 가져온 출처 (nvd@nist.gov 등)
    cvss_is_primary       NVD 자체 평가(Primary)이면 1
    vendor, product       KEV의 vendorProject, product
    cwe                   KEV의 cwes 첫 항목 (없으면 빈 값)
    known_ransomware      KEV의 knownRansomwareCampaignUse
    in_primary_sample     주 분석 표본이면 1 (published >= 2021-11-03 이고 점수 있음)

설계에 따라 고정한 것 (scripts 실행 전 확정, PROGRESS.md 5.1 참조)
    - CVSS는 v3.1만 사용한다. v2/v4는 쓰지 않는다.
    - 같은 CVE에 점수가 여러 개면 NVD 자체 평가(Primary)를 우선한다.
    - 기준일은 NVD published 하나만 쓴다. lastModified는 쓰지 않는다.
    - 지연이 음수인 건은 버리지 않고 그대로 두고 별도로 보고한다.
"""
import csv
import datetime
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "data", "raw")
OUT = os.path.join(ROOT, "data", "processed")

# KEV 카탈로그 창설일. 이 날짜 이전에 공개된 CVE의 '지연'은 악용 속도가 아니라
# 카탈로그가 언제 만들어졌는지를 재는 값이 되므로 주 분석에서 제외한다.
KEV_LAUNCH = datetime.date(2021, 11, 3)


def newest(pattern):
    files = sorted(glob.glob(os.path.join(RAW, pattern)))
    if not files:
        sys.exit("원자료가 없다: %s (scripts/fetch_data.py 를 먼저 실행)" % pattern)
    return files[-1]


def pick_cvss31(metrics):
    """CVSS v3.1 항목 중 하나를 고른다. NVD 자체 평가(Primary)를 우선한다."""
    entries = [e for e in metrics.get("cvssMetricV31", [])
               if e.get("cvssData", {}).get("version") == "3.1"]
    if not entries:
        return None
    for e in entries:
        if e.get("type") == "Primary" or e.get("source") == "nvd@nist.gov":
            return e
    return entries[0]


def main():
    kev_file = newest("kev_*.json")
    nvd_file = newest("nvd_kev_*.json")
    snapshot = os.path.basename(kev_file).replace("kev_", "").replace(".json", "")

    with open(kev_file, encoding="utf-8") as f:
        kev_raw = json.load(f)
    with open(nvd_file, encoding="utf-8") as f:
        nvd_raw = json.load(f)

    kev = {v["cveID"]: v for v in kev_raw["vulnerabilities"]}
    nvd = {it["cve"]["id"]: it["cve"] for it in nvd_raw["vulnerabilities"]}

    report = {
        "snapshot_date": snapshot,
        "kev_file": os.path.basename(kev_file),
        "nvd_file": os.path.basename(nvd_file),
        "kev_catalog_version": kev_raw.get("catalogVersion"),
        "kev_records": len(kev_raw["vulnerabilities"]),
        "kev_unique_cve": len(kev),
        "nvd_records": len(nvd_raw["vulnerabilities"]),
        "nvd_total_results": nvd_raw.get("totalResults"),
        "kev_launch_cutoff": KEV_LAUNCH.isoformat(),
    }

    only_kev = sorted(set(kev) - set(nvd))
    only_nvd = sorted(set(nvd) - set(kev))
    report["in_kev_not_in_nvd"] = only_kev
    report["in_nvd_not_in_kev"] = only_nvd

    rows = []
    no_v31 = []
    secondary_only = []
    for cve_id in sorted(set(kev) & set(nvd)):
        k = kev[cve_id]
        c = nvd[cve_id]
        published = datetime.date.fromisoformat(c["published"][:10])
        date_added = datetime.date.fromisoformat(k["dateAdded"])
        entry = pick_cvss31(c.get("metrics", {}))
        if entry is None:
            no_v31.append(cve_id)
            score = severity = source = ""
            is_primary = ""
        else:
            data = entry["cvssData"]
            score = data.get("baseScore")
            severity = data.get("baseSeverity")
            source = entry.get("source", "")
            is_primary = 1 if (entry.get("type") == "Primary" or source == "nvd@nist.gov") else 0
            if not is_primary:
                secondary_only.append(cve_id)

        in_primary = 1 if (published >= KEV_LAUNCH and entry is not None) else 0
        cwes = k.get("cwes") or []
        rows.append({
            "cve_id": cve_id,
            "published": published.isoformat(),
            "date_added": date_added.isoformat(),
            "delay_days": (date_added - published).days,
            "cvss_v31_score": score,
            "cvss_v31_severity": severity,
            "cvss_source": source,
            "cvss_is_primary": is_primary,
            "vendor": k.get("vendorProject", ""),
            "product": k.get("product", ""),
            "cwe": cwes[0] if cwes else "",
            "known_ransomware": k.get("knownRansomwareCampaignUse", ""),
            "in_primary_sample": in_primary,
        })

    report["joined_records"] = len(rows)
    report["missing_cvss_v31"] = no_v31
    report["cvss_from_secondary_source"] = secondary_only
    report["primary_sample_n"] = sum(r["in_primary_sample"] for r in rows)
    report["negative_delay"] = sorted(r["cve_id"] for r in rows if r["delay_days"] < 0)
    report["published_before_cutoff"] = sum(
        1 for r in rows if datetime.date.fromisoformat(r["published"]) < KEV_LAUNCH)

    os.makedirs(OUT, exist_ok=True)
    csv_path = os.path.join(OUT, "kev_delay.csv")
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    with open(os.path.join(OUT, "build_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print("스냅샷            :", snapshot, "(catalogVersion %s)" % report["kev_catalog_version"])
    print("KEV 원자료        :", report["kev_records"], "건")
    print("NVD 원자료        :", report["nvd_records"], "건 (totalResults=%s)" % report["nvd_total_results"])
    print("결합 성공         :", report["joined_records"], "건")
    print("  KEV에만 있음    :", len(only_kev))
    print("  NVD에만 있음    :", len(only_nvd))
    print("CVSS v3.1 결측    :", len(no_v31), "건", no_v31 if no_v31 else "")
    print("2차 출처 점수 사용:", len(secondary_only), "건")
    print("창설일 이전 공개  :", report["published_before_cutoff"], "건 (주 분석 제외)")
    print("주 분석 표본 n    :", report["primary_sample_n"], "건")
    print("지연 음수         :", len(report["negative_delay"]), "건", report["negative_delay"] if report["negative_delay"] else "")
    print("->", csv_path)


if __name__ == "__main__":
    main()
