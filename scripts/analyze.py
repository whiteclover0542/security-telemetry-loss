# -*- coding: utf-8 -*-
"""분석 스크립트. 사전에 정한 분석만 수행한다 (PROGRESS.md 3.4 / 5.1 참조).

입력 : data/processed/kev_delay.csv
출력 : data/processed/results.json     모든 수치
       data/processed/results.md       논문에 붙일 표
       paper/figures/fig1_scatter.svg  CVSS 점수 vs 등재 지연
       paper/figures/fig2_severity.svg 심각도 구간별 지연 중앙값

사전 확정 판정 기준
    rho < -0.1 이고 p < 0.05  -> 가설 지지
    |rho| <= 0.1              -> 관계 없음
    rho >  0.1                -> 가설과 반대

실행: python scripts/analyze.py
"""
import csv
import json
import math
import os
import random
import sys

# 윈도우 콘솔(cp949)에서도 한글과 기호가 깨지지 않게 한다.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except AttributeError:
    pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stats  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC = os.path.join(ROOT, "data", "processed")
FIGS = os.path.join(ROOT, "paper", "figures")

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
BOOTSTRAP_REPS = 5000
SEED = 20260908


def load():
    with open(os.path.join(PROC, "kev_delay.csv"), encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["delay_days"] = int(r["delay_days"])
        r["cvss_v31_score"] = float(r["cvss_v31_score"]) if r["cvss_v31_score"] else None
        r["in_primary_sample"] = r["in_primary_sample"] == "1"
    return rows


def correlate(rows, label):
    x = [r["cvss_v31_score"] for r in rows]
    y = [r["delay_days"] for r in rows]
    rho, p = stats.spearman(x, y)
    lo, hi = stats.bootstrap_ci(x, y, lambda a, b: stats.spearman(a, b)[0],
                                reps=BOOTSTRAP_REPS, seed=SEED)
    return {"label": label, "n": len(rows), "rho": rho, "p": p, "ci95": [lo, hi]}


def verdict(rho, p):
    if rho < -0.1 and p < 0.05:
        return "가설 지지 (점수가 높을수록 등재가 빠름)"
    if abs(rho) <= 0.1:
        return "가설 기각 — 관계 없음 (|rho| <= 0.1)"
    if rho > 0.1:
        return "가설과 반대 (점수가 높을수록 등재가 느림)"
    return "가설 지지 조건 미충족 (rho < -0.1 이나 p >= 0.05)"


def severity_table(rows):
    out = []
    for sev in SEVERITY_ORDER:
        g = [r["delay_days"] for r in rows if r["cvss_v31_severity"] == sev]
        if not g:
            continue
        d = stats.describe(g)
        d["severity"] = sev
        d["iqr"] = d["q3"] - d["q1"]
        d["pct_within_30d"] = 100.0 * sum(1 for v in g if v <= 30) / len(g)
        d["pct_negative"] = 100.0 * sum(1 for v in g if v < 0) / len(g)
        out.append(d)
    return out


# ------------------------------------------------------------------ SVG 그리기
def signed_log(v):
    """지연이 음수부터 수천까지 걸쳐 있어 부호 있는 로그 축을 쓴다."""
    return math.copysign(math.log10(1.0 + abs(v)), v)


def svg_header(w, h, title):
    return [
        '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" '
        'font-family="Segoe UI, Malgun Gothic, sans-serif">' % (w, h, w, h),
        '<title>%s</title>' % title,
        '<rect width="%d" height="%d" fill="#ffffff"/>' % (w, h),
    ]


def write_svg(path, parts):
    parts.append("</svg>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))


def fig_scatter(rows, path):
    W, H = 780, 470
    L, R, T, B = 78, 24, 46, 62
    pw, ph = W - L - R, H - T - B
    xs = [r["cvss_v31_score"] for r in rows]
    ys = [signed_log(r["delay_days"]) for r in rows]
    x0, x1 = 1.5, 10.3
    y0, y1 = min(ys) - 0.15, max(ys) + 0.15

    def px(v):
        return L + (v - x0) / (x1 - x0) * pw

    def py(v):
        return T + ph - (v - y0) / (y1 - y0) * ph

    s = svg_header(W, H, "CVSS v3.1 기본점수와 KEV 등재 지연")
    s.append('<text x="%d" y="26" font-size="15" font-weight="600" fill="#111">'
             'CVSS v3.1 기본점수와 KEV 등재 지연 (주 분석 표본 n=%d)</text>' % (L, len(rows)))

    # y축 눈금: 부호 있는 로그
    for v in (-100, -10, 0, 10, 100, 1000):
        yv = signed_log(v)
        if not (y0 <= yv <= y1):
            continue
        y = py(yv)
        s.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1"/>'
                 % (L, y, L + pw, y, "#c9ced6" if v == 0 else "#eef0f3"))
        s.append('<text x="%.1f" y="%.1f" font-size="11" fill="#555" text-anchor="end">%s</text>'
                 % (L - 8, y + 4, "{:,}".format(v)))
    # x축 눈금
    for v in range(2, 11):
        x = px(v)
        s.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#eef0f3" stroke-width="1"/>'
                 % (x, T, x, T + ph))
        s.append('<text x="%.1f" y="%.1f" font-size="11" fill="#555" text-anchor="middle">%d</text>'
                 % (x, T + ph + 18, v))

    rng = random.Random(SEED)
    for r in rows:
        jx = px(r["cvss_v31_score"]) + rng.uniform(-4.5, 4.5)
        jy = py(signed_log(r["delay_days"]))
        col = "#c2410c" if r["delay_days"] < 0 else "#1d4ed8"
        s.append('<circle cx="%.1f" cy="%.1f" r="2.4" fill="%s" fill-opacity="0.32"/>' % (jx, jy, col))

    s.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#333"/>' % (L, T + ph, L + pw, T + ph))
    s.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#333"/>' % (L, T, L, T + ph))
    s.append('<text x="%.1f" y="%d" font-size="12" fill="#333" text-anchor="middle">'
             'CVSS v3.1 기본점수</text>' % (L + pw / 2.0, H - 24))
    s.append('<text x="18" y="%.1f" font-size="12" fill="#333" text-anchor="middle" '
             'transform="rotate(-90 18 %.1f)">등재 지연 (일, 부호 있는 로그 축)</text>'
             % (T + ph / 2.0, T + ph / 2.0))
    s.append('<circle cx="%d" cy="%d" r="3.4" fill="#c2410c" fill-opacity="0.75"/>' % (L + 12, H - 26))
    s.append('<text x="%d" y="%d" font-size="11" fill="#444">지연 &lt; 0 (NVD 공개 전 KEV 등재)</text>'
             % (L + 22, H - 22))
    write_svg(path, s)


def fig_severity(table, path):
    W, H = 700, 400
    L, R, T, B = 92, 28, 48, 78
    pw, ph = W - L - R, H - T - B
    vmax = max(t["q3"] for t in table) * 1.12

    def py(v):
        return T + ph - (v / vmax) * ph

    s = svg_header(W, H, "심각도 구간별 KEV 등재 지연")
    s.append('<text x="%d" y="26" font-size="15" font-weight="600" fill="#111">'
             '심각도 구간별 등재 지연: 중앙값과 사분위 범위</text>' % L)

    step = 200 if vmax > 900 else 100
    v = 0
    while v <= vmax:
        y = py(v)
        s.append('<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="#eef0f3"/>' % (L, y, L + pw, y))
        s.append('<text x="%d" y="%.1f" font-size="11" fill="#555" text-anchor="end">%s</text>'
                 % (L - 8, y + 4, "{:,}".format(v)))
        v += step

    colors = {"LOW": "#94a3b8", "MEDIUM": "#60a5fa", "HIGH": "#2563eb", "CRITICAL": "#1e3a8a"}
    slot = pw / float(len(table))
    for i, t in enumerate(table):
        cx = L + slot * (i + 0.5)
        bw = min(74, slot * 0.5)
        # 사분위 범위
        s.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s" fill-opacity="0.22"/>'
                 % (cx - bw / 2, py(t["q3"]), bw, max(1.0, py(t["q1"]) - py(t["q3"])),
                    colors.get(t["severity"], "#888")))
        # 중앙값
        s.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="4"/>'
                 % (cx - bw / 2, py(t["median"]), cx + bw / 2, py(t["median"]),
                    colors.get(t["severity"], "#888")))
        s.append('<text x="%.1f" y="%.1f" font-size="12" font-weight="600" fill="#111" '
                 'text-anchor="middle">%.0f일</text>' % (cx, py(t["median"]) - 9, t["median"]))
        s.append('<text x="%.1f" y="%d" font-size="12" fill="#333" text-anchor="middle">%s</text>'
                 % (cx, T + ph + 20, t["severity"]))
        s.append('<text x="%.1f" y="%d" font-size="11" fill="#666" text-anchor="middle">n=%d</text>'
                 % (cx, T + ph + 37, t["n"]))

    s.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#333"/>' % (L, T + ph, L + pw, T + ph))
    s.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#333"/>' % (L, T, L, T + ph))
    s.append('<text x="18" y="%.1f" font-size="12" fill="#333" text-anchor="middle" '
             'transform="rotate(-90 18 %.1f)">등재 지연 (일)</text>' % (T + ph / 2.0, T + ph / 2.0))
    s.append('<text x="%d" y="%d" font-size="11" fill="#666">'
             '굵은 선 = 중앙값, 옅은 상자 = 1사분위~3사분위</text>' % (L, H - 14))
    write_svg(path, s)


# ------------------------------------------------------------------ 본체
def main():
    rows = load()
    scored = [r for r in rows if r["cvss_v31_score"] is not None]
    primary = [r for r in scored if r["in_primary_sample"]]
    primary_pos = [r for r in primary if r["delay_days"] >= 0]

    res = {"seed": SEED, "bootstrap_reps": BOOTSTRAP_REPS}
    res["counts"] = {
        "all_rows": len(rows),
        "with_cvss_v31": len(scored),
        "primary_sample": len(primary),
        "primary_excluding_negative": len(primary_pos),
        "negative_delay_in_primary": len(primary) - len(primary_pos),
    }
    res["delay_describe_primary"] = stats.describe([r["delay_days"] for r in primary])
    res["delay_describe_all"] = stats.describe([r["delay_days"] for r in scored])
    res["cvss_describe_primary"] = stats.describe([r["cvss_v31_score"] for r in primary])

    res["correlation"] = {
        "primary": correlate(primary, "주 분석: KEV 창설 이후 공개분"),
        "full": correlate(scored, "민감도 1: 전수 (소급 등재 포함)"),
        "primary_nonneg": correlate(primary_pos, "민감도 2: 주 표본에서 음수 지연 제외"),
    }
    for k, v in res["correlation"].items():
        v["verdict"] = verdict(v["rho"], v["p"])

    res["severity"] = severity_table(primary)
    groups = [[r["delay_days"] for r in primary if r["cvss_v31_severity"] == s]
              for s in SEVERITY_ORDER]
    groups = [g for g in groups if g]
    h, df, p = stats.kruskal_wallis(groups)
    # 효과크기 epsilon^2 = H / (n - 1). 순위 분산 중 집단 차이로 설명되는 비율.
    eps2 = h / (len(primary) - 1.0)
    res["kruskal_wallis"] = {"H": h, "df": df, "p": p, "epsilon_squared": eps2,
                             "groups": [s for s in SEVERITY_ORDER
                                        if any(r["cvss_v31_severity"] == s for r in primary)]}

    # --- 사후 추가 분석 (탐색적) ---------------------------------------
    # 아래 둘은 사전에 계획한 것이 아니라 결과를 본 뒤 추가했다. 결과가 어느 쪽으로
    # 나오든 그대로 보고한다. PROGRESS.md 5.6 설계 변경 이력에 기록했다.
    res["exploratory"] = {"note": "사전 계획이 아니라 결과 확인 후 추가한 분석"}
    nvd_primary = [r for r in primary if r["cvss_is_primary"] == "1"]
    res["exploratory"]["nvd_primary_scored_only"] = (
        correlate(nvd_primary, "NVD 자체 평가 점수만") if len(nvd_primary) > 30 else None)
    recent = [r for r in primary if r["published"] >= "2024-01-01"]
    res["exploratory"]["recent_2024plus"] = (
        correlate(recent, "2024년 이후 공개분만") if len(recent) > 30 else None)
    for _k in ("nvd_primary_scored_only", "recent_2024plus"):
        _v = res["exploratory"][_k]
        if _v:
            _v["verdict"] = verdict(_v["rho"], _v["p"])

    neg = [r for r in primary if r["delay_days"] < 0]
    res["negative_delay"] = {
        "n": len(neg),
        "share_pct": 100.0 * len(neg) / len(primary),
        "median_days": stats.describe([r["delay_days"] for r in neg])["median"] if neg else None,
        "mean_cvss": sum(r["cvss_v31_score"] for r in neg) / len(neg) if neg else None,
        "mean_cvss_rest": (sum(r["cvss_v31_score"] for r in primary if r["delay_days"] >= 0)
                           / max(1, len(primary) - len(neg))),
        "by_severity": {s: sum(1 for r in neg if r["cvss_v31_severity"] == s) for s in SEVERITY_ORDER},
    }
    res["same_day_or_faster_pct"] = 100.0 * sum(1 for r in primary if r["delay_days"] <= 0) / len(primary)
    res["within_30d_pct"] = 100.0 * sum(1 for r in primary if r["delay_days"] <= 30) / len(primary)

    os.makedirs(FIGS, exist_ok=True)
    fig_scatter(primary, os.path.join(FIGS, "fig1_scatter.svg"))
    fig_severity(res["severity"], os.path.join(FIGS, "fig2_severity.svg"))

    with open(os.path.join(PROC, "results.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)

    # ---- 논문에 붙일 표 (마크다운)
    md = []
    md.append("### 표 1. 표본 구성\n")
    md.append("| 구분 | 건수 |")
    md.append("| --- | --- |")
    md.append("| KEV 카탈로그 전수 | %d |" % res["counts"]["all_rows"])
    md.append("| CVSS v3.1 점수 보유 | %d |" % res["counts"]["with_cvss_v31"])
    md.append("| **주 분석 표본** (2021-11-03 이후 공개) | **%d** |" % res["counts"]["primary_sample"])
    md.append("| 그중 지연이 음수인 건 | %d |" % res["counts"]["negative_delay_in_primary"])

    d = res["delay_describe_primary"]
    md.append("\n### 표 2. 등재 지연 분포 (주 분석 표본, 단위: 일)\n")
    md.append("| n | 평균 | 표준편차 | 최소 | 1사분위 | 중앙값 | 3사분위 | 최대 |")
    md.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    md.append("| %d | %.1f | %.1f | %d | %.0f | %.0f | %.0f | %d |"
              % (d["n"], d["mean"], d["sd"], d["min"], d["q1"], d["median"], d["q3"], d["max"]))

    md.append("\n### 표 3. 주 분석 결과 — Spearman 순위상관\n")
    md.append("| 표본 | n | rho | 95% 신뢰구간 | p | 사전 기준에 따른 판정 |")
    md.append("| --- | --- | --- | --- | --- | --- |")
    for key in ("primary", "full", "primary_nonneg"):
        c = res["correlation"][key]
        md.append("| %s | %d | %+.4f | [%+.3f, %+.3f] | %.4f | %s |"
                  % (c["label"], c["n"], c["rho"], c["ci95"][0], c["ci95"][1], c["p"], c["verdict"]))

    md.append("\n### 표 4. 심각도 구간별 등재 지연 (주 분석 표본)\n")
    md.append("| 심각도 | n | 중앙값 | 1사분위 | 3사분위 | 평균 | 30일 이내 % | 지연 음수 % |")
    md.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for t in res["severity"]:
        md.append("| %s | %d | %.0f | %.0f | %.0f | %.1f | %.1f | %.1f |"
                  % (t["severity"], t["n"], t["median"], t["q1"], t["q3"], t["mean"],
                     t["pct_within_30d"], t["pct_negative"]))
    kw = res["kruskal_wallis"]
    md.append("\nKruskal-Wallis H = %.3f, df = %d, p = %.4f, 효과크기 epsilon^2 = %.4f"
              % (kw["H"], kw["df"], kw["p"], kw["epsilon_squared"]))

    md.append("\n### 표 5. 사후 추가 분석 (사전 계획 아님, 탐색적)\n")
    md.append("| 하위표본 | n | rho | 95% 신뢰구간 | p | 판정 |")
    md.append("| --- | --- | --- | --- | --- | --- |")
    for key in ("nvd_primary_scored_only", "recent_2024plus"):
        c = res["exploratory"][key]
        if c:
            md.append("| %s | %d | %+.4f | [%+.3f, %+.3f] | %.4f | %s |"
                      % (c["label"], c["n"], c["rho"], c["ci95"][0], c["ci95"][1], c["p"], c["verdict"]))

    with open(os.path.join(PROC, "results.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")

    print("\n".join(md))
    print("\n--- 사전 판정 기준 적용 ---")
    c = res["correlation"]["primary"]
    print("주 분석: rho = %+.4f, p = %.4f  ->  %s" % (c["rho"], c["p"], c["verdict"]))
    n = res["negative_delay"]
    print("지연 음수: %d건 (%.1f%%), 중앙값 %.0f일, 평균 CVSS %.2f (나머지 %.2f)"
          % (n["n"], n["share_pct"], n["median_days"], n["mean_cvss"], n["mean_cvss_rest"]))
    print("공개 당일 이전 등재: %.1f%% / 30일 이내 등재: %.1f%%"
          % (res["same_day_or_faster_pct"], res["within_30d_pct"]))
    print("\n-> %s, %s" % (os.path.join(PROC, "results.json"), os.path.join(PROC, "results.md")))
    print("-> %s (fig1_scatter.svg, fig2_severity.svg)" % FIGS)


if __name__ == "__main__":
    main()
