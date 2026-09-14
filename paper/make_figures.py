"""Draw the paper's figures as static SVG from the stored v2 results.

Standard library only. Values come from data/p1/v2/analysis.json and
exploratory.json, so the figures regenerate with the analyses.
"""
import json
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[1]
V2 = ROOT / "data" / "p1" / "v2"
OUT = Path(__file__).resolve().parent / "figures"

SURFACE, INK, INK2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
FONT = "'Noto Sans KR','NanumGothic','Malgun Gothic',system-ui,sans-serif"


def esc(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class Svg:
    def __init__(self, width, height):
        self.w, self.h, self.parts = width, height, []

    def add(self, markup):
        self.parts.append(markup)

    def text(self, x, y, s, size=12, fill=INK2, anchor="start", weight=400):
        self.add(f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}" text-anchor="{anchor}" '
                 f'font-weight="{weight}">{esc(s)}</text>')

    def line(self, x1, y1, x2, y2, stroke=GRID, width=1):
        self.add(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{stroke}" stroke-width="{width}"/>')

    def polyline(self, points, stroke, width=2):
        pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
        self.add(f'<polyline points="{pts}" fill="none" stroke="{stroke}" stroke-width="{width}" '
                 f'stroke-linejoin="round" stroke-linecap="round"/>')

    def dot(self, x, y, fill, r=4):
        self.add(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{fill}" stroke="{SURFACE}" stroke-width="2"/>')

    def save(self, name):
        OUT.mkdir(exist_ok=True)
        body = "\n".join(self.parts)
        (OUT / name).write_text(
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" width="{self.w}" height="{self.h}" '
            f'font-family="{FONT}">\n<rect width="{self.w}" height="{self.h}" fill="{SURFACE}"/>\n{body}\n</svg>\n',
            encoding="utf-8")
        print("wrote", OUT / name)


def legend(svg, x, y, items):
    for label, color in items:
        svg.line(x, y - 4, x + 18, y - 4, stroke=color, width=2)
        svg.dot(x + 9, y - 4, color, r=3.5)
        svg.text(x + 24, y, label, size=12, fill=INK2)
        x += 40 + sum(12.5 if ord(ch) > 127 else 7.2 for ch in label)


def ordinal_line_chart(name, title, subtitle, x_labels, series, y_max, y_step, y_label, x_label, marker_x=None):
    svg = Svg(700, 400)
    left, right, top, bottom = 64, 664, 92, 340
    svg.text(24, 30, title, size=16, fill=INK, weight=700)
    svg.text(24, 52, subtitle, size=12, fill=INK2)
    legend(svg, 24, 76, [(label, color) for label, color, _ in series])

    ticks = [round(i * y_step, 4) for i in range(int(round(y_max / y_step)) + 1)]
    ypos = lambda v: bottom - (v / y_max) * (bottom - top)
    for t in ticks:
        svg.line(left, ypos(t), right, ypos(t), stroke=GRID if t else AXIS)
        svg.text(left - 8, ypos(t) + 4, f"{t:.2f}".rstrip("0").rstrip(".") if t else "0", size=11, fill=MUTED, anchor="end")
    step = (right - left) / (len(x_labels) - 1)
    xpos = lambda i: left + i * step
    for i, lab in enumerate(x_labels):
        svg.text(xpos(i), bottom + 18, lab, size=11, fill=MUTED, anchor="middle")
    svg.text((left + right) / 2, bottom + 40, x_label, size=12, fill=INK2, anchor="middle")
    svg.add(f'<text x="18" y="{(top + bottom) / 2:.1f}" font-size="12" fill="{INK2}" text-anchor="middle" '
            f'transform="rotate(-90 18 {(top + bottom) / 2:.1f})">{esc(y_label)}</text>')

    if marker_x is not None:
        idx, text = marker_x
        x = xpos(idx)
        svg.line(x, top, x, bottom, stroke=INK2, width=1)
        svg.text(x + 6, top + 12, text, size=11, fill=INK2)

    for label, color, values in series:
        pts = [(xpos(i), ypos(v)) for i, v in enumerate(values)]
        svg.polyline(pts, color)
        for x, y in pts:
            svg.dot(x, y, color)
    svg.save(name)


def figure_m1_delay(analysis):
    rules = [("net_scan", "net_scan"), ("mass_file", "mass_file"), ("remote_thread", "remote_thread"),
             ("module_load", "module_load"), ("beacon", "beacon")]
    mults = ["0.5", "0.75", "0.9", "1.0", "1.1", "1.25", "1.5", "2.0", "5.0", "10.0"]
    table = analysis["m1_table"]
    series = []
    for (rule, label), color in zip(rules, SERIES):
        rows = [v for k, v in table.items() if k.startswith(rule + "|")]
        series.append((label, color, [statistics.fmean(r[m]["reduction"] for r in rows) for m in mults]))
    ordinal_line_chart(
        "fig1_m1_delay.svg",
        "그림 1. M1에서 지연 크기에 따른 경보 감소",
        "20% 무작위 지연, 세 사례·시드 30 평균. 윈도우(W)를 넘으면 폐기가 발생한다.",
        [f"{float(m):g}×" for m in mults], series, 0.30, 0.05, "경보 감소율", "지연 크기 (윈도우 W의 배수, 순서 척도)",
        marker_x=(3, "지연 = W  (오른쪽부터 폐기 발생)"))


def figure_buffer(analysis):
    shape = analysis["mitigation_shape"]
    bufs = ["0", "0.5", "1", "2", "5", "10"]
    dists = [("fixed", "고정"), ("uniform", "균일 U(0, 2D)"), ("lognormal", "로그정규"), ("burst", "버스트")]
    series = []
    for (dist, label), color in zip(dists, SERIES):
        rows = [v for k, v in shape.items() if k.startswith(dist + "|") and k.endswith("|0.2|2.0")]
        series.append((label, color, [statistics.fmean(r[b] for r in rows) for b in bufs]))
    ordinal_line_chart(
        "fig3_buffer.svg",
        "그림 3. 지연 분포별 재정렬 버퍼의 복구 곡선 (M1)",
        "평균 지연 D = 2W, 20% 지연, 네 규칙·세 사례·시드 10 평균",
        [f"{float(b):g}×" for b in bufs], series, 0.25, 0.05, "잔존 회피 (경보 감소율)", "버퍼 크기 (윈도우 W의 배수, 순서 척도)",
        marker_x=(3, "B = D"))


def figure_trace(exploratory):
    drops = exploratory["trace_size"]["evading_runs_drops"]
    rows = [("무작위 지연", drops["random"]), ("표적 지연", drops["targeted"])]
    svg = Svg(700, 250)
    left, right = 120, 660
    svg.text(24, 30, "그림 2. 악성 주체를 빼낸 M1 실행이 남긴 폐기 건수", size=16, fill=INK, weight=700)
    svg.text(24, 52, "선: 10~90% 범위 · 점: 중앙값 · 세로 눈금: 최솟값 (로그 척도)", size=12, fill=INK2)
    import math
    lo, hi = 1, 100000
    xpos = lambda v: left + (math.log10(max(v, lo)) - math.log10(lo)) / (math.log10(hi) - math.log10(lo)) * (right - left)
    top, bottom = 80, 200
    for p in range(0, 6):
        v = 10 ** p
        svg.line(xpos(v), top, xpos(v), bottom, stroke=GRID if p else AXIS)
        svg.text(xpos(v), bottom + 18, f"{v:,}", size=11, fill=MUTED, anchor="middle")
    svg.text((left + right) / 2, bottom + 40, "폐기 이벤트 수", size=12, fill=INK2, anchor="middle")
    color = SERIES[0]
    for i, (label, q) in enumerate(rows):
        y = top + 30 + i * 60
        svg.text(left - 12, y + 4, label, size=12, fill=INK2, anchor="end")
        svg.add(f'<line x1="{xpos(q["p10"]):.1f}" y1="{y}" x2="{xpos(q["p90"]):.1f}" y2="{y}" stroke="{color}" '
                f'stroke-width="6" stroke-linecap="round" opacity="0.35"/>')
        svg.line(xpos(q["min"]), y - 9, xpos(q["min"]), y + 9, stroke=INK2, width=1)
        svg.dot(xpos(q["median"]), y, color, r=5)
        svg.text(xpos(q["median"]), y - 14, f"중앙값 {q['median']:,}", size=11, fill=INK, anchor="middle")
        svg.text(xpos(q["min"]), y + 24, f"최소 {q['min']:,}", size=11, fill=MUTED, anchor="middle")
    svg.save("fig2_trace.svg")


def main():
    analysis = json.loads((V2 / "analysis.json").read_text(encoding="utf-8"))
    exploratory = json.loads((V2 / "exploratory.json").read_text(encoding="utf-8"))
    figure_m1_delay(analysis)
    figure_trace(exploratory)
    figure_buffer(analysis)


if __name__ == "__main__":
    main()
