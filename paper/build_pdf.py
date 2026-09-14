"""Typeset paper/PAPER.md into paper/PAPER.pdf with headless Chrome.

Markdown is rendered with markdown-it (tables enabled), inline TeX is turned
into plain HTML math, and Chrome prints the page to A4. Run make_figures.py
first so the SVG figures exist.
"""
import argparse
import html
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from markdown_it import MarkdownIt

HERE = Path(__file__).resolve().parent
CHROME_CANDIDATES = [
    Path("C:/Program Files/Google/Chrome/Application/chrome.exe"),
    Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"),
]
TEX = {r"\ge": "≥", r"\le": "≤", r"\square": "□", r"\times": "×", "-": "−"}

CSS = """
@page { size: A4; margin: 20mm 19mm 20mm 19mm; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { font-family: 'NanumMyeongjo', 'Noto Serif KR', serif; font-size: 10.2pt; line-height: 1.72;
       color: #0b0b0b; background: #ffffff; margin: 0; word-break: keep-all; overflow-wrap: anywhere; }
h1, h2, h3, table, figcaption, .meta { font-family: 'Noto Sans KR', 'NanumGothic', sans-serif; }
code, pre { font-family: 'D2Coding', 'Consolas', 'Noto Sans KR', monospace; }
h1 { font-size: 19pt; line-height: 1.4; text-align: center; margin: 6mm 0 5mm; font-weight: 700; }
h1 + p, h1 + p + p { text-align: center; margin: 0.5mm 0; color: #52514e; }
h2 { font-size: 13.5pt; margin: 9mm 0 3mm; padding-bottom: 1.5mm; border-bottom: 1px solid #c3c2b7;
     break-after: avoid; }
h3 { font-size: 11pt; margin: 6mm 0 2mm; break-after: avoid; }
p { margin: 0 0 2.6mm; text-align: justify; }
p.ref { text-align: left; padding-left: 7mm; text-indent: -7mm; }
hr { border: none; border-top: 1px solid #e1e0d9; margin: 6mm 0; }
strong { font-weight: 700; }
a { color: #1c5cab; text-decoration: none; }
ul, ol { margin: 0 0 3mm; padding-left: 6mm; }
li { margin: 0.6mm 0; }
blockquote { margin: 3mm 0; padding: 2mm 4mm; border-left: 3px solid #c3c2b7; background: #f9f9f7; color: #2b2b29; }
blockquote p { margin: 0; }
table { border-collapse: collapse; width: 100%; margin: 3mm 0 4mm; font-size: 8.2pt; line-height: 1.45;
        break-inside: avoid; }
th, td { border-bottom: 1px solid #e1e0d9; padding: 1.2mm 1.6mm; vertical-align: top; }
th { border-bottom: 1px solid #898781; text-align: left; font-weight: 700; background: #f9f9f7; }
td[style*="right"], th[style*="right"] { font-variant-numeric: tabular-nums; }
code { font-size: 8.4pt; background: #f3f2ee; padding: 0 1mm; border-radius: 2px; }
pre { font-size: 7.6pt; line-height: 1.5; background: #f7f6f2; border: 1px solid #e1e0d9; border-radius: 3px;
      padding: 3mm; white-space: pre-wrap; break-inside: avoid; }
pre code { background: none; padding: 0; font-size: inherit; }
img { display: block; max-width: 100%; margin: 4mm auto 5mm; break-inside: avoid; }
.math { font-family: 'Times New Roman', 'NanumMyeongjo', serif; white-space: nowrap; }
.math i { font-style: italic; }
"""


def tex_to_html(expr):
    for k, v in TEX.items():
        expr = expr.replace(k, v)
    expr = html.escape(expr)
    return re.sub(r"(?<![A-Za-z])([A-Za-z])(?![A-Za-z])", r"<i>\1</i>", expr)


def convert_math(markdown):
    """Replace $...$ outside code fences and inline code with HTML spans."""
    out = []
    for i, chunk in enumerate(re.split(r"(```.*?```)", markdown, flags=re.S)):
        if i % 2:
            out.append(chunk)
            continue
        pieces = re.split(r"(`[^`\n]*`)", chunk)
        for j, piece in enumerate(pieces):
            if j % 2 == 0:
                piece = re.sub(r"\$([^$\n]+?)\$",
                               lambda m: f'<span class="math">{tex_to_html(m.group(1))}</span>', piece)
            out.append(piece)
    return "".join(out)


def render_html(md_path):
    text = md_path.read_text(encoding="utf-8")
    md = MarkdownIt("commonmark", {"html": True}).enable("table")
    body = md.render(convert_math(text))
    body = re.sub(r'src="(figures/[^"]+)"',
                  lambda m: f'src="{(md_path.parent / m.group(1)).resolve().as_uri()}"', body)
    # Reference entries carry long URLs; justification would stretch the words around them.
    body = re.sub(r"<p>\[(\d+)\]", r'<p class="ref">[\1]', body)
    title = re.search(r"^# (.+)$", text, re.M).group(1)
    return (f'<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>{html.escape(title)}</title>'
            f"<style>{CSS}</style></head><body>{body}</body></html>")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=HERE / "PAPER.md")
    parser.add_argument("--output", type=Path, default=HERE / "PAPER.pdf")
    args = parser.parse_args()
    chrome = next((c for c in CHROME_CANDIDATES if c.exists()), None) or shutil.which("chrome")
    if chrome is None:
        raise SystemExit("Chrome or Edge is required to print the PDF")
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp) / "paper.html"
        page.write_text(render_html(args.input), encoding="utf-8")
        subprocess.run([str(chrome), "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                        "--virtual-time-budget=8000", f"--print-to-pdf={args.output.resolve()}", page.as_uri()],
                       check=True, capture_output=True)
    print("wrote", args.output)


if __name__ == "__main__":
    main()
