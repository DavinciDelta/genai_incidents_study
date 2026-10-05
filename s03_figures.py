#!/usr/bin/env python3
"""s03_figures.py — Step 3. Figure 1 from out/split.json (SVG, stdlib only; no plotting library).
Panel A: adversary-present incidents per record year, ON-AI vs WITH-AI (grouped bars, direct labels).
Panel B: ON/WITH composition of each disclosure channel (100% stacked bars) — the selection-bias diagnostic.
Palette: two categorical slots (blue #2a78d6, orange #eb6834), documented as CVD-safe for adjacent marks.
Output: out/fig1_on_with.svg
"""
import collections, json
from common import OUT
S = json.load(open(OUT / "split.json"))
F = {i: s for i, s in S.items() if s["population"] in ("ON-AI", "WITH-AI")}
BLUE, ORANGE, INK, INK2, GRID, SURF = "#2a78d6", "#eb6834", "#0b0b0b", "#52514e", "#e6e5e1", "#fcfcfb"
yrs = list(range(2020, 2027)); by = {y: collections.Counter(s["population"] for s in F.values() if s["year"] == y) for y in yrs}
chans = [("cve/ghsa", "CVE / GHSA feed"), ("harm-db", "Harm databases (OECD, AIID, AIAAIC, AVID)"), ("research/other", "Research &amp; vendor write-ups")]
ch = {c: collections.Counter(s["population"] for s in F.values() if s["source_class"] == c) for c, _ in chans}
ymax = max(max(c.values()) for c in by.values()); ymax = int(-(-ymax // 200) * 200)

W, H = 1060, 420; o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="Inter,Helvetica,Arial,sans-serif">', f'<rect width="{W}" height="{H}" fill="{SURF}"/>',
    f'<text x="24" y="30" font-size="15" font-weight="600" fill="{INK}">Figure 1. Adversary-present AI incidents, split by the role the AI system plays (n = {len(F):,})</text>',
    f'<text x="24" y="48" font-size="11.5" fill="{INK2}">ON-AI: the AI system is the target or vector.  WITH-AI: the AI is the attacker\'s instrument against a conventional target.</text>',
    f'<text x="24" y="63" font-size="11.5" fill="{INK2}">Source: genai_incidents (pip), rule-based split prior to manual coding (s02_split.py). BOTH and UNRESOLVED rows omitted.</text>']
ax, ay, aw, ah = 70, 104, 520, 256
o.append(f'<text x="{ax}" y="{ay-12}" font-size="12.5" font-weight="600" fill="{INK}">A  Incidents per record year</text>')
for t in range(0, ymax + 1, ymax // 4):
    y = ay + ah - ah * t / ymax; o += [f'<line x1="{ax}" x2="{ax+aw}" y1="{y:.1f}" y2="{y:.1f}" stroke="{GRID}"/>', f'<text x="{ax-8}" y="{y+4:.1f}" font-size="10.5" text-anchor="end" fill="{INK2}">{t}</text>']
gw = aw / len(yrs); bw = (gw - 14) / 2
for i, y in enumerate(yrs):
    x0 = ax + i * gw + 7
    for j, (pop, col) in enumerate((("ON-AI", BLUE), ("WITH-AI", ORANGE))):
        v = by[y][pop]; h = ah * v / ymax; x = x0 + j * (bw + 2); top = ay + ah - h
        o += [f'<rect x="{x:.1f}" y="{top:.1f}" width="{bw:.1f}" height="{h:.1f}" rx="3" fill="{col}"/>', f'<text x="{x+bw/2:.1f}" y="{top-4:.1f}" font-size="10" text-anchor="middle" fill="{INK2}">{v}</text>']
    o.append(f'<text x="{x0+bw+1:.1f}" y="{ay+ah+16}" font-size="11" text-anchor="middle" fill="{INK2}">{y}</text>')
o += [f'<line x1="{ax}" x2="{ax+aw}" y1="{ay+ah}" y2="{ay+ah}" stroke="{INK2}"/>', f'<text x="{ax+aw/2}" y="{ay+ah+36}" font-size="10.5" text-anchor="middle" fill="{INK2}">record year (ingestion-affected; the 2026 bar reflects catch-up ingestion, not a measured surge)</text>']
for k, (pop, col) in enumerate((("ON-AI", BLUE), ("WITH-AI", ORANGE))):
    o += [f'<rect x="{ax+10}" y="{ay+8+k*18-9}" width="12" height="12" rx="2" fill="{col}"/>', f'<text x="{ax+28}" y="{ay+9+k*18}" font-size="11" fill="{INK}">{pop}</text>']
bx, bY, bw2 = 660, 104, 280
o.append(f'<text x="{bx}" y="{bY-12}" font-size="12.5" font-weight="600" fill="{INK}">B  Composition of each disclosure channel</text>')
for i, (c, label) in enumerate(chans):
    n = sum(ch[c].values()); on, wi = ch[c]["ON-AI"], ch[c]["WITH-AI"]; y = bY + 20 + i * 64; w_on = bw2 * on / n
    o += [f'<text x="{bx}" y="{y-6}" font-size="11" fill="{INK}">{label}  <tspan fill="{INK2}">n = {n:,}</tspan></text>',
          f'<rect x="{bx}" y="{y}" width="{max(w_on-1,0):.1f}" height="18" rx="3" fill="{BLUE}"/>', f'<rect x="{bx+w_on+1:.1f}" y="{y}" width="{max(bw2-w_on-1,0):.1f}" height="18" rx="3" fill="{ORANGE}"/>',
          f'<text x="{bx+6}" y="{y+13}" font-size="10.5" fill="#fff" font-weight="600">{100*on/n:.0f}% ON</text>', f'<text x="{bx+bw2-6}" y="{y+13}" font-size="10.5" text-anchor="end" fill="#fff" font-weight="600">{100*wi/n:.0f}% WITH</text>']
o += [f'<text x="{bx}" y="{H-24}" font-size="10.5" fill="{INK2}">Each channel observes a different population: a pooled ON/WITH ratio</text>', f'<text x="{bx}" y="{H-10}" font-size="10.5" fill="{INK2}">is a ratio of disclosure channels, not of attacks.</text>', "</svg>"]
(OUT / "fig1_on_with.svg").write_text("\n".join(o)); print("wrote out/fig1_on_with.svg")
