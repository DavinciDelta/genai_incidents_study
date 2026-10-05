"""common.py — shared loaders and helpers. Every script imports from here so the data path is one place."""
from __future__ import annotations
import collections, json, random, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EXT, OUT = ROOT / "external", ROOT / "out"
OUT.mkdir(exist_ok=True)
CYCLE = EXT / "incident-rank-validation/projects/owasp-llm/cycles/2026"

# ---------------------------------------------------------------- corpus
def load_full() -> dict:
    """Full corpus (external/incidents.json) keyed by id. Run fetch_data.py first."""
    raw = json.load(open(EXT / "incidents.json"))
    rows = raw["incidents"] if isinstance(raw, dict) and "incidents" in raw else raw
    return {r["id"]: r for r in rows}

def source_class(r: dict) -> str:
    s = r.get("source_ids") or []
    if r.get("cve_ids") or any(x.startswith(("CVE", "GHSA")) for x in s): return "cve/ghsa"
    if any(x.startswith(("OECD", "AIID", "AIAAIC", "AVID")) for x in s): return "harm-db"
    return "research/other"

def text(r: dict) -> str:
    return f"{r.get('title','')} {r.get('description','')} {r.get('affected','')}"

# ---------------------------------------------------------------- incident-rank-validation artifacts
def load_rv() -> dict:
    tax = {e["entry_id"]: e for e in json.load(open(CYCLE / "taxonomy/taxonomy.json"))["entries"]}
    labels = collections.defaultdict(list)
    for row in json.load(open(CYCLE / "classify/labeled_incidents.json")): labels[row["incident_id"]].append(row)
    gold = {json.loads(l)["incident_id"]: json.loads(l) for l in open(CYCLE / "calibration/adjudicated_goldset.jsonl")}
    post = json.load(open(CYCLE / "calibration/posteriors.json"))
    ranks = {}
    pat = re.compile(r"^\|\s*([A-Z0-9-]+)\s*\|\s*([\d.]+) \(([\d.]+)[–-]([\d.]+)\)\s*\|\s*([\d.]+) \(([\d.]+)[–-]([\d.]+)\)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|")
    for line in open(CYCLE / "results/rank_comparison_report.md"):
        m = pat.match(line.strip())
        if m:
            e, lr, lo, hi, vr, vlo, vhi, tier, d, a = m.groups()
            ranks[e] = {"lambda_rank": float(lr), "lambda_ci": (float(lo), float(hi)), "vote_rank": float(vr),
                        "tier": tier.strip(), "direction": d.strip(), "action": a.strip()}
    conc = json.load(open(CYCLE / "results/concordance.json"))
    return {"taxonomy": tax, "labels": labels, "gold": gold, "posteriors": post, "ranks": ranks, "concordance": conc}

def beta_mean(post, kind, entry, stratum="security"):
    b = post[kind].get(f"{entry}::{stratum}")
    if not b: return None, 0
    a, be = b["alpha"], b["beta"]; return a / (a + be), int(a + be - 2)

def join_rv(corpus: dict, rv: dict) -> dict:
    """Attach rank-validation labels/gold to current corpus rows, following ID redirects."""
    from genai_incidents import resolve_id, load_deprecations
    deps = load_deprecations(); rows, unresolved = {}, []
    for inc_id, lab in rv["labels"].items():
        cur = inc_id if inc_id in corpus else (resolve_id(inc_id) if inc_id in deps else None)
        if not cur or cur not in corpus: unresolved.append(inc_id); continue
        g = rv["gold"].get(inc_id)
        rows[cur] = {"rv_entries": sorted({l["entry_id"] for l in lab}), "rv_stage": max(l["stage"] for l in lab),
                     "gold_labels": g["labels"] if g else None, "snapshot_id": inc_id}
    return {"rows": rows, "unresolved": unresolved}

# ---------------------------------------------------------------- stats + output helpers
def boot_ci(items, pred, B=2000, seed=20261005):
    """Percentile bootstrap 95% CI for a proportion. Returns (p, lo, hi)."""
    rng = random.Random(seed); n = len(items)
    if not n: return 0.0, 0.0, 0.0
    f = [1 if pred(x) else 0 for x in items]; p = sum(f) / n
    bs = sorted(sum(rng.choices(f, k=n)) / n for _ in range(B))
    return p, bs[int(0.025 * B)], bs[int(0.975 * B)]

def sum_note(pcts, what="The % column"):
    """Sentence for a complete % column whose one-decimal rows do not sum to 100.0; None if they do."""
    t = f"{sum(float(f'{p:.1f}') for p in pcts):.1f}"
    return None if t == "100.0" else f"*{what} sums to {t}, not 100.0, because each row is rounded to one decimal place.*"

READ = ("How to read the tables: n is the denominator of the % column. It counts records unless the description says otherwise. "
        "% is rounded to one decimal. Where a table lists only the most frequent values, the remaining values are pooled in a last row, "
        "so each % column covers all of n. Where a column still does not sum to 100.0, a line under the table says why.")

def table(title, items, key, top=12, ci=False, note=None, desc=None, rest=True, by_value=False):
    """Markdown frequency table of key(item) over items, optional bootstrap CI per row.
    desc: description printed under the title. rest: pool the values beyond `top` into a last row and,
    if the % column still misses 100.0, say why. by_value: order rows by value instead of by count."""
    c = collections.Counter(key(x) for x in items); n = len(items)
    rows = c.most_common(top)
    if by_value: rows.sort()
    L = [f"\n**{title}** (n = {n:,})" + (f" — {note}" if note else ""), ""] + ([desc, ""] if desc else [])
    L += ["| value | n | % |" + (" 95% CI |" if ci else ""), "|---|---|---|" + ("---|" if ci else "")]
    for k, v in rows:
        row = f"| {k} | {v:,} | {100*v/n:.1f} |"
        if ci:
            p, lo, hi = boot_ci(items, lambda x, k=k: key(x) == k); row += f" {100*lo:.1f}–{100*hi:.1f} |"
        L.append(row)
    if rest:
        hidden, m = len(c) - len(rows), n - sum(v for _, v in rows)
        if hidden: L.append(f"| *{hidden:,} more values (pooled)* | {m:,} | {100*m/n:.1f} |" + (" |" if ci else ""))
        s = sum_note([100*v/n for _, v in rows] + ([100*m/n] if hidden else []))
        if s: L += ["", s]
    return L

def write(name, lines):
    p = OUT / name; p.write_text("\n".join(lines) + "\n"); print(f"wrote {p.relative_to(ROOT)}"); return p
