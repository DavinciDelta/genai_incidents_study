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
    """Attach rank-validation's classifier labels and hand labels to current corpus records, following ID redirects.
    Several snapshot ids can land on one current record (the corpus merged duplicates since the snapshot). The record
    keeps ONE representative snapshot id: a hand-labelled one if any landed (its own id first), else its own id, else the first;
    `gold_all` keeps every hand-label list that landed on it, `snapshot_ids` every id. Returns rows, the unresolved ids,
    and `collapsed` = number of resolving ids beyond one per record."""
    from genai_incidents import resolve_id, load_deprecations
    deps = load_deprecations(); landed, unresolved = collections.defaultdict(list), []
    for inc_id in rv["labels"]:
        cur = inc_id if inc_id in corpus else (resolve_id(inc_id) if inc_id in deps else None)
        if not cur or cur not in corpus: unresolved.append(inc_id); continue
        landed[cur].append(inc_id)
    rows = {}
    for cur, ids in landed.items():
        rep = cur if (cur in ids and cur in rv["gold"]) else next((i for i in ids if i in rv["gold"]), cur if cur in ids else ids[0]); lab = rv["labels"][rep]
        g = rv["gold"].get(rep)
        rows[cur] = {"rv_entries": sorted({l["entry_id"] for l in lab}), "rv_stage": max(l["stage"] for l in lab),
                     "gold_labels": g["labels"] if g else None, "snapshot_id": rep, "snapshot_ids": ids,
                     "gold_all": [rv["gold"][i]["labels"] for i in ids if i in rv["gold"]]}
    return {"rows": rows, "unresolved": unresolved, "collapsed": sum(len(v) - 1 for v in landed.values())}

def blind_agreement(rv: dict) -> tuple:
    """Rows where the adjudicator's blind label (before seeing the LLM votes) equals the final label exactly:
    a single final label equal to the blind one, or 'out-of-scope' against an empty label list. Returns (rows, total)."""
    g = rv["gold"].values()
    return sum(v["labels"] == [v.get("blind_label")] or (v.get("blind_label") == "out-of-scope" and v["labels"] == []) for v in g), len(rv["gold"])

def load_prelabels() -> dict:
    """rank-validation's three-LLM pre-labels (calibration/llm_prelabels.jsonl): snapshot id -> {consensus, agreement, triage_tier}.
    The hand-labelled set was drawn from these: every 'disagree' row, and a quota per consensus entry."""
    out = {}
    for line in open(CYCLE / "calibration/llm_prelabels.jsonl"):
        d = json.loads(line); out[d["incident_id"]] = {k: d.get(k) for k in ("consensus", "agreement", "triage_tier")}
    return out

def owasp_names(rv: dict) -> dict:
    """The ten OWASP LLM Top 10 entries under both numberings, matched by name (never by number), plus the ten proposed
    additions. Returns {'corpus': {corpus code: name}, 'rv': {rv id: name}, 'rv2corpus': {rv id: corpus code},
    'corpus2rv': {corpus code: rv id}, 'asi': {ASI code: name}}."""
    corp = {k: v["name"] for k, v in json.load(open(EXT / "owasp_llm_top10_2026.json"))["entries"].items()}
    asi = {k: v["name"] for k, v in json.load(open(EXT / "owasp_asi_top10.json"))["entries"].items()}
    norm = lambda t: t.lower().replace("vulnerabilities", "").replace("weaknesses", "").replace(" and ", " ").strip()
    rvn = {e: t["canonical_name"] for e, t in rv["taxonomy"].items()}
    rv2c = {e: next((k for k, n in corp.items() if norm(n) == norm(nm)), None) for e, nm in rvn.items()}
    rv2c = {e: c for e, c in rv2c.items() if c}
    assert len(rv2c) == 10 and set(rv2c.values()) == set(corp), "the ten OWASP LLM entries must match by name"
    return {"corpus": corp, "rv": rvn, "rv2corpus": rv2c, "corpus2rv": {c: e for e, c in rv2c.items()}, "asi": asi}

# ---------------------------------------------------------------- MITRE ATLAS release
def load_atlas() -> dict:
    """The pinned MITRE ATLAS release (external/ATLAS.yaml), read with regexes because stdlib has no YAML parser.
    Returns techniques {id: {name, attack_ref, maturity}}, mitigations {id: {name, categories, lifecycle}}
    and mitigates {technique id: {mitigation ids}} from MITRE's own `mitigates` relationships."""
    txt = (EXT / "ATLAS.yaml").read_text()
    def entries(section, prefix):
        parts = re.split(rf"^  ({prefix}[\d.]+):\n", re.search(rf"^{section}:\n(.*?)(?=^\S|\Z)", txt, re.S | re.M).group(1), flags=re.M)
        return dict(zip(parts[1::2], parts[2::2]))
    one = lambda body, key: (m.group(1).strip("'\"") if (m := re.search(rf"^    {key}: (.*)$", body, re.M)) else None)
    many = lambda body, key: (re.findall(r"^    - (.*)$", m.group(1), re.M) if (m := re.search(rf"^    {key}:\n((?:    - .*\n)+)", body, re.M)) else [])
    tech = {t: {"name": one(b, "name"), "maturity": one(b, "maturity"),
                "attack_ref": (m.group(1) if (m := re.search(r"^    attack-reference:\n      id: (\S+)", b, re.M)) else None)}
            for t, b in entries("techniques", r"AML\.T").items()}
    mit = {m: {"name": one(b, "name"), "categories": many(b, "categories"), "lifecycle": many(b, "lifecycle-phases")}
           for m, b in entries("mitigations", r"AML\.M").items()}
    rel = collections.defaultdict(set)
    for m, t in re.findall(r"- source: (AML\.M\d+)\n\s+target: (AML\.T[\d.]+)\n\s+relationship-type: mitigates", txt): rel[t].add(m)
    return {"techniques": tech, "mitigations": mit, "mitigates": rel}

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

HOWTO = ("**How to read every table in `out/`.** n is the denominator of the % column and counts records unless the description says "
         "otherwise. Percentages round to one decimal, so a complete column can sum to 99.9 or 100.1. Where only the most frequent values "
         "are listed, the rest are pooled in a last row; `other` is the corpus's own value, not the pooled row. Where a record can carry "
         "several labels, shares are per label and need not sum to 100. 95% CI means a percentile bootstrap over records (2,000 resamples); "
         "hand-labelled shares carry no CI because that sample was not drawn at random. ON-AI and WITH-AI are never pooled, and shares are "
         "also given within each disclosure channel because each channel sees a different population. Corpus labels (OWASP, ATLAS, attack "
         "vector) are keyword rules, not coded fields. Record year reflects when a tracker was ingested. OWASP codes use the corpus's "
         "numbering and names are always printed.")
GLOSSARY = [
    ("disclosure channel", "this study's grouping of records by the kind of tracker they came from: `cve/ghsa` (vulnerability feeds), `harm-db` (OECD, AIID, AIAAIC, AVID harm databases) or `research/other`; see Table 1.2."),
    ("population", "this study's split of records by whose AI it is: ON-AI (the victim's AI is attacked), WITH-AI (the AI is the attacker's instrument), BOTH, UNRESOLVED, NONE; see step 2."),
    ("adversary frame", "ON-AI + WITH-AI + BOTH: the records in which someone attacked."),
    ("rank-validation", "incident-rank-validation, a separate project that re-labelled a May 2026 snapshot of this corpus against the OWASP LLM Top 10 candidate list. Its artifacts are read here, never run."),
    ("classifier label", "the entry rank-validation's own classifier (keyword rules, then an LLM) assigned to a snapshot record."),
    ("hand-labelled", "labelled by rank-validation's one human adjudicator, who chose one of 20 entries or decided that no entry fits. 1,200 rows, drawn by quota from three LLM pre-labellers' agreement, not at random; see Table 1.14."),
    ("no entry fits", "the adjudicator's verdict that none of the 20 entries applies (stored as an empty label list)."),
    ("proposed additions", "the ten NEW-/ROLL- entries in rank-validation's 2026 candidate list that are not in the OWASP LLM Top 10."),
    ("community vote", "the OWASP community vote rank of each candidate entry, as reported by rank-validation."),
    ("data rank", "rank-validation's rank of each entry by estimated incident count over its whole 7,714-record snapshot, with a 90% interval; its agreement with the vote is weighted κ = 0.20 (interval −0.16 to 0.57)."),
    ("frame-blind", "an entry rank-validation declared unobservable in this corpus and left out of its ranking: Data and Model Poisoning, Vector and Embedding Weaknesses, Unbounded Consumption."),
    ("the two numberings", "the corpus and rank-validation number the same ten OWASP entries differently (corpus LLM04 = Supply Chain, rank-validation LLM04 = Data and Model Poisoning); every join is by name; see Table 1.0."),
    ("corpus lookup", "the fixed OWASP-code → ATLAS-technique table in the corpus's build script, which produces most of its ATLAS labels."),
    ("ATLAS / ATT&CK", "MITRE ATLAS, the adversary-technique catalogue for AI systems, and its parent Enterprise ATT&CK catalogue; ATLAS publishes technique → mitigation links."),
    ("record type", "the corpus `category` field: vulnerability disclosure, real-world incident, research, research-demonstrated, red-team or threat report. 'Demonstrated' below means research, research-demonstrated or red-team."),
    ("unstated", "no keyword rule matched: the record does not say. These rows are the hand-coding workload."),
    ("snapshot", "the 7,714-record copy of this corpus that rank-validation labelled in May 2026; its ids are followed to the current corpus through the package's redirects."),
    ("classifier stage", "how rank-validation's classifier labelled a snapshot record: stage 1 = keyword rules, stage 2 = an LLM on the rest."),
    ("posterior mean", "rank-validation's recall and precision estimates: (hits + 1) / (rows + 2), a Beta(1,1) prior over the hand-labelled rows behind each entry."),
    ("90% interval vs 95% CI", "rank-validation reports 90% intervals on its ranks; this study's own proportions carry 95% bootstrap CIs. The two are never mixed in one column."),
    ("realized", "a real-world incident or a vulnerability disclosure (corpus record type), as opposed to a demonstration or a threat report."),
    ("ATLAS category, lifecycle phase, tactic", "ATLAS's own tags: the kind of control a mitigation is (Policy, Technical - AI, Technical - Cyber), the model-lifecycle stages it belongs to, and the adversary goal a technique serves (Initial Access, Execution, Impact, …)."),
]
READ = "Conventions, 95% CI, pooled rows and the glossary: `out/s01_overview.md` section 0."

CHANNELS = ("cve/ghsa", "harm-db", "research/other")

def table(title, items, key, top=12, ci=False, note=None, desc=None, rest=True, by_value=False, num=None, channels=False, floor=0, col="value", rounding_note=False):
    """Markdown frequency table of key(item) over items.
    num: table number, printed as 'Table <num>'. ci: bootstrap 95% CI per row. channels: add the share of each disclosure channel's
    items carrying the value (items must be corpus records). floor: rows with fewer items than this show counts but no % or CI.
    rest: pool the values beyond `top` into a last row. by_value: order rows by value. rounding_note: add the old per-table rounding line."""
    c = collections.Counter(key(x) for x in items); n = len(items)
    rows = c.most_common(top)
    if by_value: rows.sort()
    ch = {x: [r for r in items if source_class(r) == x] for x in CHANNELS} if channels else {}
    head = (f"**Table {num}. " if num else "**") + f"{title}** (n = {n:,})"
    L = ["", head, ""] + ([desc, ""] if desc else []) + ([f"*{note}*", ""] if note else [])
    cols = [col, "n", "%"] + (["95% CI"] if ci else []) + ([f"% in {x}" for x in CHANNELS] if channels else [])
    L += ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    def pct(a, b): return f"{100*a/b:.1f}" if b else "—"
    for k, v in rows:
        small = v < floor
        row = f"| {k} | {v:,} | {'—' if small else pct(v, n)} |"
        if ci:
            if small: row += " — |"
            else: p, lo, hi = boot_ci(items, lambda x, k=k: key(x) == k); row += f" {100*lo:.1f}–{100*hi:.1f} |"
        if channels: row += "".join(f" {'—' if small else pct(sum(key(r) == k for r in ch[x]), len(ch[x]))} |" for x in CHANNELS)
        L.append(row)
    if rest:
        hidden, m = len(c) - len(rows), n - sum(v for _, v in rows)
        if hidden: L.append(f"| *{hidden:,} more values (pooled)* | {m:,} | {pct(m, n)} |" + (" |" if ci else "") + ("".join(f" {pct(sum(key(r) not in dict(rows) for r in ch[x]), len(ch[x]))} |" for x in CHANNELS) if channels else ""))
        if rounding_note:
            s = sum_note([100*v/n for _, v in rows] + ([100*m/n] if hidden else []))
            if s: L += ["", s]
    return L

def write(name, lines):
    p = OUT / name; p.write_text("\n".join(lines) + "\n"); print(f"wrote {p.relative_to(ROOT)}"); return p
