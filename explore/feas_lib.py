"""feas_lib.py — shared loaders for the exploratory feasibility scripts (feas_A/B/C; 2026-10-08). Reads the repository; writes only to explore/out/.
Not part of `make all`: these numbers back docs/POSITIONING.md and are candidates for a future pipeline step.

Step 2's rules are reused, not copied: the vector sets, regexes and classify() are exec'd from s02_split.py's own source
(ast, constant assignments and the one function only), so the script itself never runs and out/split.json is never written.
"""
from __future__ import annotations
import ast, collections, csv, json, math, re, sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRATCH = Path(__file__).resolve().parent / "out"   # explore/out: exploratory outputs, not part of `make all`
sys.path.insert(0, str(REPO))
from common import load_full, load_rv, join_rv, load_prelabels, source_class, text  # noqa: E402

CH = ("cve/ghsa", "harm-db", "research/other")
FRAME = ("ON-AI", "WITH-AI", "BOTH")
NO_ATT = "no attacker: operator harm or model failure (misplaced record)"
NONE_W = "none: conventional exploit record misplaced in WITH-AI"
DEMO = {"research", "research-demonstrated", "red-team"}

# ------------------------------------------------------------------ step-2 rules, exec'd from s02_split.py's source
def s02_rules() -> dict:
    tree = ast.parse((REPO / "s02_split.py").read_text())
    ns = {"re": re, "text": text}
    want = {"ON_VEC", "WITH_VEC", "CODE_VEC", "ADV", "WITH_KW", "ON_KW"}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and any(getattr(t, "id", None) in want for t in node.targets)) or \
           (isinstance(node, ast.FunctionDef) and node.name == "classify"):
            exec(compile(ast.Module([node], []), "s02_split.py", "exec"), ns)
    return ns

R2 = s02_rules()

def classify(r: dict, use_vector: bool = True) -> tuple:
    """Step 2's classify(); use_vector=False blanks the corpus attack_vector so only text + record type decide."""
    return R2["classify"](r if use_vector else {**r, "attack_vector": None})

# ------------------------------------------------------------------ data
def load_all():
    C = load_full()
    S = json.load(open(REPO / "out/split.json"))
    P = {r["id"]: r for r in csv.DictReader(open(REPO / "out/dataset_post.csv"))}
    return C, S, P

def reviewed_pop(i: str, S: dict, P: dict, leak_to_with: bool = False) -> str:
    """Population after step 4's review: ON-AI / WITH-AI records the review found have no adversary become 'NONE (review)';
    WITH-AI conventional-exploit records misplaced there become 'CVE misplaced (review)'. leak_to_with: also move ON-AI records
    whose reviewed entry point AND target are 'other' (AI as the attacker's tool, per the review notes) to WITH-AI."""
    pop = S[i]["population"]
    if pop == "ON-AI":
        ep, tg = P[i]["entry_point_post"], P[i]["target_post"]
        if ep == NO_ATT: return "NONE (review)"
        if leak_to_with and ep == "other" and tg.startswith("other"): return "WITH-AI"
        return "ON-AI"
    if pop == "WITH-AI":
        ar = P[i]["ai_role_post"]
        if ar == NO_ATT: return "NONE (review)"
        if ar == NONE_W: return "CVE misplaced (review)"
        return "WITH-AI"
    return pop

TRACKER_CH = {"CVE": "cve/ghsa", "GHSA": "cve/ghsa", "OECD": "harm-db", "AIID": "harm-db", "AIAAIC": "harm-db", "AVID": "harm-db"}
def tracker(sid: str) -> str:
    m = re.match(r"[A-Za-z]+", sid); return m.group(0).upper() if m else sid
def tracker_channel(sid: str) -> str:
    return TRACKER_CH.get(tracker(sid), "research/other")

# ------------------------------------------------------------------ metrics
def metrics(units, frame=FRAME) -> dict:
    """units: iterable of (channel, population, weight). Headline numbers of the channel x population association.
    cve_on = ON-AI share of cve/ghsa frame units; hdb_with = WITH-AI share of harm-db frame units; res_on likewise;
    pooled_on = ON / (ON + WITH) over all channels; ratio = ON : WITH; V = Cramér's V on channel x {ON, WITH} (BOTH left out).
    frame: the populations that make up the denominator of the channel shares (default ON-AI, WITH-AI, BOTH)."""
    t = collections.defaultdict(lambda: collections.Counter())
    for ch, pop, w in units: t[ch][pop] += w
    fr = {ch: sum(t[ch][p] for p in frame) for ch in CH}
    sh = lambda ch, p: t[ch][p] / fr[ch] if fr[ch] else float("nan")
    on, wi = sum(t[ch]["ON-AI"] for ch in CH), sum(t[ch]["WITH-AI"] for ch in CH)
    # Cramér's V, 3 x 2, ON vs WITH only
    rows = [(t[ch]["ON-AI"], t[ch]["WITH-AI"]) for ch in CH if t[ch]["ON-AI"] + t[ch]["WITH-AI"] > 0]
    n = sum(a + b for a, b in rows); col = (sum(a for a, _ in rows), sum(b for _, b in rows)); chi2 = 0.0
    for a, b in rows:
        rt = a + b
        for obs, ct in ((a, col[0]), (b, col[1])):
            e = rt * ct / n if n else 0
            if e: chi2 += (obs - e) ** 2 / e
    V = math.sqrt(chi2 / n) if n else float("nan")
    return {"table": {ch: dict(t[ch]) for ch in CH}, "frame_n": fr, "cve_on": sh("cve/ghsa", "ON-AI"), "hdb_with": sh("harm-db", "WITH-AI"),
            "res_on": sh("research/other", "ON-AI"), "ON": on, "WITH": wi, "pooled_on": on / (on + wi) if on + wi else float("nan"),
            "ratio": on / wi if wi else float("nan"), "V": V}

def fmt_n(x) -> str:
    return f"{x:,.0f}" if abs(x - round(x)) < 1e-9 else f"{x:,.1f}"

def line(label: str, m: dict) -> str:
    fr, t = m["frame_n"], m["table"]
    c = lambda ch, p: fmt_n(t[ch].get(p, 0))
    return (f"| {label} | {100*m['cve_on']:.1f}% ({c('cve/ghsa','ON-AI')}/{fmt_n(fr['cve/ghsa'])}) | {100*m['hdb_with']:.1f}% ({c('harm-db','WITH-AI')}/{fmt_n(fr['harm-db'])}) | "
            f"{100*m['res_on']:.1f}% ({c('research/other','ON-AI')}/{fmt_n(fr['research/other'])}) | {100*m['pooled_on']:.1f}% ({fmt_n(m['ON'])}/{fmt_n(m['ON']+m['WITH'])}) | "
            f"{m['ratio']:.2f} | {m['V']:.2f} |")

HEAD = ["| cut | CVE/GHSA: ON-AI share of frame | harm-db: WITH-AI share of frame | research/other: ON-AI share | pooled ON / (ON+WITH) | ON:WITH ratio | Cramér's V (ON vs WITH) |",
        "|---|---|---|---|---|---|---|"]

def dump(name: str, obj) -> None:
    (SCRATCH / name).write_text(json.dumps(obj, indent=1, default=str))
