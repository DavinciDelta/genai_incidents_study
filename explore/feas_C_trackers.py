"""feas_C_trackers.py — Claim C: does the association hold tracker by tracker, and what would an outside sample need?

C1 per underlying tracker (source-id prefix): records listing it, frame entry, ON / WITH / BOTH, ON share of ON+WITH, under the
   published split, the text-only split and the step-4 reviewed labels; 'sole' = records whose every source id is from that tracker
C2 tracker x year for the large trackers (is the 2026 harm-db ON-AI rise one tracker?)
C3 records cross-listed between a vulnerability tracker and a harm tracker
C4 sizing a separately assembled primary-source sample (expectation-setting only: frame-entry rates per channel from step 2)
Writes feas_C_trackers.json next to this file.
"""
import collections, math
from feas_lib import (CH, FRAME, load_all, classify, reviewed_pop, tracker, tracker_channel, dump)

C, S, P = load_all()
T = {i: classify(C[i], use_vector=False)[0] for i in C}
R = {i: reviewed_pop(i, S, P) for i in C}
pct = lambda a, b: f"{100*a/b:.1f}%" if b else "—"
out = {}
FAMILY = {"USENIX": "academic venue (USENIX/CCS/NDSS)", "CCS": "academic venue (USENIX/CCS/NDSS)", "NDSS": "academic venue (USENIX/CCS/NDSS)",
          "INC": "curated legacy (INC/LEGACY)", "LEGACY": "curated legacy (INC/LEGACY)"}
fam = lambda s: FAMILY.get(tracker(s), tracker(s))
ORDER = ["CVE", "GHSA", "MAL", "OECD", "AIID", "AIAAIC", "AVID", "VTR", "ATLAS", "ARXIV", "academic venue (USENIX/CCS/NDSS)", "RES", "EXT", "OWASP",
         "PROMPTFOO", "GARAK", "REDTEAM", "curated legacy (INC/LEGACY)"]
recs = collections.defaultdict(set)
for i, r in C.items():
    for s in r.get("source_ids") or []: recs[fam(s)].add(i)
assert set(recs) <= set(ORDER), set(recs) - set(ORDER)

def split(ids, pop):
    c = collections.Counter(pop[i] for i in ids); on, wi = c["ON-AI"], c["WITH-AI"]
    return c, on, wi

print("# C1. ON / WITH split within each underlying tracker (a record counts under every tracker it lists)\n")
print("| tracker | channel | records | in frame | ON-AI | WITH-AI | BOTH | ON share of ON+WITH: published | text only | reviewed | sole-tracker records: ON share (published) | majority |")
print("|---|---|---|---|---|---|---|---|---|---|---|---|")
pubpop = {i: S[i]["population"] for i in C}
for t in ORDER:
    ids = recs.get(t, set())
    if not ids: continue
    c, on, wi = split(ids, pubpop); fr = sum(c[p] for p in FRAME)
    _, ton, twi = split(ids, T); _, ron, rwi = split(ids, R)
    sole = {i for i in ids if all(fam(s) == t for s in C[i]["source_ids"])}
    _, son, swi = split(sole, pubpop)
    chs = collections.Counter(tracker_channel(s) for i in ids for s in C[i]["source_ids"] if fam(s) == t).most_common(1)[0][0]
    maj = "—" if on + wi < 10 else ("ON-AI" if on > wi else "WITH-AI")
    print(f"| {t} | {chs} | {len(ids):,} | {fr:,} ({pct(fr, len(ids))}) | {on:,} | {wi:,} | {c['BOTH']} | {pct(on, on + wi)} ({on}/{on + wi}) | "
          f"{pct(ton, ton + twi)} ({ton}/{ton + twi}) | {pct(ron, ron + rwi)} ({ron}/{ron + rwi}) | {pct(son, son + swi)} ({son}/{son + swi}) | {maj} |")
    out.setdefault("C1", {})[t] = {"channel": chs, "records": len(ids), "frame": fr, "on": on, "with": wi, "both": c["BOTH"],
                                   "text_only": [ton, twi], "reviewed": [ron, rwi], "sole": [son, swi]}
print("\nmajority = which population is larger among the tracker's ON+WITH records (— if fewer than 10).")

# AVID: what kind of records are its ON-AI ones?
avid = [i for i in recs["AVID"] if S[i]["population"] == "ON-AI"]
print(f"\nAVID ON-AI records ({len(avid)}): record types {dict(collections.Counter(C[i]['category'] for i in avid))}; attack vectors {dict(collections.Counter(C[i].get('attack_vector') for i in avid).most_common(4))}; "
      f"titles containing 'Guardrail Jailbreak' {sum('Guardrail Jailbreak' in C[i]['title'] for i in avid)}.")
oecd_on = [i for i in recs["OECD"] if S[i]["population"] == "ON-AI"]
print(f"OECD ON-AI records ({len(oecd_on)}): record types {dict(collections.Counter(C[i]['category'] for i in oecd_on))}; channel {dict(collections.Counter(S[i]['source_class'] for i in oecd_on))}; "
      f"reviewed: still ON-AI {sum(R[i] == 'ON-AI' for i in oecd_on)}, no attacker {sum(R[i] == 'NONE (review)' for i in oecd_on)}; 'other/other' leak (AI was the tool) "
      f"{sum(P[i]['entry_point_post'] == 'other' and P[i]['target_post'].startswith('other') for i in oecd_on)}.")

vtr = [i for i in recs["VTR"] if S[i]["population"] in FRAME]
print(f"VTR (vendor threat-intel reports: OpenAI, Anthropic, Google, Microsoft, ...) frame records ({len(vtr)}): published {dict(collections.Counter(S[i]['population'] for i in vtr))}; "
      f"rules {dict(collections.Counter(S[i]['rule'] for i in vtr))}; corpus vectors {dict(collections.Counter(C[i].get('attack_vector') for i in vtr).most_common(3))}; "
      f"text only {dict(collections.Counter(T[i] for i in vtr))}; the ON-AI ones after review: {dict(collections.Counter(P[i]['entry_point_post'] for i in vtr if S[i]['population'] == 'ON-AI'))}.")

# ------------------------------------------------------------------ C2 tracker x year
print("\n# C2. ON share of ON+WITH by tracker and record year (published split)\n")
YEARS = (2022, 2023, 2024, 2025, 2026)
print("| tracker | " + " | ".join(str(y) for y in YEARS) + " |\n|---|" + "---|" * len(YEARS))
for t in ("CVE", "GHSA", "OECD", "AIID", "AIAAIC", "AVID"):
    row = []
    for y in YEARS:
        ids = [i for i in recs[t] if C[i]["year"] == y]; _, on, wi = split(ids, pubpop)
        row.append(f"{pct(on, on + wi)} ({on}/{on + wi})" if on + wi else "—")
    print(f"| {t} | " + " | ".join(row) + " |")
    out.setdefault("C2", {})[t] = row
hdb26 = [i for i in C if S[i]["source_class"] == "harm-db" and C[i]["year"] == 2026 and S[i]["population"] == "ON-AI"]
print(f"\nharm-db 2026 ON-AI records ({len(hdb26)}) by tracker listed: {dict(collections.Counter(fam(s) for i in hdb26 for s in C[i]['source_ids']).most_common())}; "
      f"reviewed still ON-AI {sum(R[i] == 'ON-AI' for i in hdb26)}.")

# ------------------------------------------------------------------ C3 cross-listed records
VULN, HARM = {"CVE", "GHSA"}, {"OECD", "AIID", "AIAAIC", "AVID"}
cross = [i for i in C if {tracker(s) for s in C[i]["source_ids"]} & VULN and {tracker(s) for s in C[i]["source_ids"]} & HARM]
multi_h = [i for i in C if len({tracker(s) for s in C[i]["source_ids"]} & HARM) >= 2]
print(f"\n# C3. Cross-listing\n\nRecords listed by both a vulnerability tracker (CVE/GHSA) and a harm tracker: {len(cross)}; populations {dict(collections.Counter(S[i]['population'] for i in cross))}.")
print(f"Records listed by 2+ harm trackers: {len(multi_h)}; populations {dict(collections.Counter(S[i]['population'] for i in multi_h))}. "
      "A tracker-by-tracker replication therefore runs on almost disjoint record sets.")
out["C3"] = {"vuln_x_harm": len(cross), "multi_harm": len(multi_h)}

# ------------------------------------------------------------------ C4 sizing an outside sample
print("\n# C4. Sizing a separately assembled primary-source sample (expectation-setting from step 2; not a finding)\n")
chn = collections.Counter(S[i]["source_class"] for i in C); frn = collections.Counter(S[i]["source_class"] for i in C if S[i]["population"] in FRAME)
z = 1.96
def n_for(p, h): return math.ceil(z * z * p * (1 - p) / h / h)
print("| channel | frame-entry rate in the index (step 2) | ON share (published) | records with an adversary needed for ±5 pts | ±7 pts | records to screen for ±7 pts at that entry rate |")
print("|---|---|---|---|---|---|")
for ch in CH:
    e = frn[ch] / chn[ch]; t = collections.Counter(S[i]["population"] for i in C if S[i]["source_class"] == ch)
    p = t["ON-AI"] / (t["ON-AI"] + t["WITH-AI"])
    print(f"| {ch} | {pct(frn[ch], chn[ch])} ({frn[ch]:,}/{chn[ch]:,}) | {100*p:.1f}% | {n_for(p, .05)} | {n_for(p, .07)} | {math.ceil(n_for(p, .07) / e):,} |")
# two-proportion power: n per group to detect p1 vs p2 at alpha .05, power .8
def n2(p1, p2, za=1.96, zb=0.8416):
    pb = (p1 + p2) / 2
    return math.ceil((za * math.sqrt(2 * pb * (1 - pb)) + zb * math.sqrt(p1 * (1 - p1) + p2 * (1 - p2))) ** 2 / (p1 - p2) ** 2)
print(f"\nTo detect the published contrast (CVE/GHSA ON 88.3% vs harm-db ON 21.3%) at alpha .05, power .8: {n2(.883, .213)} adversary records per channel; "
      f"a much weaker contrast (70% vs 40%): {n2(.70, .40)} per channel; (60% vs 45%): {n2(.60, .45)} per channel.")
print("Inter-coder agreement on ON/WITH: a two-coder kappa with a 95% CI half-width of about 0.1 needs roughly 100–150 double-coded records "
      "(rule of thumb for kappa near 0.7–0.8 and balanced classes).")
out["C4"] = {"n2_published": n2(.883, .213), "n2_70_40": n2(.70, .40), "n2_60_45": n2(.60, .45)}
dump("feas_C_trackers.json", out)
