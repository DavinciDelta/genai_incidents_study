# Attacker methodology in real-world AI incidents

<!-- Working draft. Every number below is produced by a script in this folder; regenerate with `make all`
     before quoting, and cite the table id (Table 2.2, Table 4.1, …) so a reader can find it in out/.
     Blocks marked TODO are yours to fill.

     THE STORY (the spine every section hangs on):
     1. Everyone ranks AI threats by vote or by harm. Nobody has checked what the public record says about
        how attackers actually operate, because the record is an index of other trackers whose labels are
        keyword rules.
     2. The first thing the record shows is that "AI incidents" are two different populations: attacks ON
        AI systems (vulnerability feeds) and attacks WITH AI (harm databases). Which one you see depends on
        where you look, so every pooled statistic in circulation is a statistic about reporting channels.
     3. Within each population, the public record, read carefully, says something specific: ON-AI is an
        agent-and-tooling story in which half the entries are conventional software bugs; WITH-AI is a
        deepfake-fraud story in which the medium is usually not even stated.
     4. The expert vote and the record disagree where it matters (Improper Output Handling, MCP tool
        exploitation, deepfake misuse), and a human re-labelling agrees with neither fully.
     5. What this licenses is not a corrected Top 10 but a sampling frame, a codebook and a workload for
        the hand-coded study that can answer the attacker question. -->

## Abstract

<!-- TODO: 150–200 words. Skeleton: -->
Public analysis of AI incidents is organised around harm (AI Incident Database taxonomies; MIT AI Risk
Repository; Li et al. AIES 2025) or around expert vote (OWASP LLM Top 10). We ask instead how adversaries
operate, and what the public record can and cannot say about it. Using the open genai_incidents index
(**15,666** records from CVE/GHSA feeds, four harm databases and research write-ups) as a sampling frame,
rule-based classification finds **2,832** adversary-present records and splits them by whose AI it is:
attacks **on** AI systems (**1,339**) and attacks **with** AI (**1,460**). The populations arrive through
nearly disjoint channels: 88% of adversary records from CVE/GHSA are on-AI, 78% from harm databases are
with-AI (Table 2.2), so pooled statistics about "AI incidents" measure reporting channels. Within
populations, on-AI is an agent-and-tooling story in which 45% of records carry a CVE or CWE and a quarter
enter through a conventional software bug (Tables 4.1–4.3); with-AI is deepfake fraud whose medium the
record usually does not state (Tables 4.4–4.5). The corpus's category ranking disagrees with the OWASP
community vote by up to eleven places, and one person's hand labels disagree with both (Tables 5.1–5.3).
We release the classified datasets, a limitations audit of AI-incident data, and the frame for a
hand-coded study.

## 1. Introduction

<!-- TODO: motivation paragraph in your words. Anchors: -->
- The harm view is well served: AIID and its taxonomies; MIT AI Risk Repository and tracker; Li et al.
  AIES 2025 (499 GenAI incidents, who/what/how). The attacker view is not: ATLAS case studies are few;
  Grosse et al. AAAI 2024 code 32 incidents; Kumar et al. 2026 (Agent Incident Registry) code 487 agent
  incidents with one curator and no agreement statistic; the only OWASP-vs-incident test (Lambros &
  Wilson 2026) found weighted κ 0.20 with an interval crossing zero and three unobservable entries
  (Table 1.15), pooled over sources.
- The vocabulary is older than the data: criminology distinguished crimes *with*, *against* and *by* AI
  before any incident corpus existed (Hayward & Maas 2021; Caldwell et al. 2020); single-database codings
  reproduce it (Huwyler 2025 on AIID; Maugeri et al. AISec 2025 on CVE). What nobody has shown is that the
  two populations come from different channels, so that the mix in any pooled index is a property of the
  index.
- Reporting bias is acknowledged in words but not measured: AIID counts "conflate media reporting
  propensity, system deployment and harm frequency" (Mengesha et al. 2026); surveillance has no
  denominators (Abraham et al. 2026); the Agent Incident Registry's realized-harm share "reflects the
  balance of disclosure pathways" (Kumar et al. 2026). Tables 2.2 and 5.1–5.3 put numbers on this.
- Why now: agentic incidents of 2025–26 (MCP servers, coding agents); vendor threat-intel reports now
  describe attributed campaigns; the OWASP LLM Top 10 (2026) and Agentic Top 10 are being adopted as
  priorities without an incident check.
<!-- Novelty, per the literature check of 2026-10-07: new = the population × channel cross-tab and its
     consequence; the label-derivation audit of an aggregated index (keyword OWASP codes; 90.7% of ATLAS
     labels from a lookup); per-population entry point / target / medium / objective with provenance and
     unstated shares. Partly done = the category-vs-vote comparison (Lambros & Wilson, pooled;
     Parthasarathy 2026 does the "fits no entry" test on 131 agentic AIID incidents). The method a
     reviewer will contest: LLM coders (Camporese, Massacci & Gong 2026 find them insufficient on
     security codes); answer with the agreement figures, the adjudicator and the planned human review. -->
- Contributions (<!-- TODO: in your words -->): (i) the on/with split and the channel finding; (ii) a
  classified, released dataset of the 2,799 on-AI and with-AI records with every value's provenance;
  (iii) the category-vs-vote comparison with its human check; (iv) a limitations audit of aggregated
  AI-incident data; (v) the sampling frame and codebook for the hand-coded study.

## 2. The data: an index of trackers whose labels are rules

Source: `s01_overview.py` → `out/s01_overview.md` (section 0 is the glossary and conventions).

- genai_incidents, pip 2.12.0, full JSON at tag v2.12.0 (pins in `external/PINS.json`): **15,666**
  records, 1983–2026; 7,475 with a CVE, 7,801 with a CWE; median description 281 characters (557 in
  CVE/GHSA records, 263 in harm databases, 259 in research), which is why it is a sampling frame and not
  coding material (Table 1.1, §B bullets).
- **Disclosure channel**, the study's one derived variable: CVE/GHSA 51.5%, harm databases (OECD, AIID,
  AIAAIC, AVID) 45.4%, research/other 3.1% (Table 1.2). Dates are month-only on 99.9% of CVE records and
  day-level on 76% of harm-database records (Table 1.7); 48.6% of records dated 2019+ carry 2026 because
  of catch-up ingestion (Tables 1.5–1.6), so no table here is a trend.
- **Labels are rule outputs.** The corpus's OWASP code "Supply Chain" sits on 98.2% of all CVE/GHSA
  records and arrives with the feed (Table 1.10); 36.0% of OWASP codes equal the code seeded from the
  attack-vector field; 90.7% of its 31,248 MITRE ATLAS technique labels are what a fixed OWASP→ATLAS
  lookup in its build script produces (§B2). Corpus labels stratify samples here; they never populate a
  hand-coded field.
- **An independent human check exists.** incident-rank-validation (Lambros 2026) hand-labelled 1,200
  rows of a May 2026 snapshot against the OWASP LLM Top 10 candidate list; 1,123 join current records
  (Table 1.13). The rows were drawn by quota over three LLM pre-labellers' agreement, not at random
  (Table 1.14), so they support "where labellings disagree", never prevalence. Its vote-vs-data
  concordance is weighted κ 0.20 (−0.16 to 0.57) over 17 of 20 entries (Table 1.15); per-entry recall
  0.01–0.49 (Table 1.16). The corpus and that project number the same ten OWASP entries differently;
  every join is by name (Table 1.0).

<!-- TODO: one paragraph on why it is still the right sampling frame (controlled attack vector, CVE link,
     record type, a resolvable primary reference on every row). -->

## 3. Two populations, two channels

Source: `s02_split.py` → `out/split.json`, `out/s02_split.md`; `s03_figures.py` → `out/fig1_on_with.svg`.

Deciding question: **whose asset is the AI system?** ON-AI = the victim's AI is subverted (target or
vector). WITH-AI = the attacker's AI is pointed at a conventional target. BOTH and UNRESOLVED carried
separately. Four in five records involve no adversary at all (NONE 12,655, 80.8%; Table 2.1).

| Population | n | share of the adversary frame (95% bootstrap CI) |
|---|---|---|
| ON-AI | 1,339 | 47.3% (45.4–49.0) |
| WITH-AI | 1,460 | 51.6% (49.8–53.4) |
| BOTH | 33 | 1.2% |
| UNRESOLVED | 179 | — ("fraud", "scam" or "campaign" fires, nothing says what the AI did; Table 2.12) |

![Figure 1](out/fig1_on_with.svg)

**The central finding (Table 2.2).** Of the frame records from CVE/GHSA, 88.0% are ON-AI; from harm
databases, 78.2% are WITH-AI; from research, 92.9% are ON-AI (Figure 1B, which omits BOTH, draws 88.3 /
78.7 / 97.3). Only 8.5% of CVE/GHSA records and 24.6% of harm-database records enter the frame at all.
**A pooled ON/WITH ratio is a ratio of channels, not of attacks**, and so is every downstream share.

What each population is (Tables 2.6–2.9): ON-AI is 40.9% vulnerability disclosures with no observed
attack, 29.1% real-world incidents and 22.9% demonstrations (research, research-demonstrated, red-team);
its top corpus vector is prompt injection (25.7%) ahead of a long tail of conventional exploits. WITH-AI
is 80.8% deepfake and 94.2% real-world; its 80 vulnerability disclosures are misplaced CVEs (Table 2.5).

Independent check (Table 2.13): the person's hand labels land on different entries per population,
ON-AI on Data and Model Poisoning (22), Supply Chain (21), MCP Tool Interface Exploitation (17) and
Prompt Injection (15); WITH-AI on Misinformation (47) and Weaponized LLM Abuse (43) with 42.5% fitting no
entry. The split is recoverable by an independent coder.

<!-- TODO: worked example for the edge case (user jailbreaks a model, output used downstream → BOTH). -->

## 4. How the attacks happen, as far as the record says

Source: `s04_methodology.py` → `out/s04_methodology.md`, `out/dataset_pre.csv`, `out/dataset_post.csv`.

Each ON-AI record gets an entry point and a target component, each WITH-AI record an AI medium and an
attacker objective, assigned in a fixed order: a keyword rule over title + description + `affected`;
else the corpus attack-vector label where it maps to exactly one value; else a label-group rule (a
conventional-exploit label is an entry point of its own kind; a tracker stub names no target); else a
label coded from the text by two independent coders with an adjudicator (854 labels, agreement 85–100%
per dimension, `coded/relabels.json`). Table 4.0 gives the source counts; the pre- and
post-reclassification datasets are released. "Other" and "no attacker" stay visible as values.

**ON-AI (n = 1,339).** Entry point (Table 4.1): direct prompt 24.7%, exploit of a conventional software
vulnerability 22.9%, indirect carrier 14.6%, malicious package / model 9.8%, prompt injection with the
carrier not stated 6.0%, adversarial input 5.8%, the agent's tools or sandbox 5.3%, credential 4.7%,
exposed service 3.7%. Target (Table 4.2): agents, copilots and MCP 48.9% (79.6% of the CVE channel),
consumer chatbots 19.5%, tracker stubs naming no system 11.1%. Software basis (Table 4.3): 45.1% carry a
CVE or CWE, 31.5% a model-level vector with none, 23.4% neither.

**WITH-AI (n = 1,460).** Medium (Table 4.4): "deepfake, medium not stated" 41.5%, image 19.0%, voice
16.7%, text 7.9%, video 7.8%, generated code 0.6%. Objective (Table 4.5): financial fraud or extortion
32.1%, political influence 19.5%, non-consensual or abuse imagery 14.8%, defamation or impersonation
10.8%, intrusion 6.5%; 7.1% describe no attacker at all (a product failure filed as an incident).

<!-- TODO: 2 paragraphs interpreting. Points to make: ON-AI is an agent-and-tooling story and half of it
     is ordinary application security; WITH-AI is a deepfake-fraud story told by harm databases in stubs;
     LLM-assisted intrusion is nearly invisible in public databases (generated code 0.6%, intrusion 6.5%)
     even though vendor reports describe it. -->

## 5. Which categories stand out against the expert vote

Source: `s05_techniques.py` → `out/s05_techniques.md`.

Per population, the corpus's OWASP category rank against the OWASP community vote (20 candidates ranked
by respondents; Tables 5.1–5.2). ON-AI: Improper Output Handling sits +11 places above its vote rank
(corpus 2nd, vote 13th; 5% of its records are demonstrations); Supply Chain +4 but it is a channel marker
(98.2% of CVE records); Prompt Injection, the vote's first, is the corpus's third. WITH-AI: Misinformation
+12 (83.8% of records, also a channel marker). Neither is a corrected Top 10: the corpus column ranks
keyword rules.

**The hand labels disagree with both (Table 5.3).** The person's most-used ON-AI label, Data and Model
Poisoning (22), is the corpus's 7th; three labels with no corpus code hold 70 hand labels (MCP Tool
Interface Exploitation 17 and Cross-Modal Safety Bypass 10 in ON-AI, Weaponized LLM Abuse 43 in
WITH-AI); no entry fits 14% of hand-labelled ON-AI and 43% of WITH-AI rows, because every rubric entry
requires an LLM mechanism that deepfake fraud and classifier evaluations lack. Where the person did use a
corpus category the corpus usually carries it too (Prompt Injection 14 of 15), so the disagreement is in
what the corpus adds in bulk and what it cannot name.

<!-- TODO: one paragraph on what this licenses (expectation-setting; seed rows; the categories a
     hand-coded study must be able to express) and what it does not (prevalence; a corrected list). -->

## 6. The hand-coded study this sets up

<!-- TODO: paste/trim the 12-field frame. -->
Unit: an identifiable adversary acted with intent, against or by means of an AI system, with a primary
source describing the method. ~500 incidents from `out/dataset_post.csv`, stratified by population ×
year (2023–26) × channel, ON-AI oversampled, rows the person judged "no entry fits" excluded, hand-labelled
rows used as seeds. The coded values in `coded/relabels.json` are pre-codes to be confirmed, not codes.
Two coders on 20%, κ per field, rulebook frozen after a 30-incident pilot.

## 7. Statistical methods

- Deterministic rule classification for frame and strata; the rule that fired is recorded per record and
  checked against the 339 hand-labelled rows in the frame (Table 2.13).
- Percentile bootstrap (2,000 resamples) 95% CIs on every proportion; none on hand-labelled shares.
- Reclassification of unstated values: rules first, then two LLM coders and an adjudicator; agreement
  reported per dimension; a human review of the coded subset before any value is cited.
- Cohen's κ per hand-coded field (quadratic-weighted for ordered fields), pre-adjudication value reported.
- χ² / Fisher exact for ON-vs-WITH comparisons within channel, Cramér's V, Benjamini–Hochberg at 5% FDR.
- Temporal claims on primary-source disclosure date only (corpus dates are month-only for CVE records).
- Rank-validation artifacts used three ways only: out-of-scope exclusion, seed rows, expectation-setting.

## 8. Limitations of the data

Full list with numbers: `out/s05_techniques.md`, section "Limitations of the data".

- Channel confounding: 604 of 686 CVE-channel frame records are ON-AI, 1,370 of 1,753 harm-database ones
  WITH-AI; every pooled comparison compares channels (Table 2.2).
- Labels are rule outputs; Supply Chain marks the CVE channel (Tables 1.10, 5.1).
- The split is rule-based with unmeasured error: 707 of 1,262 vector-only WITH-AI rows contain no
  attacker word; 80 WITH-AI rows are CVEs (Table 2.5).
- One coder, a quota sample: 161 ON-AI and 174 WITH-AI hand-labelled rows; 77 of 1,200 rows have no
  current record of their own (Tables 1.13–1.14).
- Demonstration inflation (22.9% of ON-AI) and deepfake dominance (80.8% of WITH-AI).
- Ingestion-driven years, month-only CVE dates, tracker stubs (67 of the 74 WITH-AI no-entry rows), empty
  exploitation and attribution fields (Tables 1.5–1.7, 4.0).
- LLM-coded pre-labels for the formerly unstated rows await human review.
<!-- TODO: one sentence of mitigation per item. -->

## References

<!-- Verified by opening each page (2026-10-05 and 2026-10-07 literature checks); full citations TODO.
     Closest prior work, cite first: -->
- Lambros, R. & Wilson, S. (2026). Incident-data robustness analysis of the OWASP Top 10 for LLM
  Applications (2026). arXiv:2608.19266. — pooled corpus-vs-vote test; the hand labels used here.
- Kumar, HN, Birur, Agarwal & Harshangi (2026). The Agent Incident Registry. arXiv:2609.11030. — 487 agent
  incidents, causal role / vector family / attack surface; single curator.
- Mengesha, Owen, Collins, Wong, Mylius, Slattery & McGregor (2026). A pragmatic classification framework
  for AI incident monitoring. arXiv:2604.21412. — AIID + OECD AIM; reporting-propensity biases.
- Abraham et al. (2026). AI incident monitoring through a public health lens. arXiv:2604.19914. — no
  denominators; 296 AIID deepfake incidents.
- Maugeri, Castiglione, Raciti & Bella (2025). AI-related vulnerabilities within CVEs: are we ready yet?
  AISec@CCS 2025, doi:10.1145/3733799.3762969. — 1.57% of CVEs AI-relevant, two thirds conventional bugs.
- Parthasarathy (2026). Coverage and complementarity of three agentic AI risk taxonomies across 131
  real-world incidents. Research Square, doi:10.21203/rs.3.rs-10425736/v1. — 27 of 131 fit no OWASP-ASI entry.
- Grosse, Bieringer, Besold, Biggio & Alahi (2024). When your AI becomes a target. AAAI 38(21),
  doi:10.1609/aaai.v38i21.30347. — 32 incidents, attacker target and goal.
- Li et al. (2025). AIES 2025. — 499 GenAI incidents, harm-centred who/what/how.
<!-- Context and method: -->
- Hayward & Maas (2021). Artificial intelligence and crime: a primer for criminologists. Crime, Media,
  Culture 17(2), doi:10.1177/1741659020917434. · Caldwell, Andrews, Tanay & Griffin (2020). AI-enabled
  future crime. Crime Science 9:14, doi:10.1186/s40163-020-00123-8. — crimes with / against / by AI.
- Schröer, Apruzzese et al. (2025). SoK: On the offensive potential of AI. SaTML 2025, arXiv:2412.18442.
- OECD (2026). Trends in AI incidents and hazards reported by the media. OECD AI Papers,
  doi:10.1787/4f5ff43c-en. — what the media channel sees: synthetic media 14%, scams ~10%.
- Nong, Du, Behravan & Cai (2026). How reliable are NVD CWE labels? arXiv:2608.21977. · Zhang, Massacci &
  Zhang (2026). The cathedral and the bazaar of software vulnerabilities. arXiv:2607.05670. — the
  vulnerability record depends on who labelled it.
- Camporese, Massacci & Gong (2026). LLMs for qualitative data analysis fail on security-specific comments.
  arXiv:2604.10834. — the case against LLM coders; answer it in §7.
- MIT AI Risk Initiative (2026). AI Incident Tracker June 2026 update. — 8 models vs 2 humans on 10
  incidents, κ per taxonomy.
- Walker, Schiff & Schiff (2024). Political Deepfakes Incidents Database. AAAI 38(21),
  doi:10.1609/aaai.v38i21.30349. · Raza (2026). The deepfakes we missed. arXiv:2605.12075.
- Brodt, Feldman, Schneier & Nassi (2026). The promptware kill chain. arXiv:2601.09625. — 21 ON-AI
  incidents staged on a kill chain.
<!-- Already verified on 2026-10-05: -->
Marchal et al. 2024 arXiv · Bieringer et al. 2026 SaTML (arXiv:2412.14855 v5 is the full taxonomy) ·
Paeth et al. 2025 AAAI · Hadan et al. 2025 IJHCI · Shifat et al. 2026 FSE-LLMSC · Harzevili et al. 2023
MSR · Hasan et al. 2026 TOSEM · Li & Gao 2026 DSN · Segal et al. 2026 MSR · Dong et al. 2019 USENIX
Security · Anwar et al. 2022 TDSC · Croft et al. 2023 ICSE · Mu et al. 2018 USENIX Security · Allodi &
Massacci 2014 TISSEC · Apruzzese et al. 2023 SaTML · Pittaras & McGregor 2023 SafeAI · Lee et al. 2024 CHI
· Lin et al. 2024 USENIX Security (Malla) · Shen et al. 2024 CCS · Hamer et al. 2025 arXiv.
