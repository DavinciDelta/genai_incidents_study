# Conversation log — how this study took shape

Chronological record of the working session (2026-10-01 → 2026-10-05) that produced this repository.
Each entry: what was asked → what was done → what was decided. Discarded approaches are kept here on
purpose; they explain why the current design looks the way it does.

## 2026-10-01

**Ask: difference between genai_incidents, rocklambros/incident-rank-validation and the OWASP Top 10;
ways to subdivide incidents for empirical study.**
Done: read both repos. Decided framing: OWASP = the claim (expert-voted list), genai_incidents = the
evidence (13k-row heuristic index), incident-rank-validation = the test (Bayesian measurement-error
engine; weighted κ 0.20, LLM04/08/10 frame-blind). Proposed ten orthogonal facets instead of a deeper
OWASP tree; recommended four first: record type, AI system type + agency, AI-native vs incidental, ATLAS-
granularity mechanism.

**Ask: combine the rank-validation repo here; empirical paper ideas incl. "human error vs LLM-related"
cause; benchmark of defences from incidents with PoCs; validity.**
Done: added rank-validation as a git submodule (later removed, see 2026-10-05). Wrote
`benchmark-and-causal-study-design.md`. Key finding that reframed the benchmark idea: of ~2,400
reproducible PoC rows, the large majority are conventional appsec bugs in AI tooling (XSS, authz, RCE),
not LLM-defence tests; genuine model-behaviour attacks with a shipped artifact ≈ 93. Decided: two
benchmarks must not be merged; cause classification is three facets (locus, LLM failure mode, control
gap), not a binary. A first-run locus crosswalk: human-engineering 53%, undetermined 23%, AI-as-enabler
12%, interaction 4%, llm-intrinsic 3%. Noted CWE-1427 appears on zero rows — NVD codes prompt-injection
CVEs as code-execution CWEs, biasing any human-vs-model split toward "human".

## 2026-10-02

**Ask: what does the rank-validation engine rank by, and what knobs change the ranking?**
Done: it ranks by recall/precision-corrected incident count (λ × stratum size), not severity. Knobs:
witness (vote / data / 0.75–0.25 blend), blend scale, frame-blind handling, rollup scope, fold rule,
likelihood (NB / Poisson / Dirichlet-Multinomial / non-Bayesian twin), κ denominator (0.203 over 20 vs
~0.12 over 17 measurable), strata/time windows, classifier (RARR: ρ 0.918–0.971, order robust).

**Ask: how reliable is the data rank; use rank-validation for a per-entry deep dive instead; one simple
script.**
Done: `deepdive.py` joining rank-validation artifacts to the corpus via `resolve_id()`. Verdict: data
rank is weak as prevalence, usable only ordinally within the corpus (17/20 entries' rank CIs span ≥10
places; ai-harm stratum uncalibrated; Misinformation's rank 2 rests on that stratum). Per-entry
composition is the more valid use. Workplan: freeze frame → gold seeds per entry → sub-category rubric →
dual coding → report composition with bootstrap CIs.

**Ask: draft.md on data-rank unreliability + full vote/data table; categorise incidents by ATLAS
Initial Access ("failure category"); stats script.**
Done, then **scrapped on 2026-10-05 at the user's request**: the Initial-Access failure categories
produced a 52% "exploit-public-facing-app" bucket and 20% undetermined (38% of landmark), keyword rules
were brittle, one-label-per-incident flattened chains. Files deleted via git revert.

## 2026-10-05

**Ask: scrap the failure-category approach; instead break down `attack_vector = other`, using
rank-validation.**
Done: profiled `other` (≈4k rows: half CVE records with unmapped CWEs, half OECD/AIID news). Found the
rank-validation stage-2 rationales (2,079 of the `other` rows) and 408 gold adjudications (194 out of
scope) already provide a label + one-sentence reason. Proposed: split by population, seed sub-categories
from gold rows, extend by rules over *rationale* text, hold out gold as the check.

**Ask: peer-reviewed papers doing something similar.**
Done: Li et al. AIES 2025 (closest); Pittaras & McGregor SafeAI 2023 (failure-cause taxonomy); Lee et
al. CHI 2024 (κ protocol); SBSeg 2025 and SoK 2502.12497 (CVE root causes in LLM supply chain);
Lambros 2026 preprint (the rank-validation paper, self-marked non-publishable); Hopkins & King 2010
AJPS for the quantification method. No peer-reviewed expert-rank-vs-incident test exists.

**Ask: adopt the AIES design but code attacker methodology, not harm. Approach + resources.**
Done: measured that the corpus cannot be coding material (median description 268–281 chars; ATLAS
labels are heuristic co-occurrence, not observed chains; 111 threat reports; ~100 rows name an actor).
Decided: corpus = sampling frame only, code from primary references; two populations analysed
separately — **ON-AI** (AI is target/vector) vs **WITH-AI** (AI is the attacker's instrument); 12-field
coding frame with ATLAS tactic sequence as spine; ~500-incident sample; resources to add in priority:
full ATLAS case studies, vendor threat-intel reports (OpenAI/Anthropic/Google/Microsoft), agent-
exploitation write-ups, KEV/honeypot evidence, court/IC3 records, Malla (USENIX Sec 2024).

**Ask: do the split; Figure 1; abstract + intro; explain all statistics; cite MIT tracker and
priorities.**
Done: `split_on_with.py`, `fig_on_with.py`, `introduction.md`. Pre-split on v2.11.0: ON-AI 1,045 /
WITH-AI 1,451 / BOTH 31 / unresolved 178. **Central finding: population tracks disclosure channel**
(CVE 85% ON, harm-db 81% WITH, research 97% ON) — a pooled ratio is a ratio of channels.

**Ask: explain unresolved, Panel B, and the edge case; then break down methodology of both.**
Done: unresolved = adversary word ("fraud"/"scam"/"campaign") fired with no role signal → hand review.
Panel B = selection-bias diagnostic. Edge case (user jailbreaks model, output used downstream) = BOTH;
current rule routes `jailbreak` to ON-AI and is flagged as too coarse. Methodology breakdown: ON-AI is an
agent-exploitation story (48% agent/copilot/MCP targets; 45% have a CVE/CWE vs 32% model-behaviour
only; 23% demonstrated); WITH-AI is a deepfake-fraud story (81% deepfake; image 19% / voice 17%; fraud
33%); LLM-assisted intrusion nearly invisible in public databases.

**Ask: add a corpus overview + premise section; then a preliminary-analysis section from rank-
validation.**
Done: both added to introduction.md. New result: rank-validation gold labels land on disjoint entry sets
for the two populations (ON-AI → technical entries; WITH-AI → Misinformation + Weaponized LLM Abuse
only; 43% of WITH-AI gold rows out of scope) — the split is recoverable by an independent coder.

**Ask: delete everything and restart from `pip install genai-incidents`; step-wise replicable scripts;
concise draft with room to edit.**
Done: this repository. Research branch and submodule removed from the `genai_incidents` clone (clone
itself kept — it is the user's foreman board checkout; `rm -rf` offered). New layout: `fetch_data.py`
(pins), `s01_overview.py` (README snippet + profile + rank-validation view, no dissection),
`s02_split.py`, `s03_figures.py`, `s04_methodology.py`, `common.py`, `draft.md`. Corpus moved to
v2.12.0 (15,666 rows; frame 2,832; ON 1,339 / WITH 1,460); all findings reproduce.

## 2026-10-05 → 2026-10-06 (second session)

**Ask: clean up the generated outputs; describe every table; explain every % column that misses 100.**
Done: shared reading note and glossary printed once (s01 section 0); numbered tables with titles that
state the finding; pooled remainder rows; descriptions of at most two sentences. Found and fixed: the
Source table scattered AIAAIC ids (no hyphen) into singletons; `join_rv` let a duplicate snapshot id
overwrite a hand label (1,123 hand-labelled records join, ON-AI 161); the hand-labelled set is a quota
over three LLM pre-labellers' agreement (all 431 disagreement rows, up to 60 per consensus entry), not
the 40/100 sampler; nine step-4 keyword rules matched substrings ('invest' in 'investigation', …; 99
records moved); the corpus and rank-validation number the OWASP entries differently (Table 1.0).

**Ask: tables after Hamer et al. (attack techniques → mitigations → gaps).** Built as step 5 on the
corpus's ATLAS labels, then found that 90.7% of those labels are produced from the OWASP codes by a
fixed lookup in the corpus build script (Misinformation → Publish Poisoned Models among them).
**Scrapped on 2026-10-06 at the user's request**: the mitigation half, the ATLAS fetch and pins. Step 5
now compares the corpus's OWASP categories with the community vote per population and carries the hand
labels as one limitation table (hand-label rank only within the sample).

**Ask: step 4 should classify from the corpus label when no keyword matches, and show its source.**
Done 2026-10-06: text rules first, attack-vector label second where it maps to exactly one value
(Table 4.0), `unstated` otherwise; '↳ from the text / from the corpus label' under every value; two
label-only values ('prompt injection, carrier not stated', 'deepfake, medium not stated'). Unstated
fell from 48.8% to 31.2% (entry point) and from 48.8% to 7.2% (AI medium). `out/methodology.json`
carries a `_source` per dimension. Pipeline order is now s02 before s01 (section C reads split.json).

## 2026-10-07 (third session, continued)

**Ask: vet `dataset_pre.csv` against GitHub; check every label; use the model where needed to confirm
labels; reflect any change in the post csv and explain; add the incompleteness, disclosure and pooling
limitations; a 2026-only csv to see whether the recent record sits closer to the vote.**
Done. Integrity: the pinned full JSON re-downloaded from GitHub matches the sha256 in `external/PINS.json`
and the pip package; all 2,799 rows of `dataset_pre.csv` match corpus fields, the split and the rule
outputs. Labels: a stratified audit of the rule-assigned labels, up to 20 records per (dimension, value,
assignment step), 620 labels in 36 strata, each read by two independent Claude (claude-fable-5-1)
reviewers given title, description, affected field and corpus labels; a third adjudicated the 28 splits.
Mythos 5.1 is not callable from this environment; Fable 5.1 shares its underlying model. Result: 365
correct, 249 corrected, 6 kept with a dissent (`coded/review.json`; s04 applies the corrections with
how = "corrected by review", Table 4.0 column, Table 4.0b per stratum, Table 4.0c population-weighted
residual error: entry point 47% wrong before / 39% still wrong after, target 36 / 31, AI medium 36 / 32,
objective 15 / 12). Worst rules: "stolen or leaked credential" text rule 3 of 20 (fires on "credentials",
"token", "exposed" in SSRF/auth-bypass CVEs), WITH-AI "none: conventional exploit" label group 0 of 20
(OECD "AI-driven attack" commentary and ChatGPT-misuse stories), "defamation / impersonation" 4 of 20
("deepfake"/"phishing" in CVE text), "consumer chatbot" target 5 of 20 (named models, agents, no-attacker
stories). Decision: corrections apply to the sampled records only; no rule was re-tuned on the audited
sample, so Table 4.0b still measures the rules; each distribution table now names the values whose
sampled labels were mostly wrong. Bug found by the diff: corrected records lost their original source in
`dataset_pre.csv`; fixed (pre keeps the rule source). Limitations added to s05 and draft §8: the public
record is a small self-selected sample (8.5% of CVE/GHSA and 24.6% of harm-db records involve an
adversary; `exploited_in_wild` on 14 of 15,666; IC3 AI-related complaints 2.2% of its total; INTAiC);
the index pools trackers with different units. 2026-only cut (`out/dataset_post_2026.csv`, 730 ON-AI /
686 WITH-AI; Table 5.4): the recent record sits further from the vote, not closer (ON-AI ρ +0.29 →
+0.06, WITH-AI −0.57 → −0.94).

**Ask: the most accurate method: have an agent go through every incident in pre to make sure post is
classified properly; report the difference.** Done 2026-10-07. Every label not in the 620-label sample
(4,978 labels, 2,748 records, 55 batches of 50, both dimensions per record) was read by two independent
reviewers blind to the assignment step; splits went to an adjudicator per four batches; then 21 records
whose two labels disagreed on "no attacker" were settled by one adjudicator (17 no adversary, 4 one).
Models: the Fable usage limit was reached at batch 45; 4,331 second-pass labels had two Fable 5.1
reviewers, 187 one Fable and one Opus 5.5, 460 two Opus 5.5; second-pass and consistency adjudication by
Opus 5.5; existing Fable files were hashed before the switch and not overwritten. Result
(`coded/review.json`, Tables 4.0b–4.0d): 3,698 of 5,598 labels confirmed, 1,847 corrected, 53 kept with a
dissent; reviewers settled 95.8% between them. Kept as assigned: text rule 69.1%, corpus-label fallback
53.6%, label-group rule 39.4%, coded labels 91.3%. Against the committed post (sample audit): entry point
39.1% of labels changed, target 27.3%, AI medium 35.8%, objective 12.9%. Largest moves: direct prompt
24.2% to 15.1%; consumer chatbot target 18.5% to 8.7% and "a model itself" 3.0% to 11.4% (a codebook
boundary: research on named models); tracker-stub target 10.3% to 1.9%; "deepfake, medium not stated"
41.6% to 25.6% and video 8.8% to 16.5%; no attacker rose to 9.6% (ON-AI) and 11.8% (WITH-AI). Decisions:
the INC-07208 / INC-07291 objective follows the record text (impersonation), against the earlier coders'
outside-knowledge note (art installation, awareness PSA); benchmark-run records without an attack are
"no attacker" on both dimensions. `dataset_post.csv` gains `<dim>_review` (confirmed / corrected / kept
with dissent). The population split leaks: no-attacker, WITH-AI-in-ON-AI ("other") and CVE-in-WITH-AI
values are kept visible, not removed.

**Ask: an s06 comparing pre vs post, with examples of changed incidents and why, overall and 2026 only.**
Done 2026-10-07: `s06_compare.py` → `out/s06_compare.md`. Reads the pre and post datasets, the words each
text rule matched (s04 now stores `<dim>_match` in `out/methodology.json`) and the coder and reviewer notes;
no model calls. Tables 6.1 (unchanged / filled / replaced per dimension, all years vs 2026), 6.2 (by
channel), 6.3–6.6 (value shares pre vs post, both cuts), 6.7 (largest replacements and what fired the
rule), 6.8 (values that moved 3+ points the same way in both cuts), and 12 worked examples. The examples are
a fixed id list chosen to span dimensions, channels and years; each was checked by two further independent
reviewers (one told to refute the change), and all 12 held. Result: the review replaced 34.0% of rule
values (2026: 33.9%); 51.1% of labels changed with the filled ones (2026: 53.1%); within channel the 2026
rate is within 5.4 points of all years, so the recent intake is not cleaner.

## 2026-10-08

**Ask: confirm whether the corpus labels by word matching; simplify Table 5.4 with % and split ON-AI /
WITH-AI; make the hand-label limitation table readable and split it; s04 and s05 report only the
reviewed data; only s06 compares pre, current and 2026, with fewer tables.** Done. Corpus: yes —
`classify_attack_vector` in the build script takes the first of 41 regexes over title + description when
a source gives no vector (e.g. 'impersonat' → deepfake, which is why CVE texts carried harm labels), OWASP
codes are seeded from the vector for records without any, ATLAS from OWASP by lookup; now a limitation
bullet in s05. Decision: s05 runs on the populations cleaned by the review — records whose reviewed labels
say no adversary (129 ON-AI, 173 WITH-AI) and WITH-AI CVE records with no AI medium (81) are left out
(1,210 ON-AI, 1,206 WITH-AI remain); step 4 still shows them as values. Effects: ON-AI rank agreement
with the vote +0.21 (2026: +0.14, still further); WITH-AI 2026 has too few categories with 30+ records to
compare; hand-labelled sample becomes 135 ON-AI / 141 WITH-AI, and Supply Chain (18) overtakes Data and
Model Poisoning (17) as the person's most-used ON-AI label. s04: intro rewritten around the reviewed
labels; tables of assignment steps, per-step precision and rule-to-final flows removed; one review table
(agreement). s05: Tables 5.3a–b (hand labels, per population, sorted by use) and 5.4a–b (shares all years
vs 2026, per population). s06: two tables (pre / current / change / 2026 current, per population, with
change rates per dimension), eight worked examples grouped by population with flow counts, four summary
bullets; the by-channel, largest-flow and shared-shift tables removed.
Two rounds of four independent checks (pre talk in s04/s05, readability, draft-to-out tracing,
cross-file consistency) then fixed: **the 2026 'Spearman' was a Pearson correlation on unadjusted ranks
over different category sets per cut** — now true Spearman (average ranks within the set) on the categories
with 30+ records in both cuts: ON-AI +0.05 all years and +0.05 in 2026, i.e. no closer to the vote (the
earlier 'further from the vote', +0.29 → +0.06, was an artefact); WITH-AI has two such categories, too few.
Tables renumbered in file order (2026: 5.3a–b; hand labels: 5.4a–b); ‡ shown only where the marker's channel
has records in the population; hand-label titles lead with proposed-category and no-fit shares; change
columns computed from printed shares; dataset_post column glossary moved to the README; a dozen draft
figures re-cited or rephrased so each traces to `out/`.

## Standing decisions

1. The corpus is a sampling frame and pointer to primary sources; **no corpus label enters a coded field.**
2. ON-AI and WITH-AI are analysed separately; every comparison reported within channel as well as pooled.
3. Rank-validation artifacts are read, never re-run; used only to exclude out-of-scope rows, seed the
   sample, and set expectations. No cross-entry prevalence claim is made.
4. Every proportion carries a bootstrap CI; "unstated" is always shown — it is the manual-coding workload.
5. Scripts are stdlib + `genai-incidents` only; every number in `draft.md` traces to a file in `out/`.
6. Discarded: ATLAS Initial-Access "failure category" scheme (2026-10-02, reverted 2026-10-05).
