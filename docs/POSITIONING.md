# How this study relates to Lambros & Wilson (arXiv:2608.19266), and how to frame it

Written 2026-10-08. Paper facts come from the paper (v1, 18 Aug 2026) and the pinned incident-rank-validation
artifacts (`external/incident-rank-validation`, commit f7a92a1). Every number about our data comes from a script in
`explore/` (outputs in `explore/out/`), which reads the repository and is not part of `make all` yet.

## The short version

- **Same index, different question.** The paper ranks the 20 OWASP LLM risk categories by incident counts and
  compares that ranking with the OWASP expert vote. It uses an earlier, smaller snapshot of the same genai_incidents
  index we use. It never asks how attackers operate, never separates attacks on AI from attacks with AI, and never
  treats where a record was reported as a variable.
- **Our angle is the one it misses.** Where an incident is reported largely decides what kind of attack it looks
  like, and the index's labels are keyword matches. Its own hand labels show this channel effect, but it does not
  report it.
- **Your three claims.** The data can already show most of claims B and C, and the CVE half of claim A. The rest
  needs about 45–75 hours of human coding, listed at the end.

## The paper in brief

**Question.** Does the OWASP Top 10 for LLM Applications (2026), ranked by an expert vote of about 29 people,
agree with the record of real incidents, and does the answer depend on which classifier labels the record?

**Data.** A snapshot of genai_incidents v2.0.0 taken on 20 May 2026: 7,714 records, of which 6,639 were labelled.
We use v2.12.0 from 4 Oct 2026: 15,666 records. The paper does not name the index; its artifacts do
(`provenance.json`: source_repo "genai_incidents"). The paper says its "security" stratum comes from CVE, GHSA and
OSV, but by source id 68.6% of that stratum is harm-database news. Its 46-incident OWASP Agentic Security
Initiative set is used only as corroboration.

**How they collected it.** They did no collection of their own. They took the index as published. The index
maintainer builds it from a keyword crawl of CVE/GHSA/OSV plus ingested harm databases (OECD, AIID, AIAAIC, AVID),
and the index's own merge script does the deduplication.

**How they processed it.**
1. Dropped the one record dated after the snapshot. Kept the corpus's OWASP codes as metadata but did not use them.
2. A keyword pass labelled 667 records; 617 of those match the corpus's own OWASP code.
3. One model (Llama-3.3-70B) labelled the rest and set aside 1,074 as out of scope. This left 6,639 records.
4. Three models (Qwen3-235B, Llama-3.1-405B, DeepSeek-V3) labelled the 5,972 in-scope records. Their consensus,
   or the single model where there was none, became the final label.
5. **Gold set.** One person (the author) hand-labelled 1,200 records chosen by a quota on model agreement, not at
   random. For each record they read only the title and description, gave a blind first label, then saw the model
   votes and gave a final label. The blind label never saw the corpus's attack-vector or OWASP codes.
6. A Bayesian measurement-error model corrected the counts for precision and recall per category. The result was
   compared with the vote (weighted κ 0.20, interval −0.16 to 0.57), then blended 75% vote and 25% data for the
   published tiers.

**What it found.** The vote and the data agree weakly. Prompt Injection is first by vote but about twelfth by
incidents. Misinformation and Weaponized LLM Abuse are inflated by harm-database deepfake stories. More than a third
of labelled records fall outside the list.

## Where our study stands out

| | Lambros & Wilson | This study |
|---|---|---|
| Unit of analysis | 20 OWASP risk categories | Incidents: how the adversary operated (entry point, target, AI medium, objective) |
| Attacks on AI vs attacks with AI | Not separated | The organising split (ON-AI vs WITH-AI) |
| Where a record was reported | Not a variable | Central: CVE/GHSA advisories vs harm databases vs research |
| The index's own labels | Ignored as "non-authoritative" | Measured: keyword rules, then a full review that replaced 34% of first values |
| Records that fit no category | 1,074 dropped before counting; out-of-scope consensus forced into a category | Kept and shown as their own values |
| Counting choices (merging, demonstrations, weights) | Not examined | Examined (claim B below) |

Their gold set already contains our main effect, unreported. The person's blind first read said "out of scope" for
63% of harm-database rows against 18% of CVE/GHSA rows (`explore/out/feas_D_goldset_channel.out.txt`). We can use
that as independent support, because the blind label never saw the corpus's codes.

## Can the data show your three claims?

| Claim | Status now | What we can already show | What is missing |
|---|---|---|---|
| **A. The pattern holds when people label from the text alone** | Partly | CVE half: of the 199 hand-labelled CVE/GHSA records the person put on an "attack on AI" or "attack with AI" side, all 199 are on the "attack on AI" side. Our split agrees with the person's side at κ 0.81 on 184 records (0.66 on blind first reads). | The OWASP list has one "attack with AI" category, so most harm-database records land in "no entry fits" and the harm-database half cannot be tested with these labels. One coder, a quota sample. Our own reviewers were AI models and saw the corpus labels. |
| **B. Counting choices change the conclusion** | Mostly | Across 64 combinations of labels, counting unit, and record types (including real-world incidents only), CVE/GHSA is always mostly attacks on AI and harm databases always mostly attacks with AI. But the overall share of attacks on AI swings from 7.6% to 57.5% and is above half in only 7 of the 64. Weighting the three channels equally moves it from 47.8% to 69.0%. Dropping the person's "no entry fits" rows pushes the hand-labelled share of attacks on AI from 48.1% to 58.0%. | "Human correction" is so far an AI-model review. Merging the same event across trackers (one deepfake reported by OECD, AIID and AIAAIC) needs hand clustering. |
| **C. The pattern holds beyond one index** | Partly | It holds tracker by tracker inside the index: CVE 86.5% attacks on AI, GHSA 94.4%, OECD 22.7%, AIID 6.8%, AIAAIC 10.2%. Two exceptions show what drives it. AVID is a harm database but 99.1% attacks on AI, because most of its records are vulnerability reports. Vendor threat reports change sides depending on the inherited attack-vector label. | Every tracker passed through the same build script. There is no sample assembled outside the index. |

Sources: `explore/out/feas_A_validation.out.txt`, `feas_B_measurement.out.txt`, `feas_C_trackers.out.txt`.

**The result in one line.** Within each channel, the pattern survives every choice we tried. The overall,
all-channels figure does not survive, so any single pooled percentage mostly reports the mix of sources.

## A simpler framing

**Recommended title: "Where you look decides what you find"**
*How the source of a report, what one record counts and automatic labels shape what AI incident data says about
attackers.*

**Pitch.** Studies of AI attacks often lean on public indexes that mix software bug reports with news-based harm
databases. The source largely decides the story. Attacker records from bug reports are 88% attacks on AI systems.
Those from harm databases are 78% attacks carried out with AI, mostly deepfakes. The index's labels come from word
matching, and a careful re-read changed about a third of them. Rankings built on such data partly measure these
choices, not the attacks.

**The three claims in plain words.**
1. **Independent check.** People who read the original reports, without the database's tags, still find bug
   reports to be mostly attacks on AI and harm databases mostly attacks with AI.
2. **Choices matter.** The headline numbers move a lot depending on reasonable choices: counting one event once,
   correcting the automatic labels, keeping lab demonstrations apart from real attacks, and how much weight each
   source gets.
3. **Not one database's quirk.** The same pattern appears in each source database on its own and in a fresh sample
   built from original reports.

Other options considered: "Two kinds of AI attack, reported in two different places"; "Same data, different
answers"; "Is it the attacks, or the database?".

## What changed in the analysis today

Records that could not be placed stay in the data. Step 5 now counts every ON-AI (1,339) and WITH-AI (1,460) record.
The 129 and 254 records the review could not place as attacks are shown per category, not removed. The hand-label
tables keep every "no category fits" record (23 ON-AI, 74 WITH-AI). The draft's coding plan no longer excludes
"no entry fits" rows. Claim B above shows why this matters: dropping them would shift the result toward attacks on AI.

## Next steps, in order of value per hour

1. **Turn `explore/` into a pipeline step (s07), about 3 hours.** This puts the claim B grid and the claim C tracker
   table into `out/` so the draft can cite them.
2. **Add a side to the existing hand labels, about 10 hours.** One person marks attack on AI / attack with AI /
   neither for the 441 "no entry fits" and 114 Misinformation hand-labelled records (555). That completes the
   harm-database half of claim A on the existing sample.
3. **Human check of the records the AI review moved, about 8 hours.** About 470 records: no attacker, misplaced
   CVEs, and records whose attacker used AI as a tool.
4. **Blind human coding for claim A, about 50 hours.** About 450 records, stratified by channel, coded by two
   people who cannot see the corpus labels, with κ reported.
5. **Event clustering for claim B, about 10 hours.** 300 harm-database records, grouping reports of the same event.
6. **An outside sample for claim C, about 75 hours.** About 600 adversary records taken directly from NVD/GHSA, the
   harm databases, vendor threat reports, court filings and FBI IC3 notices, double-coded on 150.
