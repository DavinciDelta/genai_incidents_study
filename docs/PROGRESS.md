# Where you look decides what you find: progress so far

*A plain-language summary of the AI-incident study, as of 8 October 2026. Every number about the data comes
from a file in `out/` or `explore/out/`, named in brackets. Facts about the outside paper and the effort
estimates come from `docs/POSITIONING.md`.*

## What this project is about

Companies, researchers and standards bodies increasingly use public databases of "AI incidents" to decide which
AI threats matter most. This project asks a simple question about those databases: **when they record an attack,
what does the record actually tell us about how the attacker operated?** We split attacks into two kinds:

- **Attacks on AI**: someone attacks an AI system, for example tricking a company's AI assistant into leaking
  data, or exploiting a bug in an AI coding tool.
- **Attacks with AI**: someone uses AI as a weapon against people or organisations, for example a deepfake video
  of a politician or a cloned voice used in a scam.

## The data, step by step

**1. The source.** We use an open index called *genai_incidents* (version 2.12.0). It gathers 15,666 records
from many public trackers [Table 1.2], which reach it through three channels:

| Channel | What it is | Share of records |
|---|---|---|
| Vulnerability advisories (CVE/GHSA) | Official reports of software security bugs | 51.5% |
| Harm databases | Trackers of harm caused by AI, mostly built from news stories: the OECD AI Incidents Monitor, the AI Incident Database, AIAAIC (a public register of AI controversies) and AVID (the AI Vulnerability Database, which also holds many bug reports) | 45.4% |
| Research and other | Papers, vendor threat reports, red-team test output and the index's own curated entries | 3.1% |

We pinned the exact version and recorded the file's fingerprint (a sha256 hash). We also checked that the
installed package holds the same 15,666 records [`out/s01_overview.md`, section A], so anyone can rerun the work.

**2. Which records involve an attacker.** Most records describe a software bug with no attack seen, or a harm
with no attacker, such as a biased algorithm. Automatic rules in our script `s02_split.py` read each record's
wording and the attack-type label the index gave it, then sort the record into one of five groups [Table 2.1]:

| Group | Records |
|---|---|
| Attacks on AI | 1,339 |
| Attacks with AI | 1,460 |
| Both (signs of both kinds) | 33 |
| Unclear (an attacker is mentioned, but the rules cannot tell which kind) | 179 |
| No attack found by the rules | 12,655 |

The first three rows, 2,832 records, are the "attack records" used below. For 69.8% of them the index's own
attack-type label decided the group; the wording decided the rest [Table 2.4]. When we reran the rules on
wording alone, the result held: advisories stayed 98.8% attacks on AI and harm databases 91.4% attacks with AI
[`explore/out/feas_A_validation.out.txt`].

**3. How each attack happened.** For each of the 1,339 attacks on AI and 1,460 attacks with AI we recorded two
things [Tables 4.1, 4.2, 4.4, 4.5]:

- **Attacks on AI**: how the attacker got in (the entry point) and which part of the AI system was hit (the
  target).
- **Attacks with AI**: what the AI produced for the attacker (the medium) and what the attacker wanted (the
  objective).

The first labels came from keyword rules, or from the index's attack-type label where no keyword matched. Labels
neither could set were left "unstated". This is the *pre* dataset (`out/dataset_pre.csv`).

**4. A full review of every label.** Every label was then re-checked. That is 5,598 labels: two for each of the
1,339 attacks on AI and 1,460 attacks with AI. Two reviewers worked separately and saw each record's text and the
index's own labels, but not how our label had been set. Before any tie-breaking they chose the same label 95.8% of
the time [Table 4.0]; where they differed, an adjudicator decided. **All of them were AI models (Claude Fable 5.1
and Opus 5.5), so no human has checked these labels yet.** The reviewed labels are the *post* dataset
(`out/dataset_post.csv`). A separate file holds the 1,416 of these records dated 2026.

**5. Two outside references.** To check our results against things we did not build, we compare them with:

- **The OWASP Top 10 for LLM Applications.** OWASP is a non-profit software-security community. LLMs (large
  language models) are the technology behind chatbots such as ChatGPT. The list ranks the biggest security risks
  in software built on them, from a community vote (about 29 respondents ranked 20 candidate risks).
- **1,200 records hand-labelled by one person** for a separate project that tested that ranking (Lambros &
  Wilson, 2026). That project used an earlier copy of the same index.

## What we found

**1. Where an incident is reported is strongly tied to what kind of attack it looks like.** Of the attack records
from vulnerability advisories, 88.0% are attacks on AI. Of those from harm databases, 78.2% are attacks with AI
[Table 2.2]. This matters because an analysis that mixes the two channels ends up describing its sources rather
than the attackers. The tie holds:

- **in each tracker taken on its own,** with two exceptions that support the point. AVID, filed as a harm
  database but made mostly of bug reports, behaves like the advisories. Vendor threat reports change sides when
  the index's attack-type label is removed: 80% attacks on AI with it, 7% without
  [`explore/out/feas_C_trackers.out.txt`].
- **under 64 combinations of counting choices** (finding 6). Advisories stay 86–100% attacks on AI and harm
  databases 78–96% attacks with AI [`explore/out/feas_B_measurement.out.txt`].
- **in the outside project's hand labels,** though that project did not point it out. The OWASP list covers
  attacks on AI applications, so a record that fits none of its categories is more likely to be an attack with
  AI. On a first read, before seeing any computer suggestions, that project's labeller found no OWASP category for
  63% of harm-database records but for only 18% of advisory records. Those records were a sample chosen by quota
  [`explore/out/feas_D_goldset_channel.out.txt`]. These labels cannot yet test the attack-with-AI side directly.

**2. The largest group of attacks on AI is ordinary software bugs in AI tools.** A conventional software flaw is
the most common way in: 26.4% of all attacks on AI, and 51.7% of those reported in advisories [Table 4.1]. Next
come prompt attacks, where the attacker types instructions that trick the AI (15.1%), and instructions hidden in
web pages or documents the AI later reads (12.1%). The most common target is an AI agent, coding assistant or
tool connector. That is 45.2% overall, but 75.8% of advisory records against 8.6% of harm-database records
[Table 4.2]. Two in five attack-on-AI records (548) are bug reports with no attack actually observed [Table 2.5].

**3. Attacks with AI are mostly deepfakes; the largest aims are money and politics.**

- **The medium:** video, image and voice each account for about 15% (14.6–16.5%), and another 25.6% say
  "deepfake" without naming the medium [Table 4.4].
- **The aim:** fraud or extortion in 30.1% of records and political influence in 19.0%, together about half
  [Table 4.5].
- **AI-written code:** AI-generated or AI-assisted malware or tooling appears in 8 records (0.5%) [Table 4.4].
  These records are mostly news stories, which rarely describe malware.

**4. The index's own labels come from keyword matching, and some are plainly wrong.** When a source does not
supply an attack type, the index checks the text against 41 word patterns in a fixed order and uses the first
that matches. For example, a record containing "impersonate" or "impersonation" is labelled a deepfake
[`out/s05_techniques.md`, Limitations]. As a result:

- **80 software advisories** sit among the attacks with AI because the index labelled them "deepfake" (43) or
  "phishing" (34) [Table 2.5].
- **111 news stories** carry software-exploit labels such as "rce" [Table 2.5].

Our own first-round labels were also unreliable. The review replaced 38.4% of them for attacks on AI and 30.3% for
attacks with AI [`out/s06_compare.md`, Tables 6.1–6.2]. It also found that 9.6% of the attacks on AI and 11.8%
of the attacks with AI describe no attacker at all, such as a lawsuit or a policy report [Tables 4.1, 4.4]. These
records stay in the data, marked, rather than being deleted.

**5. Compared with the expert ranking, the data mostly shows where the records come from.**

- **Attacks on AI:** "Improper Output Handling" means an AI's answer passed to other software without checks.
  It ranks 11 places higher in the index's labels than in the vote of 20 candidate risks. The index attaches it by
  a fixed rule to injection-type software bugs, which 238 of its 548 records carry [Table 5.1].
- **Attacks with AI:** the index's "Misinformation" label sits on 83.8% of these records [Table 5.2]. 98.7% of
  that label comes from harm databases, so its rank follows the source, not the attacks [Table 5.1].
- **2026:** records dated 2026 sit no closer to the vote than all years together [Tables 5.3a–b]. Rank agreement
  is +0.17 in both for attacks on AI and −0.95 in both for attacks with AI, on only 6 and 4 categories.
- **The outside hand labels:** where they and the index use the same category, and it holds 10 or more records,
  they mostly agree (from 20 of 21 down to 13 of 22). In that project's sample, 14% of attacks on AI and 43% of
  attacks with AI fit none of the 20 candidate risks. A further 27% and 26% fit only a newly proposed one
  [Tables 5.4a–b].

**6. Any single "overall" percentage mostly reflects the mix of sources.** Between 7.6% and 57.5% of all attack
records count as attacks on AI, depending on three reasonable choices [`explore/out/feas_B_measurement.out.txt`]:

- whether an incident reported by several trackers counts once or once per tracker;
- whether lab demonstrations with no real victim, and bug reports with no attack seen, count as attacks;
- which set of labels is used.

Separately, giving the three channels equal weight moves the published 47.8% to 69.0%. The direction within each
channel never changes (finding 1).

## What we cannot conclude yet

- **How common attacks are in the real world.** Only 8.5% of advisory records and 24.6% of harm-database records
  were placed by our rules as involving an attacker [Table 2.2]. Attacks that are never disclosed, settled
  privately or seen only by security vendors are absent [`out/s05_techniques.md`, Limitations].
- **Trends over time.** A record's year is often the year a tracker added it, not when the attack happened.
- **That the labels are right.** AI models reviewed them; a human check of a sample is still owed.
- **That the pattern holds outside this one index.** Every tracker's records were collected and processed by the
  same index software, so a quirk in that processing could create the same pattern everywhere. Next step 5 tests
  this.

## What comes next

Effort estimates are from `docs/POSITIONING.md`.

1. **Make the extra checks behind findings 1 and 6 part of the main, rerunnable analysis,** so the paper can cite
   them (about 3 hours).
2. **Add "attack on AI or with AI" to the outside hand labels** where the OWASP list gave no category, to finish
   the independent check (about 10 hours).
3. **Have a person check the records the AI review set aside or moved between groups.** This covers about 470
   records: those with no attacker, the misplaced advisories, and those whose attacker used AI as a tool (about 8
   hours).
4. **Have two people each sort about 450 records into attack on AI, attack with AI or neither,** without seeing
   the index's labels, and compare their answers (about 50 hours).
5. **Build a small sample from outside the index.** Read advisories, harm databases, vendor threat reports and
   court filings directly (about 75 hours).

## Words used here

- **Attack on AI / attack with AI:** the AI system is the target / the AI is the attacker's tool.
- **Channel:** where a record was first reported: vulnerability advisory, harm database, or research and other.
- **CVE / GHSA:** the standard public IDs for software vulnerabilities (MITRE's CVE list and GitHub's advisories).
- **Harm database:** a tracker of harm caused by AI, mostly compiled from news reports.
- **OWASP Top 10 for LLM Applications:** an expert-voted ranking of security risks in software built on large
  language models.
- **Keyword rule:** a label set automatically by matching words in the text, not by someone reading it.
- **Pre / post:** the labels before and after the full review.
