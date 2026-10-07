# genai_incidents attacker-methodology study — project context

Purpose: a replicable preliminary analysis and paper draft on **how adversaries operate** in real-world
AI incidents (attacker-centred, modelled on Li et al. AIES 2025 which is harm-centred). Full history and
the reasoning behind every decision: `docs/CONVERSATION_LOG.md` — read it before proposing a new
categorisation scheme; one has already been tried and discarded.

Pipeline (run in order; `make all`): `fetch_data.py` → `s02_split.py` → `s01_overview.py` (reads `out/split.json`) →
`s03_figures.py` → `s04_methodology.py` (writes `out/methodology.json`) → `s05_techniques.py`. Shared code in `common.py`. Outputs in `out/`. Inputs pinned in
`external/PINS.json` (pip `genai-incidents` version, full-JSON tag + sha256, rank-validation commit,
corpus build-script sha256).

Rules of the house
- Stdlib + `genai-incidents` only. No plotting libraries, no model calls, no hand-edited numbers.
- `coded/relabels.json` holds labels for the records step 4's rules left `unstated`, made in-session by two
  independent Claude coders plus an adjudicator (2026-10-06), not by the pipeline. `coded/review.json` holds
  the 2026-10-07 audit of the rule-assigned labels (stratified sample, two independent Claude reviewers plus
  an adjudicator) and the corrections s04 applies on top of the rules. Scripts read both; `make` cannot
  regenerate them; a human review is still owed before any of their values is cited as a finding.
- Every figure in `draft.md` must trace to a file in `out/`; regenerate before quoting.
- The corpus is a sampling frame, not coding material. Corpus labels (OWASP, ATLAS, attack_vector)
  stratify samples; they never populate a hand-coded field. Step 4's rule dimensions read the text first
  and fall back on the attack-vector label only where it maps to exactly one value (Table 4.0), with the
  source shown under every value (decision of 2026-10-06).
- ON-AI vs WITH-AI are separate populations. Report within disclosure channel as well as pooled.
- incident-rank-validation artifacts are read, never run. Use: out-of-scope exclusion, seed rows,
  expectation-setting. Never a cross-entry prevalence claim.
- Show "unstated"/"unresolved" shares; never force a record into a category.
- Deliverables land on disk and are committed before being discussed.
