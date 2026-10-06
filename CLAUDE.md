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
- Every figure in `draft.md` must trace to a file in `out/`; regenerate before quoting.
- The corpus is a sampling frame, not coding material. Corpus labels (OWASP, ATLAS, attack_vector)
  stratify samples; they never populate a coded field.
- ON-AI vs WITH-AI are separate populations. Report within disclosure channel as well as pooled.
- incident-rank-validation artifacts are read, never run. Use: out-of-scope exclusion, seed rows,
  expectation-setting. Never a cross-entry prevalence claim.
- Show "unstated"/"unresolved" shares; never force a record into a category.
- Deliverables land on disk and are committed before being discussed.
