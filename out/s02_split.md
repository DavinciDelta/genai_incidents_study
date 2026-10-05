# Step 2 — ON-AI vs WITH-AI split


**Population (all records)** (n = 15,666)

| value | n | % |
|---|---|---|
| NONE | 12,655 | 80.8 |
| WITH-AI | 1,460 | 9.3 |
| ON-AI | 1,339 | 8.5 |
| UNRESOLVED | 179 | 1.1 |
| BOTH | 33 | 0.2 |

**Population within the adversary frame** (n = 2,832)

| value | n | % | 95% CI |
|---|---|---|---|
| WITH-AI | 1,460 | 51.6 | 49.8–53.4 |
| ON-AI | 1,339 | 47.3 | 45.4–49.0 |
| BOTH | 33 | 1.2 | 0.8–1.6 |

**Rule that fired (adversary frame)** (n = 2,832)

| value | n | % |
|---|---|---|
| with-vector | 1,262 | 44.6 |
| on-vector | 716 | 25.3 |
| on-vocabulary | 338 | 11.9 |
| conventional-exploit-of-ai-tooling | 285 | 10.1 |
| with-vocabulary | 198 | 7.0 |
| on+with signals | 33 | 1.2 |

**Population × disclosure channel** (adversary frame; this is Figure 1 Panel B)

| channel | n | ON-AI | WITH-AI | BOTH |
|---|---|---|---|---|
| cve/ghsa | 686 | 604 (88%) | 80 (12%) | 2 |
| harm-db | 1753 | 370 (21%) | 1370 (78%) | 13 |
| research/other | 393 | 365 (93%) | 10 (3%) | 18 |

**Population × record year** (adversary frame)

| year | ON-AI | WITH-AI | BOTH |
|---|---|---|---|
| 2020 | 37 | 65 | 0 |
| 2021 | 19 | 50 | 0 |
| 2022 | 27 | 26 | 1 |
| 2023 | 70 | 131 | 4 |
| 2024 | 139 | 207 | 11 |
| 2025 | 281 | 272 | 8 |
| 2026 | 730 | 686 | 9 |

**ON-AI: attack_vector** (n = 1,339)

| value | n | % |
|---|---|---|
| prompt-injection | 344 | 25.7 |
| rce | 147 | 11.0 |
| jailbreak | 101 | 7.5 |
| adversarial-input | 89 | 6.6 |
| data-exfiltration | 86 | 6.4 |
| malware | 85 | 6.3 |
| auth-bypass | 69 | 5.2 |
| other | 59 | 4.4 |

**ON-AI: category** (n = 1,339)

| value | n | % |
|---|---|---|
| vulnerability-disclosure | 548 | 40.9 |
| real-world | 390 | 29.1 |
| research | 262 | 19.6 |
| threat-report | 94 | 7.0 |
| research-demonstrated | 33 | 2.5 |
| red-team | 12 | 0.9 |

**WITH-AI: attack_vector** (n = 1,460)

| value | n | % |
|---|---|---|
| deepfake | 1,179 | 80.8 |
| rce | 82 | 5.6 |
| other | 61 | 4.2 |
| phishing | 52 | 3.6 |
| csam-generation | 31 | 2.1 |
| data-exfiltration | 24 | 1.6 |
| misinformation | 22 | 1.5 |
| malware | 4 | 0.3 |

**WITH-AI: category** (n = 1,460)

| value | n | % |
|---|---|---|
| real-world | 1,376 | 94.2 |
| vulnerability-disclosure | 80 | 5.5 |
| threat-report | 3 | 0.2 |
| research-demonstrated | 1 | 0.1 |

**UNRESOLVED: which adversary word fired** (n = 273)

| value | n | % |
|---|---|---|
| fraud | 85 | 31.1 |
| scam | 62 | 22.7 |
| campaign | 37 | 13.6 |
| hacker | 17 | 6.2 |
| breach | 13 | 4.8 |
| abused | 11 | 4.0 |
| malicious | 7 | 2.6 |
| adversar | 7 | 2.6 |

## Cross-check against incident-rank-validation human-adjudicated labels

| population | gold rows | out of scope | top adjudicated entries |
|---|---|---|---|
| ON-AI | 158 | 23 (15%) | LLM04 22, LLM03 20, NEW-MTIE 17, LLM01 15, LLM05 12 |
| WITH-AI | 174 | 74 (43%) | LLM09 47, NEW-WLA 43, LLM02 2, LLM04 2, LLM05 2 |
| BOTH | 4 | 1 (25%) | ROLL-CMSB 1, NEW-WLA 1, NEW-MTIE 1 |
| UNRESOLVED | 25 | 13 (52%) | NEW-WLA 3, ROLL-CMSB 3, LLM09 2, LLM02 1, LLM06 1 |
| NONE | 756 | 330 (44%) | LLM09 64, LLM03 57, LLM05 55, LLM02 51, LLM06 48 |

Adversary frame: 2,832 rows; 1,756 carry a rank-validation classifier label; 336 carry a human-adjudicated label.
