# Triage evaluation report

- engine: `heuristic+defense`
- examples: **300** (held-out test split, real disclosure outcomes)

## Headline metrics

| metric | value |
|---|---|
| disposition accuracy (9-class) | **65.0%** |
| accept / reject accuracy | **97.0%** |
| macro-F1 | 0.195 |
| weighted-F1 | 0.580 |
| severity exact | 37.7% |
| severity within 1 | 76.3% (MAE 0.90) |
| corroborated_surge recall | 0.0% |

## Per-class

| disposition | precision | recall | F1 | support |
|---|---|---|---|---|
| valid_impactful | 0.26 | 0.15 | 0.19 | 54 |
| valid_low | 0.70 | 0.89 | 0.78 | 209 |
| corroborated_surge | 0.00 | 0.00 | 0.00 | 28 |
| likely_duplicate | 0.00 | 0.00 | 0.00 | 6 |
| out_of_scope | 0.00 | 0.00 | 0.00 | 3 |

## Confusion (gold rows -> predicted cols)

| gold \ pred | valid_impactful | valid_low | corroborated_surge | likely_duplicate | out_of_scope |
|---|---|---|---|---|---|
| **valid_impactful** | 8 | 46 | 0 | 0 | 0 |
| **valid_low** | 21 | 187 | 1 | 0 | 0 |
| **corroborated_surge** | 2 | 26 | 0 | 0 | 0 |
| **likely_duplicate** | 0 | 6 | 0 | 0 | 0 |
| **out_of_scope** | 0 | 3 | 0 | 0 | 0 |
