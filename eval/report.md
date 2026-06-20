# Triage evaluation report

- engine: `heuristic+defense`
- examples: **300** (held-out test split, real disclosure outcomes)

## Headline metrics

| metric | value |
|---|---|
| disposition accuracy (9-class) | **56.3%** |
| accept / reject accuracy | **97.3%** |
| macro-F1 | 0.191 |
| weighted-F1 | 0.548 |
| severity exact | 32.3% |
| severity within 1 | 71.0% (MAE 1.00) |
| corroborated_surge recall | 0.0% |

## Per-class

| disposition | precision | recall | F1 | support |
|---|---|---|---|---|
| valid_impactful | 0.18 | 0.30 | 0.23 | 54 |
| valid_low | 0.73 | 0.73 | 0.73 | 209 |
| corroborated_surge | 0.00 | 0.00 | 0.00 | 28 |
| likely_duplicate | 0.00 | 0.00 | 0.00 | 6 |
| out_of_scope | 0.00 | 0.00 | 0.00 | 3 |
| self_inflicted | 0.00 | 0.00 | 0.00 | 0 |

## Confusion (gold rows -> predicted cols)

| gold \ pred | valid_impactful | valid_low | corroborated_surge | likely_duplicate | out_of_scope | self_inflicted |
|---|---|---|---|---|---|---|
| **valid_impactful** | 16 | 38 | 0 | 0 | 0 | 0 |
| **valid_low** | 55 | 153 | 1 | 0 | 0 | 0 |
| **corroborated_surge** | 14 | 14 | 0 | 0 | 0 | 0 |
| **likely_duplicate** | 2 | 3 | 0 | 0 | 0 | 1 |
| **out_of_scope** | 0 | 3 | 0 | 0 | 0 | 0 |
| **self_inflicted** | 0 | 0 | 0 | 0 | 0 | 0 |
